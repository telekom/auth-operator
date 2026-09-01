// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"k8s.io/client-go/rest"
)

type MetricState string

const (
	MetricAvailable    MetricState = "available"
	MetricMissing      MetricState = "missing"
	MetricUnavailable  MetricState = "unavailable"
	MetricUnauthorized MetricState = "unauthorized"
	MetricReset        MetricState = "reset"
)

type Counter struct {
	Value float64
	State MetricState
}

const (
	metricScannerInitialBuffer = 64 * 1024
	metricScannerMaxTokenSize  = 1024 * 1024
)

func ParseMetric(text, name string) Counter {
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, metricScannerInitialBuffer), metricScannerMaxTokenSize)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if strings.HasPrefix(l, name+" ") || strings.HasPrefix(l, name+"{") {
			p := strings.Fields(l)
			if len(p) > 1 {
				if value, e := strconv.ParseFloat(p[1], 64); e == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
					return Counter{value, MetricAvailable}
				}
				return Counter{State: MetricUnavailable}
			}
		}
	}
	if err := s.Err(); err != nil {
		return Counter{State: MetricUnavailable}
	}
	return Counter{State: MetricMissing}
}
func ParseMetricResponse(status int, text, name string) Counter {
	if status == 401 || status == 403 {
		return Counter{State: MetricUnauthorized}
	}
	if status < 200 || status >= 300 {
		return Counter{State: MetricUnavailable}
	}
	return ParseMetric(text, name)
}
func CounterDelta(a, b Counter) Counter {
	if a.State != MetricAvailable || b.State != MetricAvailable {
		for _, state := range []MetricState{MetricUnauthorized, MetricUnavailable, MetricMissing} {
			if a.State == state || b.State == state {
				return Counter{State: state}
			}
		}
		return Counter{State: MetricMissing}
	}
	if b.Value < a.Value {
		return Counter{State: MetricReset}
	}
	return Counter{b.Value - a.Value, MetricAvailable}
}

// MetricsSnapshot is the authenticated, point-in-time response from the API server.
type MetricsSnapshot struct {
	Body       string
	StatusCode int
	State      MetricState
}

func metricDeltaState(before, after MetricsSnapshot) MetricState {
	if before.State == MetricUnauthorized || after.State == MetricUnauthorized {
		return MetricUnauthorized
	}
	if before.State == MetricUnavailable || after.State == MetricUnavailable {
		return MetricUnavailable
	}
	if before.State != MetricAvailable || after.State != MetricAvailable {
		return MetricMissing
	}
	return MetricAvailable
}

// FetchMetrics retrieves /metrics using the credentials and TLS settings in config.
func FetchMetrics(ctx context.Context, config *rest.Config) (MetricsSnapshot, error) {
	if config == nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics: nil REST config")
	}
	hc, err := rest.HTTPClientFor(config)
	if err != nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics HTTP client: %w", err)
	}
	return fetchMetrics(ctx, hc, config)
}

// fetchMetrics uses a client prepared by the caller so repeated snapshots can
// reuse its transport and connection pool while each request remains scoped to
// its own context.
func fetchMetrics(ctx context.Context, hc *http.Client, config *rest.Config) (MetricsSnapshot, error) {
	if config == nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics: nil REST config")
	}
	if hc == nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics: nil HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(config.Host, "/")+"/metrics", http.NoBody)
	if err != nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return MetricsSnapshot{State: MetricUnavailable}, fmt.Errorf("metrics request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return MetricsSnapshot{StatusCode: resp.StatusCode, State: MetricUnavailable}, fmt.Errorf("read metrics response: %w", err)
	}
	state := MetricAvailable
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		state = MetricUnauthorized
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		state = MetricUnavailable
	}
	return MetricsSnapshot{Body: string(b), StatusCode: resp.StatusCode, State: state}, nil
}

type MetricSample struct {
	Labels map[string]string
	Value  float64
}

func metricSamples(text, name string) ([]MetricSample, error) {
	var out []MetricSample
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, metricScannerInitialBuffer), metricScannerMaxTokenSize)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		metric, valueText, ok := splitMetricLine(line)
		if !ok {
			continue
		}
		metricName, labels := parseMetricName(metric)
		if metricName != name {
			continue
		}
		fields := strings.Fields(valueText)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
			out = append(out, MetricSample{Labels: labels, Value: value})
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan metrics: %w", err)
	}
	return out, nil
}

const (
	APIServerAdmissionDuration = "apiserver_admission_step_admission_duration_seconds"
	WebhookAdmissionDuration   = "apiserver_admission_webhook_admission_duration_seconds"
)

func ParseAdmissionMetrics(before, after string, labels map[string]string) (Counter, HistogramDelta, error) {
	api := ParseHistogramDelta(before, after, APIServerAdmissionDuration+"_sum", APIServerAdmissionDuration+"_count", labels)
	webhook := ParseHistogramDelta(before, after, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
	if api.State == MetricUnavailable || webhook.State == MetricUnavailable {
		return Counter{State: MetricUnavailable}, webhook, fmt.Errorf("malformed admission metrics")
	}
	return api.Count, webhook, nil
}

func ParseHistogramSnapshot(text, sumName, countName string, labels map[string]string) HistogramDelta {
	sum, sumOK, sumErr := matchingMetricSample(text, sumName, labels)
	count, countOK, countErr := matchingMetricSample(text, countName, labels)
	if sumErr != nil || countErr != nil {
		return HistogramDelta{State: MetricUnavailable}
	}
	if !sumOK || !countOK {
		return HistogramDelta{State: MetricMissing}
	}
	return HistogramDelta{Sum: Counter{Value: sum.Value, State: MetricAvailable}, Count: Counter{Value: count.Value, State: MetricAvailable}, State: MetricAvailable}
}

func ParseHistogramResponse(snapshot MetricsSnapshot, sumName, countName string, labels map[string]string) HistogramDelta {
	if snapshot.State != MetricAvailable {
		state := snapshot.State
		return HistogramDelta{Sum: Counter{State: state}, Count: Counter{State: state}, State: state}
	}
	return ParseHistogramSnapshot(snapshot.Body, sumName, countName, labels)
}

func histogramResponseDelta(before, after MetricsSnapshot, sumName, countName string, labels map[string]string) HistogramDelta {
	if before.State != MetricAvailable || after.State != MetricAvailable {
		state := metricDeltaState(before, after)
		return HistogramDelta{Sum: Counter{State: state}, Count: Counter{State: state}, State: state}
	}
	return ParseHistogramDelta(before.Body, after.Body, sumName, countName, labels)
}

func metricDiagnostics(before, after, delta Counter, webhookBefore, webhookAfter, webhookDelta HistogramDelta) string {
	if before.State == MetricAvailable && after.State == MetricAvailable && delta.State == MetricAvailable &&
		webhookBefore.State == MetricAvailable && webhookAfter.State == MetricAvailable && webhookDelta.State == MetricAvailable {
		return ""
	}
	return fmt.Sprintf(
		"api metric states before=%s after=%s delta=%s; webhook states before=%s after=%s delta=%s",
		before.State,
		after.State,
		delta.State,
		webhookBefore.State,
		webhookAfter.State,
		webhookDelta.State,
	)
}
func splitMetricLine(line string) (metric, value string, ok bool) {
	pos := strings.IndexAny(line, " \t")
	if pos <= 0 || pos == len(line)-1 {
		return "", "", false
	}
	remaining := strings.TrimSpace(line[pos:])
	if remaining == "" {
		return "", "", false
	}
	if end := strings.IndexAny(remaining, " \t"); end >= 0 {
		remaining = remaining[:end]
	}
	return line[:pos], remaining, true
}
func parseMetricName(metric string) (metricName string, labels map[string]string) {
	start := strings.IndexByte(metric, '{')
	if start < 0 {
		return metric, map[string]string{}
	}
	labels = map[string]string{}
	end := strings.LastIndexByte(metric, '}')
	if end < start {
		return metric, labels
	}
	for _, item := range splitLabels(metric[start+1 : end]) {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) == 2 {
			labels[strings.TrimSpace(kv[0])] = unquoteLabel(strings.TrimSpace(kv[1]))
		}
	}
	return metric[:start], labels
}
func splitLabels(s string) []string {
	var out []string
	start := 0
	quoted, escaped := false, false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quoted {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == ',' && !quoted {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
func unquoteLabel(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
	}
	return s
}
func matchingSample(samples []MetricSample, labels map[string]string) (MetricSample, bool) {
	var matched MetricSample
	found := false
	for _, sample := range samples {
		ok := true
		for k, v := range labels {
			if sample.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			if !found {
				matched.Labels = sample.Labels
				found = true
			}
			matched.Value += sample.Value
		}
	}
	return matched, found
}

func matchingMetricSample(text, name string, labels map[string]string) (MetricSample, bool, error) {
	samples, err := metricSamples(text, name)
	if err != nil {
		return MetricSample{}, false, err
	}
	sample, ok := matchingSample(samples, labels)
	return sample, ok, nil
}

type HistogramDelta struct {
	Sum, Count  Counter
	MeanSeconds float64
	State       MetricState
}

type histogramSampleSet struct {
	beforeSum, afterSum     MetricSample
	beforeCount, afterCount MetricSample
	found, unavailable      bool
}

func histogramSamples(before, after, sumName, countName string, labels map[string]string) histogramSampleSet {
	bs, bok, beforeSumErr := matchingMetricSample(before, sumName, labels)
	as, aok, afterSumErr := matchingMetricSample(after, sumName, labels)
	bc, bcok, beforeCountErr := matchingMetricSample(before, countName, labels)
	ac, acok, afterCountErr := matchingMetricSample(after, countName, labels)
	if beforeSumErr != nil || afterSumErr != nil || beforeCountErr != nil || afterCountErr != nil {
		return histogramSampleSet{unavailable: true}
	}
	return histogramSampleSet{beforeSum: bs, afterSum: as, beforeCount: bc, afterCount: ac, found: bok && aok && bcok && acok}
}

func validHistogramSamples(bs, as, bc, ac MetricSample) bool {
	return bs.Value >= 0 && as.Value >= 0 && bc.Value >= 0 && ac.Value >= 0 &&
		math.Trunc(bc.Value) == bc.Value && math.Trunc(ac.Value) == ac.Value
}

func histogramCounterDelta(bs, as, bc, ac MetricSample) HistogramDelta {
	sum := CounterDelta(Counter{bs.Value, MetricAvailable}, Counter{as.Value, MetricAvailable})
	count := CounterDelta(Counter{bc.Value, MetricAvailable}, Counter{ac.Value, MetricAvailable})
	if sum.State != MetricAvailable || count.State != MetricAvailable {
		state := MetricReset
		if sum.State != MetricReset && count.State != MetricReset {
			state = MetricMissing
		}
		return HistogramDelta{Sum: sum, Count: count, State: state}
	}
	mean := 0.0
	if count.Value > 0 {
		mean = sum.Value / count.Value
	}
	if mean < 0 || math.IsNaN(mean) || math.IsInf(mean, 0) {
		return HistogramDelta{Sum: sum, Count: count, State: MetricUnavailable}
	}
	return HistogramDelta{Sum: sum, Count: count, MeanSeconds: mean, State: MetricAvailable}
}

// ParseHistogramDelta selects matching sum/count series, preserving reset state.
func ParseHistogramDelta(before, after, sumName, countName string, labels map[string]string) HistogramDelta {
	samples := histogramSamples(before, after, sumName, countName, labels)
	if samples.unavailable {
		return HistogramDelta{State: MetricUnavailable}
	}
	if !samples.found {
		return HistogramDelta{State: MetricMissing}
	}
	if !validHistogramSamples(samples.beforeSum, samples.afterSum, samples.beforeCount, samples.afterCount) {
		return HistogramDelta{State: MetricUnavailable}
	}
	return histogramCounterDelta(samples.beforeSum, samples.afterSum, samples.beforeCount, samples.afterCount)
}
