// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/csv"
	"strings"
	"testing"
)

func TestReportFormatsPreserveProvenanceAndTelemetry(t *testing.T) {
	r := Result{
		RunID: "run-7", InputHash: "input-7", WorkloadHash: "work-7", ConfigHash: "config-7", EnvironmentID: "env-7",
		Environment: Environment{
			Architecture: "amd64", CPUs: "4", Memory: "8Gi", GoVersion: "go1.26", KindVersion: "kind v0.30",
			KubernetesVersion: "v1.33", HelmVersion: "v3.18", KyvernoVersion: "v1.19", NodeImage: "kindest/node:v1", NodeVersion: "v1",
			OperatorVersion: "op", ChartVersion: "chart", PolicyHash: "policy", HostCPUModel: "cpu", HostMemory: "mem",
			ContainerRuntime: "docker", Evidence: map[string]string{"cpus": "live"},
		},
		Cell: Cell{
			Engine: "map", Tier: "t1", Mode: "protect", Phase: "create", Verb: "create", Concurrency: 8, Variant: "enabled",
		},
		Status: "failed", Samples: 1, Errors: 1, Error: "boom",
		MetricBefore: Counter{Value: 1, State: MetricAvailable}, MetricAfter: Counter{Value: 2, State: MetricAvailable}, MetricDelta: Counter{Value: 1, State: MetricAvailable},
		WebhookBefore:     HistogramDelta{State: MetricAvailable, Sum: Counter{Value: 3, State: MetricAvailable}, Count: Counter{Value: 4, State: MetricAvailable}},
		WebhookAfter:      HistogramDelta{State: MetricReset, Sum: Counter{Value: 1, State: MetricAvailable}, Count: Counter{Value: 2, State: MetricAvailable}},
		WebhookDelta:      HistogramDelta{State: MetricReset},
		PodRestartsBefore: Counter{Value: 2, State: MetricAvailable}, PodRestartsAfter: Counter{Value: 3, State: MetricAvailable},
		PodRestartsDelta: Counter{Value: 1, State: MetricAvailable},
	}
	rows := AggregateReport([]Result{r}, "")
	var raw, aggregate strings.Builder
	if err := WriteCSV(&raw, []Result{r}); err != nil {
		t.Fatal(err)
	}
	if err := WriteReportCSV(&aggregate, rows); err != nil {
		t.Fatal(err)
	}
	assertReportCSV(t, "raw", raw.String())
	assertReportCSV(t, "aggregate", aggregate.String())
	var md, aggregateMD strings.Builder
	if err := WriteMarkdown(&md, []Result{r}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "throughput_successes_per_sec") {
		t.Fatalf("markdown header %s", md.String())
	}
	if err := WriteReportMarkdown(&aggregateMD, rows); err != nil {
		t.Fatal(err)
	}
	if md.Len() == 0 || aggregateMD.Len() == 0 {
		t.Fatalf("Markdown output is empty: raw=%d aggregate=%d", md.Len(), aggregateMD.Len())
	}
	for _, value := range []string{"run-7", "input-7", "work-7", "config-7", "env-7", "architecture", "metric_before_state", "webhook_before_sum", "pod_restarts_delta"} {
		if !strings.Contains(md.String(), value) {
			t.Errorf("raw Markdown missing %q", value)
		}
		if !strings.Contains(aggregateMD.String(), value) {
			t.Errorf("aggregate Markdown missing %q", value)
		}
	}
}

func assertReportCSV(t *testing.T, name, data string) {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("%s CSV: %v", name, err)
	}
	if len(records) != 2 || len(records[0]) != len(records[1]) {
		t.Fatalf("%s shape: %#v", name, records)
	}
	for _, field := range append(provenanceHeaders, telemetryHeaders...) {
		if !containsString(records[0], field) {
			t.Errorf("%s missing %s", name, field)
		}
	}
	joined := strings.Join(records[1], "|")
	for _, value := range []string{"run-7", "input-7", "work-7", "config-7", "env-7", "amd64", "live", "reset", "3.000", "4.000"} {
		if !strings.Contains(joined, value) {
			t.Errorf("%s missing value %q", name, value)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestReportMetricStatePreservesParsedReset(t *testing.T) {
	if got := reportMetricState(MetricAvailable, Counter{State: MetricReset}); got != MetricReset {
		t.Fatalf("metric state = %q, want reset", got)
	}
	if got := reportMetricState(MetricUnavailable, Counter{State: MetricAvailable}); got != MetricUnavailable {
		t.Fatalf("transport state = %q, want unavailable", got)
	}
}

func TestAggregateReportSameCellBaselineAndEscaping(t *testing.T) {
	rs := []Result{
		{
			Cell:   Cell{Engine: "map", Tier: "t1", Mode: "protect", Phase: "create", Verb: "create", Concurrency: 1, Variant: "baseline"},
			Status: "complete", Samples: 1, P50Micros: 1000, RunID: "run-1", InputHash: "hash", WorkloadHash: "work", ConfigHash: "cfg", EnvironmentID: "env",
		},
		{
			Cell:   Cell{Engine: "map", Tier: "t1", Mode: "protect", Phase: "create", Verb: "create", Concurrency: 1, Variant: "enabled"},
			Status: "complete", Samples: 1, P50Micros: 1250, RunID: "run-1", InputHash: "different", WorkloadHash: "work", ConfigHash: "cfg", EnvironmentID: "env",
		},
	}
	rows := AggregateReport(rs, "env|1")
	if len(rows) != 2 || !rows[1].HasBaseline {
		t.Fatalf("rows %#v", rows)
	}
	var b strings.Builder
	if err := WriteReportMarkdown(&b, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "env\\|1") || !strings.Contains(b.String(), "0.250") || !strings.Contains(b.String(), "25.000") {
		t.Fatalf("markdown %s", b.String())
	}
}

func TestAggregateReportJoinsExcludedVariantToBaseline(t *testing.T) {
	common := func(variant string, p50 int64) Result {
		return Result{
			Cell:   Cell{Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseCreate, Verb: verbMixed, Concurrency: 1, Variant: variant},
			Status: "complete", Samples: 1, P50Micros: p50, RunID: "run-1", InputHash: "input", WorkloadHash: "work", ConfigHash: "cfg", EnvironmentID: "env",
		}
	}
	baseline := common(engineBaseline, 1000)
	baseline.Cell.Engine = engineBaseline
	excluded := common(variantExcluded, 1250)

	rows := AggregateReport([]Result{excluded, baseline}, "")
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2: %#v", len(rows), rows)
	}
	for _, row := range rows {
		if row.Cell.Variant == variantExcluded {
			if !row.HasBaseline || row.BaselineP50Micros != baseline.P50Micros {
				t.Fatalf("excluded row did not join baseline: %#v", row)
			}
			return
		}
	}
	t.Fatalf("excluded row missing: %#v", rows)
}
func TestAggregateReportStableAndMarginal(t *testing.T) {
	rs := []Result{
		{Cell: Cell{Engine: "z", Tier: "b", Mode: "m", Phase: "create", Concurrency: 1, Variant: "enabled"}, Status: "complete", P50Micros: 20},
		{Cell: Cell{Engine: "a", Tier: "a", Mode: "m", Phase: "create", Concurrency: 1, Variant: "enabled"}, Status: "complete", P50Micros: 10},
	}
	rows := AggregateReport(rs, "env")
	if rows[0].Cell.Engine != "a" {
		t.Fatalf("not stable: %#v", rows)
	}
	m := MarginalRows(rows)
	if len(m) != 2 || m[0].Cell.Engine != "a" || m[0].P50Micros != 10 {
		t.Fatalf("marginal %#v", m)
	}
}

func TestReportsExposeSuccessesErrors429AndTelemetryStates(t *testing.T) {
	r := Result{
		Cell: Cell{
			Engine: "map", Tier: "t1", Mode: "protect", Phase: "create", Verb: "create", Concurrency: 1, Variant: "enabled",
		},
		Status: "failed", Samples: 2, Successes: 2, Errors: 1, Errors429: 1, P99Micros: 123, MaxMicros: 456,
		MetricBeforeState: MetricMissing, MetricAfterState: MetricUnauthorized, MetricDeltaState: MetricUnavailable, MetricDelta: Counter{State: MetricUnavailable},
		WebhookBefore: HistogramDelta{State: MetricAvailable, Sum: Counter{Value: 1}},
		WebhookAfter:  HistogramDelta{State: MetricUnauthorized}, WebhookDelta: HistogramDelta{State: MetricUnavailable},
		PodRestartsBefore: Counter{Value: 2, State: MetricAvailable}, PodRestartsAfter: Counter{Value: 3, State: MetricAvailable},
		PodRestartsDelta: Counter{Value: 1, State: MetricAvailable},
	}
	rows := AggregateReport([]Result{r}, "env")
	var b strings.Builder
	if err := WriteReportCSV(&b, rows); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"successes", "errors_429", "metric_before_state", "metric_after_state", "metric_delta_state", "webhook_delta_state"} {
		if !strings.Contains(b.String(), field) {
			t.Fatalf("CSV omits %q: %s", field, b.String())
		}
	}
	records, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse aggregate CSV: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("aggregate CSV rows = %d, want 2: %s", len(records), b.String())
	}
	values := make(map[string]string, len(records[0]))
	for i, name := range records[0] {
		values[name] = records[1][i]
	}
	for name, want := range map[string]string{
		"samples":             "2",
		"successes":           "2",
		"errors":              "1",
		"errors_429":          "1",
		"metric_before_state": "missing",
		"metric_after_state":  "unauthorized",
		"metric_delta_state":  "unavailable",
		"webhook_delta_state": "unavailable",
		"pod_restarts_before": "2.000",
		"pod_restarts_after":  "3.000",
		"pod_restarts_delta":  "1.000",
	} {
		if values[name] != want {
			t.Errorf("aggregate CSV %s = %q, want %q", name, values[name], want)
		}
	}
	b.Reset()
	if err := WriteReportMarkdown(&b, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Successes") || !strings.Contains(b.String(), "Metric Before") || !strings.Contains(b.String(), "unauthorized") {
		t.Fatalf("Markdown values missing: %s", b.String())
	}
	if !strings.Contains(b.String(), "P99 (us)") || !strings.Contains(b.String(), "Max (us)") || !strings.Contains(b.String(), "Pod Restarts Delta") {
		t.Fatalf("Markdown latency/restart fields missing: %s", b.String())
	}
	b.Reset()
	if err := WriteReportCSV(&b, rows); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"webhook_before_state", "webhook_after_state", "pod_restarts_before", "pod_restarts_after", "pod_restarts_delta", "metric_error"} {
		if !strings.Contains(b.String(), field) {
			t.Fatalf("CSV omits %q: %s", field, b.String())
		}
	}
	if !strings.Contains(b.String(), "available,2.000,available,3.000,available,1.000") {
		t.Fatalf("CSV restart evidence missing: %s", b.String())
	}
}
