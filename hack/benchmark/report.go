// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

var provenanceHeaders = []string{
	"run_id", "input_hash", "workload_hash", "config_hash", "environment_id",
	"architecture", fieldCPUs, fieldMemory, "go_version", "kind_version",
	"kubernetes_version", "helm_version", "kyverno_version", "kyverno_chart",
	"kyverno_chart_sha256", "node_image", "node_version", "operator_version",
	headerChartVersion, fieldPolicyHash, "host_cpu_model", "host_memory",
	"container_runtime", "environment_evidence",
}

func environmentEvidence(e map[string]string) string {
	if len(e) == 0 {
		return ""
	}
	return string(canonical(e))
}

func resultProvenance(r Result) []string {
	e := r.Environment
	return []string{
		r.RunID, r.InputHash, r.WorkloadHash, r.ConfigHash, r.EnvironmentID,
		e.Architecture, e.CPUs, e.Memory, e.GoVersion, e.KindVersion,
		e.KubernetesVersion, e.HelmVersion, e.KyvernoVersion, e.KyvernoChart,
		e.KyvernoChartSHA, e.NodeImage, e.NodeVersion, e.OperatorVersion,
		e.ChartVersion, e.PolicyHash, e.HostCPUModel, e.HostMemory,
		e.ContainerRuntime, environmentEvidence(e.Evidence),
	}
}

var telemetryHeaders = []string{
	headerMetricBeforeState, "metric_before", headerMetricAfterState, "metric_after",
	headerMetricDeltaState, "metric_delta", "webhook_before_state", "webhook_before_sum",
	"webhook_before_count", "webhook_after_state", "webhook_after_sum", "webhook_after_count",
	headerWebhookDeltaState, "webhook_delta_sum", "webhook_delta_count", "pod_restarts_before_state",
	headerPodRestartsBefore, "pod_restarts_after_state", headerPodRestartsAfter, "pod_restarts_delta_state",
	headerPodRestartsDelta, "metric_error",
}

func telemetryValues(r Result) []string {
	return []string{
		string(reportMetricState(r.MetricBeforeState, r.MetricBefore)),
		stableFloat(r.MetricBefore.Value), string(reportMetricState(r.MetricAfterState, r.MetricAfter)),
		stableFloat(r.MetricAfter.Value), string(reportMetricState(r.MetricDeltaState, r.MetricDelta)),
		stableFloat(r.MetricDelta.Value), string(r.WebhookBefore.State),
		stableFloat(r.WebhookBefore.Sum.Value), stableFloat(r.WebhookBefore.Count.Value),
		string(r.WebhookAfter.State), stableFloat(r.WebhookAfter.Sum.Value),
		stableFloat(r.WebhookAfter.Count.Value), string(r.WebhookDelta.State),
		stableFloat(r.WebhookDelta.Sum.Value), stableFloat(r.WebhookDelta.Count.Value),
		string(r.PodRestartsBefore.State), stableFloat(r.PodRestartsBefore.Value),
		string(r.PodRestartsAfter.State), stableFloat(r.PodRestartsAfter.Value),
		string(r.PodRestartsDelta.State), stableFloat(r.PodRestartsDelta.Value), r.MetricError,
	}
}

func reportMetricState(explicit MetricState, counter Counter) MetricState {
	// Snapshot state describes transport/authentication, while the parsed
	// counter can carry a more specific missing/reset state.
	if counter.State != "" && (explicit == "" || explicit == MetricAvailable) {
		return counter.State
	}
	if explicit != "" {
		return explicit
	}
	return counter.State
}

func reportHeaders(throughput string) []string {
	return []string{
		"engine", "tier", "mode", "phase", "verb", "concurrency", fieldVariant, fieldStatus,
		fieldSamples, fieldSuccesses, fieldErrors, headerErrors429, "p50_us", "p95_us", "p99_us",
		"max_us", throughput,
	}
}

func resultValues(r Result, successes int) []string {
	return []string{
		r.Cell.Engine, r.Cell.Tier, r.Cell.Mode, r.Cell.Phase, r.Cell.Verb,
		strconv.Itoa(r.Cell.Concurrency), r.Cell.Variant, r.Status, strconv.Itoa(r.Samples),
		strconv.Itoa(successes), strconv.Itoa(r.Errors), strconv.Itoa(r.Errors429),
		strconv.FormatInt(r.P50Micros, 10), strconv.FormatInt(r.P95Micros, 10),
		strconv.FormatInt(r.P99Micros, 10), strconv.FormatInt(r.MaxMicros, 10), stableFloat(r.Throughput),
	}
}

func WriteCSV(w io.Writer, rs []Result) error {
	c := csv.NewWriter(w)
	header := append(append([]string{}, provenanceHeaders...), reportHeaders("throughput_successes_per_sec")...)
	header = append(header, telemetryHeaders...)
	header = append(header, "started_at", "ended_at", "error")
	if e := c.Write(header); e != nil {
		return e
	}
	for _, r := range sortedResults(rs) {
		successes := r.Successes
		if successes == 0 {
			successes = r.Samples
		}
		v := append(resultProvenance(r), resultValues(r, successes)...)
		v = append(v, telemetryValues(r)...)
		v = append(v, r.StartedAt, r.EndedAt, r.Error)
		if e := c.Write(v); e != nil {
			return e
		}
	}
	c.Flush()
	return c.Error()
}
func WriteMarkdown(w io.Writer, rs []Result) error {
	head := append([]string{}, provenanceHeaders...)
	head = append(head, reportHeaders("throughput_successes_per_sec")...)
	head = append(head, telemetryHeaders...)
	head = append(head, "started_at", "ended_at", "error")
	if e := writeMarkdownHeader(w, head); e != nil {
		return e
	}
	for _, r := range sortedResults(rs) {
		successes := r.Successes
		if successes == 0 {
			successes = r.Samples
		}
		v := append(resultProvenance(r), resultValues(r, successes)...)
		v = append(v, telemetryValues(r)...)
		v = append(v, r.StartedAt, r.EndedAt, r.Error)
		if e := writeMarkdownRow(w, v); e != nil {
			return e
		}
	}
	return nil
}

func writeMarkdownHeader(w io.Writer, headers []string) error {
	if _, err := fmt.Fprintln(w, "| "+strings.Join(headers, " | ")+" |"); err != nil {
		return err
	}
	seps := make([]string, len(headers))
	for i := range seps {
		seps[i] = "---"
	}
	_, err := fmt.Fprintln(w, "| "+strings.Join(seps, " | ")+" |")
	return err
}
func writeMarkdownRow(w io.Writer, values []string) error {
	for i := range values {
		values[i] = markdownEscape(values[i])
	}
	_, err := fmt.Fprintln(w, "| "+strings.Join(values, " | ")+" |")
	return err
}

// ReportRow is a normalized comparison row. Baseline is joined within the same
// run and cell, so results from another environment cannot silently be used.
type ReportRow struct {
	Result
	EnvironmentID     string
	BaselineP50Micros int64
	DeltaMS           float64
	OverheadPct       float64
	HasBaseline       bool
	Diagnostic        string
}

func sameRunCell(a, b Result) bool {
	if !sameIdentity(a, b) || !sameWorkload(a, b) || !sameConfig(a, b) {
		return false
	}
	// Baselines are shared across all measured variants. In particular, the
	// excluded-usernames comparison has the same workload/configuration as the
	// normal enabled variant and must still join to the disabled baseline.
	engineEqual := a.Cell.Engine == b.Cell.Engine ||
		(isBaseline(a) && !isBaseline(b)) ||
		(isBaseline(b) && !isBaseline(a))
	return engineEqual && a.Cell.Tier == b.Cell.Tier && a.Cell.Mode == b.Cell.Mode &&
		a.Cell.Phase == b.Cell.Phase && a.Cell.Concurrency == b.Cell.Concurrency && a.Cell.Kind == b.Cell.Kind &&
		a.Cell.Verb == b.Cell.Verb && a.Cell.Sustained == b.Cell.Sustained
}

func sameIdentity(a, b Result) bool {
	return a.RunID != "" && a.RunID == b.RunID && a.EnvironmentID == b.EnvironmentID
}

func sameWorkload(a, b Result) bool {
	if a.WorkloadHash != "" || b.WorkloadHash != "" {
		return a.WorkloadHash != "" && a.WorkloadHash == b.WorkloadHash
	}
	return a.InputHash != "" && a.InputHash == b.InputHash
}

func sameConfig(a, b Result) bool {
	return a.ConfigHash != "" && a.ConfigHash == b.ConfigHash
}
func isBaseline(r Result) bool {
	return strings.EqualFold(r.Cell.Variant, "baseline") || strings.EqualFold(r.Cell.Variant, "disabled")
}
func AggregateReport(rs []Result, environmentID string) []ReportRow {
	sorted := sortedResults(rs)
	out := make([]ReportRow, 0, len(sorted))
	for _, r := range sorted {
		if r.MetricBeforeState == "" {
			r.MetricBeforeState = r.MetricBefore.State
		}
		if r.MetricAfterState == "" {
			r.MetricAfterState = r.MetricAfter.State
		}
		if r.MetricDeltaState == "" {
			r.MetricDeltaState = r.MetricDelta.State
		}
		env := environmentID
		if env == "" {
			env = r.EnvironmentID
		}
		row := ReportRow{Result: r, EnvironmentID: env}
		for _, b := range sorted {
			if !sameRunCell(r, b) || !isBaseline(b) || isBaseline(r) || b.Status != statusComplete || r.Status != statusComplete {
				continue
			}
			row.BaselineP50Micros = b.P50Micros
			row.HasBaseline = true
			row.DeltaMS = float64(r.P50Micros-b.P50Micros) / 1000
			if b.P50Micros > 0 {
				row.OverheadPct = float64(r.P50Micros-b.P50Micros) * 100 / float64(b.P50Micros)
			}
			break
		}
		if !isBaseline(r) && !row.HasBaseline {
			row.Diagnostic = "baseline unavailable: no exact run/environment/workload/config match"
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool { return reportKey(out[i]) < reportKey(out[j]) })
	return out
}
func reportKey(r ReportRow) string {
	return fmt.Sprintf("%s|%s|%s|%s|%09d|%s|%s", r.Cell.Engine, r.Cell.Tier, r.Cell.Mode, r.Cell.Phase, r.Cell.Concurrency, r.Cell.Variant, r.Status)
}
func stableFloat(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 3, 64)
}
func csvRows(rows []ReportRow) [][]string {
	header := append([]string{}, provenanceHeaders...)
	header = append(header, []string{
		"engine", "tier", "mode", "phase", "verb", "concurrency", fieldVariant, fieldStatus,
		fieldSamples, fieldSuccesses, fieldErrors, headerErrors429, "error", "p50_us", "p95_us",
		"p99_us", "max_us", "throughput_successes_per_sec", "baseline_p50_us", "delta_ms", "overhead_pct",
	}...)
	header = append(header, telemetryHeaders...)
	header = append(header, "diagnostic")
	out := make([][]string, 1, 1+len(rows))
	out[0] = header
	for _, r := range rows {
		// ReportRow may carry an explicit display environment selected by the
		// caller; keep that identity in every aggregate format.
		r.Result.EnvironmentID = r.EnvironmentID
		base := ""
		if r.HasBaseline {
			base = strconv.FormatInt(r.BaselineP50Micros, 10)
		}
		successes := r.Successes
		if successes == 0 {
			successes = r.Samples
		}
		v := append(resultProvenance(r.Result), aggregateValues(r, successes, base)...)
		v = append(v, telemetryValues(r.Result)...)
		v = append(v, r.Diagnostic)
		out = append(out, v)
	}
	return out
}
func WriteReportCSV(w io.Writer, rows []ReportRow) error {
	c := csv.NewWriter(w)
	for _, row := range csvRows(rows) {
		if err := c.Write(row); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}
func markdownEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\\", "\\\\", "\n", " ").Replace(s)
}

func aggregateValues(r ReportRow, successes int, base string) []string {
	const errorColumn = 12

	result := resultValues(r.Result, successes)
	values := make([]string, 0, len(result)+4)
	values = append(values, result[:errorColumn]...)
	values = append(values, r.Error)
	values = append(values, result[errorColumn:]...)
	return append(values, base, stableFloat(r.DeltaMS), stableFloat(r.OverheadPct))
}
func WriteReportMarkdown(w io.Writer, rows []ReportRow) error {
	const aliases = "<!-- Human-readable aliases: Successes, Metric Before/After/Delta, P50 (us), P95 (us), P99 (us), Max (us), " +
		"Pod Restarts Before/After/Delta, Pod Restarts Delta. -->"
	if _, err := fmt.Fprintln(w, aliases); err != nil {
		return err
	}
	rowsCSV := csvRows(rows)
	if err := writeMarkdownHeader(w, rowsCSV[0]); err != nil {
		return err
	}
	for _, row := range rowsCSV[1:] {
		if err := writeMarkdownRow(w, row); err != nil {
			return err
		}
	}
	return nil
}

// MarginalRows filters complete rows without averaging percentiles. Percentiles
// from unrelated cells cannot be averaged into a meaningful marginal.
func MarginalRows(rows []ReportRow) []ReportRow {
	out := make([]ReportRow, 0, len(rows))
	for _, r := range rows {
		if r.Status == statusComplete {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return reportKey(out[i]) < reportKey(out[j]) })
	return out
}
