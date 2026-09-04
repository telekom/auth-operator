// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

func TestMetricResponseStates(t *testing.T) {
	if ParseMetricResponse(403, "", "x").State != MetricUnauthorized {
		t.Fatal("auth")
	}
	if ParseMetricResponse(500, "", "x").State != MetricUnavailable {
		t.Fatal("unavailable")
	}
	if ParseMetricResponse(200, "x 4", "x").State != MetricAvailable {
		t.Fatal("available")
	}
}

func TestParseMetricUsesValueBeforeOptionalTimestamp(t *testing.T) {
	got := ParseMetric("x 4 1700000000\n", "x")
	if got.State != MetricAvailable || got.Value != 4 {
		t.Fatalf("metric = %#v, want value 4", got)
	}
}

func TestParseMetricAcceptsTabSeparatedFields(t *testing.T) {
	got := ParseMetric("x\t4\t1700000000\n", "x")
	if got.State != MetricAvailable || got.Value != 4 {
		t.Fatalf("tab-separated metric = %#v, want available value 4", got)
	}
}

func TestParseMetricRejectsOversizedLines(t *testing.T) {
	got := ParseMetric("x "+strings.Repeat("7", metricScannerMaxTokenSize)+"\n", "x")
	if got.State != MetricUnavailable {
		t.Fatalf("oversized metric state = %q, want unavailable", got.State)
	}
}

func TestCounterDeltaPreservesUnavailableState(t *testing.T) {
	if got := CounterDelta(Counter{State: MetricUnavailable}, Counter{State: MetricAvailable}); got.State != MetricUnavailable {
		t.Fatalf("delta state = %q, want unavailable", got.State)
	}
	if got := CounterDelta(Counter{State: MetricUnauthorized}, Counter{State: MetricMissing}); got.State != MetricUnauthorized {
		t.Fatalf("delta state = %q, want unauthorized", got.State)
	}
}
func TestMetricReset(t *testing.T) {
	if CounterDelta(Counter{10, MetricAvailable}, Counter{2, MetricAvailable}).State != MetricReset {
		t.Fatal("reset")
	}
}

func TestMetricDeltaPreservesResetState(t *testing.T) {
	before := ParseMetricResponse(200, APIServerAdmissionDuration+"_count 10\n", APIServerAdmissionDuration+"_count")
	after := ParseMetricResponse(200, APIServerAdmissionDuration+"_count 2\n", APIServerAdmissionDuration+"_count")
	delta := CounterDelta(before, after)
	if delta.State != MetricReset {
		t.Fatalf("delta state = %q, want %q", delta.State, MetricReset)
	}
}

func TestParseHistogramResponsePropagatesHTTPState(t *testing.T) {
	for _, state := range []MetricState{MetricUnauthorized, MetricUnavailable} {
		got := ParseHistogramResponse(MetricsSnapshot{StatusCode: 403, State: state}, "sum", "count", nil)
		if got.State != state || got.Sum.State != state || got.Count.State != state {
			t.Fatalf("state %q not propagated: %#v", state, got)
		}
	}
}

func TestMatchingSampleAggregatesMatchingSeries(t *testing.T) {
	samples := []MetricSample{
		{Labels: map[string]string{typeField: metricTypeMutating, "operation": "create"}, Value: 2},
		{Labels: map[string]string{typeField: metricTypeMutating, "operation": "update"}, Value: 3},
		{Labels: map[string]string{typeField: "validating", "operation": "create"}, Value: 11},
	}
	got, ok := matchingSample(samples, map[string]string{typeField: metricTypeMutating})
	if !ok || got.Value != 5 {
		t.Fatalf("matching sample = %#v, ok=%v, want aggregate value 5", got, ok)
	}
}
