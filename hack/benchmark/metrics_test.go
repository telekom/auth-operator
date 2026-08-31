// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

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
