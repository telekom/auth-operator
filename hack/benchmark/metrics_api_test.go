// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/rest"
)

func testServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	s := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	s.Start()
	return s
}

func TestFetchMetricsUsesAuthenticatedRESTConfig(t *testing.T) {
	s := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte("metric 3\n"))
	}))
	defer s.Close()
	got, err := FetchMetrics(context.Background(), &rest.Config{Host: s.URL, BearerToken: "secret"})
	if err != nil || got.State != MetricAvailable || got.Body != "metric 3\n" {
		t.Fatalf("got %#v, err %v", got, err)
	}
}
func TestFetchMetricsStates(t *testing.T) {
	for _, tc := range []struct {
		code  int
		state MetricState
	}{{http.StatusForbidden, MetricUnauthorized}, {http.StatusServiceUnavailable, MetricUnavailable}} {
		s := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code) }))
		got, err := FetchMetrics(context.Background(), &rest.Config{Host: s.URL})
		s.Close()
		if err != nil || got.State != tc.state {
			t.Errorf("code %d: %#v, %v", tc.code, got, err)
		}
	}
}
func TestParseHistogramDeltaSelectsLabelsAndResets(t *testing.T) {
	before := "h_sum{operation=\"CREATE\",resource=\"pods\"} 2\nh_sum{operation=\"UPDATE\",resource=\"pods\"} 50\nh_count{operation=\"CREATE\",resource=\"pods\"} 1\n"
	after := "h_sum{operation=\"CREATE\",resource=\"pods\"} 6\nh_sum{operation=\"UPDATE\",resource=\"pods\"} 51\nh_count{operation=\"CREATE\",resource=\"pods\"} 3\n"
	got := ParseHistogramDelta(before, after, "h_sum", "h_count", map[string]string{"operation": "CREATE", "resource": "pods"})
	if got.State != MetricAvailable || got.Sum.Value != 4 || got.Count.Value != 2 || got.MeanSeconds != 2 {
		t.Fatalf("got %#v", got)
	}
	reset := ParseHistogramDelta(after, before, "h_sum", "h_count", map[string]string{"operation": "CREATE", "resource": "pods"})
	if reset.State != MetricReset {
		t.Fatalf("reset %#v", reset)
	}
}
