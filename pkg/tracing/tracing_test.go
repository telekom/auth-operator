// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestSetup_Disabled(t *testing.T) {
	p, err := Setup(context.Background(), Config{Enabled: false}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	// Should return a noop tracer - verify it's not an SDK provider
	if p.tp == nil {
		t.Fatal("expected non-nil tracer provider")
	}
	// Noop provider should not produce valid spans
	tracer := p.Tracer()
	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}

	_, span := tracer.Start(context.Background(), "test-span")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if span.SpanContext().IsValid() {
		t.Error("noop span should not have a valid SpanContext")
	}
	span.End()
}

func TestSetup_EnabledNoEndpoint(t *testing.T) {
	_, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: "",
	}, "test")
	if err == nil {
		t.Fatal("expected error when endpoint is empty")
	}
}

func TestSetup_EnabledWithEndpoint(t *testing.T) {
	// Use a dummy endpoint; the exporter won't connect in this test
	// but the provider should still be created successfully
	p, err := Setup(context.Background(), Config{
		Enabled:      true,
		Endpoint:     "localhost:4317",
		SamplingRate: 0.5,
		Insecure:     true,
	}, "test-version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	tracer := p.Tracer()
	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}

	// Create a span to verify the tracer works
	ctx, span := tracer.Start(context.Background(), "test-span")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	span.End()
}

func TestProvider_Shutdown_Noop(t *testing.T) {
	p := &Provider{
		tp:     noop.NewTracerProvider(),
		tracer: noop.NewTracerProvider().Tracer("test"),
	}
	// Shutdown on noop should be a no-op
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAttributes(t *testing.T) {
	// Verify attribute keys are defined with expected names
	tests := []struct {
		key     string
		attrKey string
	}{
		{"auth_operator.controller", string(AttrController)},
		{"auth_operator.resource", string(AttrResource)},
		{"auth_operator.namespace", string(AttrNamespace)},
		{"auth_operator.decision", string(AttrDecision)},
		{"auth_operator.user", string(AttrUser)},
		{"auth_operator.verb", string(AttrVerb)},
	}
	for _, tt := range tests {
		if tt.attrKey != tt.key {
			t.Errorf("expected key %q, got %q", tt.key, tt.attrKey)
		}
	}
}

func TestSetup_SamplingRateZero(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		Enabled:      true,
		Endpoint:     "localhost:4317",
		SamplingRate: 0.0,
		Insecure:     true,
	}, "v0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	// Even with 0 sampling, the tracer should still produce spans
	// (they just won't be exported)
	_, span := p.Tracer().Start(context.Background(), "zero-rate-span")
	span.End()
}

func TestSetup_SamplingRateFull(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		Enabled:      true,
		Endpoint:     "localhost:4317",
		SamplingRate: 1.0,
		Insecure:     true,
	}, "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	_, span := p.Tracer().Start(context.Background(), "full-rate-span")
	if !span.SpanContext().IsValid() {
		t.Error("fully sampled span should have a valid SpanContext")
	}
	span.End()
}

func TestSetup_EnabledRegistersGlobalProvider(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		Enabled:      true,
		Endpoint:     "localhost:4317",
		SamplingRate: 1.0,
		Insecure:     true,
	}, "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	// Verify the global trace provider was set to our SDK provider, not the default noop.
	globalTP := otel.GetTracerProvider()
	if _, isNoop := globalTP.(*noop.TracerProvider); isNoop {
		t.Error("expected global TracerProvider to be SDK provider, got noop")
	}
	if globalTP != p.tp {
		t.Error("expected global TracerProvider to match the provider returned by Setup")
	}
}
