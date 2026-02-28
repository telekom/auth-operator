// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	// ServiceName is the default OTEL service name for auth-operator.
	ServiceName = "auth-operator"

	// TracerName is the instrumentation library name used for all spans.
	TracerName = "github.com/telekom/auth-operator"

	// shutdownTimeout is the maximum time to wait for the exporter to flush.
	shutdownTimeout = 5 * time.Second
)

// Config holds the configuration for the tracing subsystem.
type Config struct {
	// Enabled controls whether tracing is active.
	Enabled bool

	// Endpoint is the OTLP collector endpoint (e.g. "otel-collector:4317").
	Endpoint string

	// SamplingRate is the ratio of traces to sample (0.0 to 1.0).
	SamplingRate float64

	// Insecure disables TLS for the OTLP exporter connection.
	Insecure bool
}

// Provider wraps an OpenTelemetry TracerProvider and exposes a Tracer.
type Provider struct {
	tp     trace.TracerProvider
	tracer trace.Tracer
}

// Tracer returns the provider's tracer instance for creating spans.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Shutdown gracefully shuts down the tracer provider, flushing any pending spans.
// Uses context.Background as parent because the incoming context may already be
// canceled (e.g. after signal handling), which would cause an immediate timeout.
func (p *Provider) Shutdown(_ context.Context) error {
	if sdkTP, ok := p.tp.(*sdktrace.TracerProvider); ok {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return sdkTP.Shutdown(shutdownCtx)
	}
	return nil
}

// Setup initializes the OpenTelemetry tracing subsystem based on the given config.
// If tracing is disabled, a no-op provider is returned.
func Setup(ctx context.Context, cfg Config, version string) (*Provider, error) {
	if !cfg.Enabled {
		tp := noop.NewTracerProvider()
		return &Provider{
			tp:     tp,
			tracer: tp.Tracer(TracerName),
		}, nil
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("tracing endpoint must be set when tracing is enabled")
	}

	if cfg.SamplingRate < 0 || cfg.SamplingRate > 1 {
		return nil, fmt.Errorf("sampling rate must be between 0.0 and 1.0, got %f", cfg.SamplingRate)
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(ServiceName),
			semconv.ServiceVersionKey.String(version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTEL resource: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SamplingRate))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Register as global provider and set propagators
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(TracerName)
	return &Provider{tp: tp, tracer: tracer}, nil
}

// Span attribute keys used across the operator.
var (
	AttrController   = attribute.Key("auth_operator.controller")
	AttrResource     = attribute.Key("auth_operator.resource")
	AttrNamespace    = attribute.Key("auth_operator.namespace")
	AttrUser         = attribute.Key("auth_operator.user")
	AttrVerb         = attribute.Key("auth_operator.verb")
	AttrAPIGroup     = attribute.Key("auth_operator.api_group")
	AttrResourceType = attribute.Key("auth_operator.resource_type")
	AttrPath         = attribute.Key("auth_operator.path")
	AttrDecision     = attribute.Key("auth_operator.decision")
	AttrReason       = attribute.Key("auth_operator.reason")
	AttrRuleCount    = attribute.Key("auth_operator.rule_count")
)
