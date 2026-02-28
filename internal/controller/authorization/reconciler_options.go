// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import "go.opentelemetry.io/otel/trace"

// tracerSetter is implemented by reconcilers that support OpenTelemetry tracing.
type tracerSetter interface {
	setTracer(trace.Tracer)
}

// ReconcilerOption is a type-safe functional option for configuring reconcilers.
type ReconcilerOption func(tracerSetter)

// WithTracer returns a ReconcilerOption that sets the OpenTelemetry tracer on
// any reconciler that implements tracerSetter (RoleDefinition, BindDefinition).
func WithTracer(t trace.Tracer) ReconcilerOption {
	return func(r tracerSetter) {
		r.setTracer(t)
	}
}
