// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/telekom/auth-operator/pkg/tracing"
)

func TestPlatformTracingFlags(t *testing.T) {
	provider, propagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagator)
	})
	flags := rootCmd.PersistentFlags()
	for _, name := range []string{"tracing-enabled", "tracing-endpoint", "tracing-sampling-rate", "tracing-insecure"} {
		f := flags.Lookup(name)
		value, changed := f.Value.String(), f.Changed
		t.Cleanup(func() {
			if err := f.Value.Set(value); err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
			f.Changed = changed
		})
	}
	for _, tc := range []struct {
		name, endpoint, env, enabled, insecure string
		want                                   tracing.Config
		wantErr                                bool
	}{
		{"disabled ignores missing endpoint", "", "", "false", "", tracing.Config{SamplingRate: 0}, false},
		{"enabled requires endpoint", "", "", "true", "", tracing.Config{Enabled: true, SamplingRate: 0}, true},
		{"environment HTTP infers insecure", "", " http://127.0.0.1:4317/path ", "true", "",
			tracing.Config{Enabled: true, Endpoint: "127.0.0.1:4317", Insecure: true}, false},
		{"flag overrides environment", " https://localhost:4317/path ", "http://ignored:4317", "true", "",
			tracing.Config{Enabled: true, Endpoint: "localhost:4317"}, false},
		{"explicit secure overrides HTTP inference", "http://localhost:4317", "", "true", "false",
			tracing.Config{Enabled: true, Endpoint: "localhost:4317"}, false},
		{"explicit insecure overrides HTTPS", "https://localhost:4317", "", "true", "true",
			tracing.Config{Enabled: true, Endpoint: "localhost:4317", Insecure: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", tc.env)
			for name, value := range map[string]string{
				"tracing-enabled": tc.enabled, "tracing-endpoint": tc.endpoint,
				"tracing-sampling-rate": "0", "tracing-insecure": "false",
			} {
				if err := flags.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			flags.Lookup("tracing-insecure").Changed = false
			if tc.insecure != "" {
				if err := flags.Set("tracing-insecure", tc.insecure); err != nil {
					t.Fatal(err)
				}
			}
			cfg := tracingConfig()
			if cfg != tc.want {
				t.Fatalf("config = %+v, want %+v", cfg, tc.want)
			}
			p, err := tracing.Setup(t.Context(), cfg, "platform-test")
			if tc.wantErr {
				if err == nil {
					t.Fatal("enabled tracing without endpoint must fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Enabled() != cfg.Enabled || (p.TracerIfEnabled() != nil) != cfg.Enabled {
				t.Fatal("tracer hot-path gating does not match the flag")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := p.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
