/*
Copyright © 2026 Deutsche Telekom AG.
*/

// NOTE: These tests access package-level cobra command singletons (rootCmd,
// controllerCmd, webhookCmd) and the global flag.CommandLine. They are NOT
// safe for t.Parallel().
package cmd

import (
	"flag"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestSensitivePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"token", "auth-token", true},
		{"secret", "client-secret", true},
		{"password", "db-password", true},
		{"passphrase", "ssh-passphrase", true},
		{"key", "api-key", true},
		{"auth", "oauth-redirect", true},
		{"credential", "credential-file", true},
		{"private", "private-key", true},
		{"cert", "tls-cert", true},
		{"bearer", "bearer-token", true},
		{"apikey", "apikey", true},
		{"api-key", "api-key", true},
		{"client-id", "client-id", true},
		{"client_id", "client_id", true},
		{"case insensitive", "AUTH-TOKEN", true},
		{"safe flag", "namespace", false},
		{"safe flag port", "port", false},
		{"safe flag verbosity", "verbosity", false},
		{"safe flag metrics-addr", "metrics-bind-address", false},
		{"safe flag leader-elect", "leader-elect", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sensitivePattern.MatchString(tt.input)
			if got != tt.expected {
				t.Errorf("sensitivePattern.MatchString(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

const redactedValue = "[REDACTED]"

func TestRedactSensitiveFlags(t *testing.T) {
	// Register test flags using the global flag.CommandLine singleton.
	// We use unique names to avoid panics from duplicate registration if tests
	// are run multiple times in the same process (e.g. via -count=N).
	// flag.CommandLine does not support un-registering, so these persist.
	if flag.Lookup("test-secret-redact") == nil {
		flag.String("test-secret-redact", "my-sensitive-value", "test flag for redaction")
	}
	if flag.Lookup("test-namespace-redact") == nil {
		flag.String("test-namespace-redact", "default", "test flag for non-redaction")
	}
	if err := flag.Set("test-secret-redact", "my-sensitive-value"); err != nil {
		t.Fatalf("failed to set test-secret-redact: %v", err)
	}
	if err := flag.Set("test-namespace-redact", "default"); err != nil {
		t.Fatalf("failed to set test-namespace-redact: %v", err)
	}

	result := redactSensitiveFlags()

	if val, ok := result["test-secret-redact"]; !ok {
		t.Error("expected test-secret-redact in result")
	} else if val != redactedValue {
		t.Errorf("expected %s for test-secret-redact, got %q", redactedValue, val)
	}

	if val, ok := result["test-namespace-redact"]; !ok {
		t.Error("expected test-namespace-redact in result")
	} else if val == redactedValue {
		t.Error("test-namespace-redact should not be redacted")
	} else if val != "default" {
		t.Errorf("expected %q for test-namespace-redact, got %q", "default", val)
	}
}

func TestInitScheme(t *testing.T) {
	// initScheme populates the package-level scheme variable
	initScheme()

	if scheme == nil {
		t.Fatal("scheme should not be nil after initScheme()")
	}

	// Verify core types are registered
	knownTypes := scheme.AllKnownTypes()
	if len(knownTypes) == 0 {
		t.Fatal("scheme should have known types registered")
	}
}

func TestControllerCmdFlagValidation(t *testing.T) {
	tests := []struct {
		name        string
		bdConc      int
		rdConc      int
		waConc      int
		expectError bool
	}{
		{"all positive", 5, 5, 5, false},
		{"all zero (disabled)", 0, 0, 0, false},
		{"bd zero others positive", 0, 5, 5, false},
		{"bd positive others zero", 5, 0, 0, false},
		{"bd negative", -1, 5, 5, true},
		{"rd negative", 5, -1, 5, true},
		{"wa negative", 5, 5, -1, true},
		{"all negative", -1, -1, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConcurrency(tt.bdConc, tt.rdConc, tt.waConc)
			if (err != nil) != tt.expectError {
				t.Errorf("validateConcurrency(%d, %d, %d): expected error=%v, got %v",
					tt.bdConc, tt.rdConc, tt.waConc, tt.expectError, err)
			}
		})
	}
}

func TestValidateTrackerIntervals(t *testing.T) {
	tests := []struct {
		name           string
		syncInterval   time.Duration
		resyncInterval time.Duration
		expectError    bool
	}{
		{"both positive (ok)", 5 * time.Minute, 15 * time.Minute, false},
		{"zero sync uses internal default (ok)", 0, 15 * time.Minute, false},
		{"zero resync uses internal default (ok)", 5 * time.Minute, 0, false},
		{"both zero use internal defaults (ok)", 0, 0, false},
		{"negative sync interval (error)", -1 * time.Second, 15 * time.Minute, true},
		{"negative resync interval (error)", 5 * time.Minute, -1 * time.Second, true},
		{"both negative (error)", -5 * time.Minute, -15 * time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTrackerIntervals(tt.syncInterval, tt.resyncInterval)
			if (err != nil) != tt.expectError {
				t.Errorf("validateTrackerIntervals(%v, %v): expected error=%v, got %v",
					tt.syncInterval, tt.resyncInterval, tt.expectError, err)
			}
		})
	}
}

func TestValidateRateLimitFlags(t *testing.T) {
	tests := []struct {
		name        string
		limit       float64
		burst       int
		expectError bool
	}{
		{"disabled (zero limit)", 0, 0, false},
		{"valid limit and burst", 100, 200, false},
		{"fractional limit", 0.5, 1, false},
		{"negative limit", -1, 200, true},
		{"zero burst with positive limit", 100, 0, true},
		{"negative burst with positive limit", 100, -1, true},
		{"zero limit ignores burst", 0, -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitFlags(tt.limit, tt.burst)
			if (err != nil) != tt.expectError {
				t.Errorf("validateRateLimitFlags(%v, %d): expected error=%v, got %v",
					tt.limit, tt.burst, tt.expectError, err)
			}
		})
	}
}

func TestRootCommandStructure(t *testing.T) {
	// Verify rootCmd has expected subcommands
	subcommands := rootCmd.Commands()

	commandNames := make(map[string]bool)
	for _, cmd := range subcommands {
		commandNames[cmd.Use] = true
	}

	if !commandNames["controller"] {
		t.Error("rootCmd should have 'controller' subcommand")
	}
	if !commandNames["webhook"] {
		t.Error("rootCmd should have 'webhook' subcommand")
	}
}

func TestControllerCmdFlags(t *testing.T) {
	flags := controllerCmd.Flags()

	expectedFlags := []string{
		"leader-elect",
		"binddefinition-concurrency",
		"roledefinition-concurrency",
		"cache-sync-timeout",
		"graceful-shutdown-timeout",
		"wait-for-crds",
		"tracker-sync-interval",
		"tracker-resync-interval",
	}

	for _, name := range expectedFlags {
		f := flags.Lookup(name)
		if f == nil {
			t.Errorf("expected flag %q not found on controller command", name)
		}
	}
}

func TestTrackerIntervalFlagDefaults(t *testing.T) {
	flags := controllerCmd.Flags()

	syncFlag := flags.Lookup("tracker-sync-interval")
	if syncFlag == nil {
		t.Fatal("flag tracker-sync-interval not found on controller command")
	}
	if syncFlag.DefValue != "5m0s" {
		t.Errorf("tracker-sync-interval default = %q, want %q", syncFlag.DefValue, "5m0s")
	}

	resyncFlag := flags.Lookup("tracker-resync-interval")
	if resyncFlag == nil {
		t.Fatal("flag tracker-resync-interval not found on controller command")
	}
	if resyncFlag.DefValue != "15m0s" {
		t.Errorf("tracker-resync-interval default = %q, want %q", resyncFlag.DefValue, "15m0s")
	}
}

func TestWebhookCmdFlags(t *testing.T) {
	flags := webhookCmd.Flags()

	expectedFlags := []string{
		"port",
		"enable-http2",
		"certs-dir",
		"disable-cert-rotation",
		"cert-rotation-dns-name",
		"cert-rotation-secret-name",
		"cert-rotation-mutating-webhook",
		"cert-rotation-validating-webhook",
		"tdg-migration",
	}

	for _, name := range expectedFlags {
		f := flags.Lookup(name)
		if f == nil {
			t.Errorf("expected flag %q not found on webhook command", name)
		}
	}
}

func TestRootCmdPersistentFlags(t *testing.T) {
	flags := rootCmd.PersistentFlags()

	expectedFlags := []string{
		"namespace",
		"verbosity",
		"health-probe-bind-address",
		"metrics-bind-address",
		"metrics-secure",
	}

	for _, name := range expectedFlags {
		f := flags.Lookup(name)
		if f == nil {
			t.Errorf("expected persistent flag %q not found on root command", name)
		}
	}

	// Verify metrics-secure defaults to false.
	f := flags.Lookup("metrics-secure")
	if f != nil && f.DefValue != "false" {
		t.Errorf("flag %q default = %q, want %q", "metrics-secure", f.DefValue, "false")
	}
}

func TestFlagDefaults(t *testing.T) {
	tests := []struct {
		cmd      string
		flag     string
		expected string
	}{
		{"controller", "binddefinition-concurrency", "5"},
		{"controller", "roledefinition-concurrency", "5"},
		{"controller", "leader-elect", "true"},
		{"controller", "wait-for-crds", "true"},
		{"controller", "cache-sync-timeout", "2m0s"},
		{"controller", "graceful-shutdown-timeout", "30s"},
		{"controller", "tracker-sync-interval", "5m0s"},
		{"controller", "tracker-resync-interval", "15m0s"},
		{"controller", "webhookauthorizer-concurrency", "1"},
		{"webhook", "port", "9443"},
		{"webhook", "enable-http2", "false"},
		{"webhook", "disable-cert-rotation", "false"},
		{"webhook", "tdg-migration", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd+"/"+tt.flag, func(t *testing.T) {
			var cmd *cobra.Command
			switch tt.cmd {
			case "controller":
				cmd = controllerCmd
			case "webhook":
				cmd = webhookCmd
			default:
				t.Fatalf("unknown command %q", tt.cmd)
				return
			}
			pf := cmd.Flags().Lookup(tt.flag)
			if pf == nil {
				t.Fatalf("flag %q not found on %s command", tt.flag, tt.cmd)
			}
			if pf.DefValue != tt.expected {
				t.Errorf("flag %q default = %q, want %q", tt.flag, pf.DefValue, tt.expected)
			}
		})
	}
}
