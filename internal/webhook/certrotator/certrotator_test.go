/*
Copyright © 2026 Deutsche Telekom AG.
*/

package certrotator

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
)

func TestEnable_EmptyNamespace(t *testing.T) {
	err := Enable(
		nil, // mgr (not reached due to early validation)
		"",  // namespace — empty triggers error
		"/tmp/certs",
		"webhook.example.svc",
		"webhook-certs",
		[]rotator.WebhookInfo{},
		make(chan struct{}),
	)
	if err == nil {
		t.Fatal("expected error for empty namespace, got nil")
	}
	if !strings.Contains(err.Error(), "namespace is undefined") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestEnable_EmptyDir(t *testing.T) {
	err := Enable(
		nil,       // mgr (not reached due to early validation)
		"test-ns", // namespace — valid
		"",        // dir — empty triggers error
		"webhook.example.svc",
		"webhook-certs",
		[]rotator.WebhookInfo{},
		make(chan struct{}),
	)
	if err == nil {
		t.Fatal("expected error for empty dir, got nil")
	}
	if !strings.Contains(err.Error(), "certs-dir is undefined") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestEnable_NilManager verifies that passing a nil manager to rotator.AddRotator
// produces an error. This tests the error propagation path from the rotator library.
// Note: Full integration testing of certificate rotation requires a running manager
// and is covered by E2E tests; this unit test validates the nil-guard behavior.
func TestEnable_NilManager(t *testing.T) {
	err := Enable(
		nil, // nil manager — causes rotator.AddRotator to fail
		"test-ns",
		"/tmp/certs",
		"webhook.example.svc",
		"webhook-certs",
		[]rotator.WebhookInfo{},
		make(chan struct{}),
	)
	if err == nil {
		t.Fatal("expected error for nil manager, got nil")
	}
}
