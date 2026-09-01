//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"strings"
	"testing"
)

func TestCreatorTrackingLabelsUseDedicatedCluster(t *testing.T) {
	const wantCluster = "auth-operator-e2e-creator-tracking"
	for _, label := range []string{"creator-tracking", "creator-tracking-cleanup", "creator-tracking-upgrade"} {
		config, err := GetSuiteForLabels([]string{label})
		if err != nil {
			t.Fatalf("GetSuiteForLabels(%q): %v", label, err)
		}
		if config.ClusterName != wantCluster {
			t.Fatalf("GetSuiteForLabels(%q) selected %q, want %q", label, config.ClusterName, wantCluster)
		}
	}
}

func TestCreatorTrackingKindConfigsUseVersionSpecificAdmissionPolicyGates(t *testing.T) {
	stable, err := os.ReadFile("kind-config-creator-tracking-stable.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stable), "MutatingAdmissionPolicy=true") {
		t.Fatal("stable creator-tracking config must not pass the graduated MutatingAdmissionPolicy gate")
	}

	beta, err := os.ReadFile("kind-config-creator-tracking-beta.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(beta), "MutatingAdmissionPolicy=true") {
		t.Fatal("beta creator-tracking config must keep the MutatingAdmissionPolicy gate")
	}
}
