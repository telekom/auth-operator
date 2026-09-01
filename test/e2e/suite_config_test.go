//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import "testing"

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
