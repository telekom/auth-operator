//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telekom/auth-operator/test/utils"
)

func TestCreatorTrackingRequiresDedicatedCluster(t *testing.T) {
	t.Setenv("E2E_CREATOR_TRACKING_RUN_DIR", "")
	for _, tc := range []struct {
		name    string
		cluster string
		wantErr string
	}{
		{"unset", "", "cluster isolation violation"},
		{"base suite", "auth-operator-e2e", "cluster isolation violation"},
		{"foreign cluster", "production", "cluster isolation violation"},
		{"dedicated cluster", "auth-operator-e2e-creator-tracking", "E2E_CREATOR_TRACKING_RUN_DIR is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KIND_CLUSTER", tc.cluster)
			err := creatorValidateIsolation(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("creatorValidateIsolation() = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestCreatorTrackingKindConfigsUseVersionSpecificAdmissionPolicyGates(t *testing.T) {
	projectDir, err := utils.GetProjectDir()
	if err != nil {
		t.Fatal(err)
	}
	configPath := func(name string) string {
		return filepath.Join(projectDir, "test", "e2e", name)
	}

	stable, err := os.ReadFile(configPath("kind-config-creator-tracking-stable.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stable), "MutatingAdmissionPolicy=true") {
		t.Fatal("stable creator-tracking config must not pass the graduated MutatingAdmissionPolicy gate")
	}

	beta, err := os.ReadFile(configPath("kind-config-creator-tracking-beta.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(beta), "MutatingAdmissionPolicy=true") {
		t.Fatal("beta creator-tracking config must keep the MutatingAdmissionPolicy gate")
	}
}
