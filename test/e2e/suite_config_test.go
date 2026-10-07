//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"strings"
	"testing"
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
