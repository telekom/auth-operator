// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"testing"
)

func TestBuildBindingName(t *testing.T) {
	tests := []struct {
		name       string
		targetName string
		roleRef    string
		want       string
	}{
		{
			name:       "simple names",
			targetName: "my-app",
			roleRef:    "admin",
			want:       "my-app-admin-binding",
		},
		{
			name:       "with hyphens",
			targetName: "my-target-name",
			roleRef:    "cluster-admin",
			want:       "my-target-name-cluster-admin-binding",
		},
		{
			name:       "empty target",
			targetName: "",
			roleRef:    "admin",
			want:       "-admin-binding",
		},
		{
			name:       "empty role",
			targetName: "target",
			roleRef:    "",
			want:       "target--binding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildBindingName(tt.targetName, tt.roleRef)
			if got != tt.want {
				t.Errorf("BuildBindingName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildResourceLabels(t *testing.T) {
	tests := []struct {
		name         string
		sourceLabels map[string]string
		wantLabels   map[string]string
	}{
		{
			name:         "nil source labels",
			sourceLabels: nil,
			wantLabels: map[string]string{
				ManagedByLabel:         ManagedByValue,
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
		{
			name:         "empty source labels",
			sourceLabels: map[string]string{},
			wantLabels: map[string]string{
				ManagedByLabel:         ManagedByValue,
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
		{
			name: "with existing labels",
			sourceLabels: map[string]string{
				"app":     "test",
				"version": "v1",
			},
			wantLabels: map[string]string{
				"app":                  "test",
				"version":              "v1",
				ManagedByLabel:         ManagedByValue,
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
		{
			name: "managed-by label is overwritten",
			sourceLabels: map[string]string{
				ManagedByLabel: "other-controller",
			},
			wantLabels: map[string]string{
				ManagedByLabel:         ManagedByValue,
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildResourceLabels(tt.sourceLabels)
			if len(got) != len(tt.wantLabels) {
				t.Errorf("BuildResourceLabels() returned %d labels, want %d", len(got), len(tt.wantLabels))
			}
			for k, v := range tt.wantLabels {
				if got[k] != v {
					t.Errorf("BuildResourceLabels()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestBuildResourceLabelsDoesNotMutateInput(t *testing.T) {
	source := map[string]string{"app": "test"}
	original := map[string]string{"app": "test"}

	_ = BuildResourceLabels(source)

	if source["app"] != original["app"] {
		t.Error("BuildResourceLabels mutated the source map")
	}
	if _, exists := source[ManagedByLabel]; exists {
		t.Error("BuildResourceLabels added ManagedByLabel to the source map")
	}
}

func TestBuildResourceAnnotations(t *testing.T) {
	got := BuildResourceAnnotations("RoleDefinition", "my-role")
	want := map[string]string{
		SourceKindAnnotation: "RoleDefinition",
		SourceNameAnnotation: "my-role",
	}
	if len(got) != len(want) {
		t.Errorf("BuildResourceAnnotations() returned %d annotations, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("BuildResourceAnnotations()[%q] = %q, want %q", k, got[k], v)
		}
	}
}
