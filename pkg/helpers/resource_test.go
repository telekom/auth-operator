// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"strings"
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
			name:       "single char names",
			targetName: "a",
			roleRef:    "b",
			want:       "a-b-binding",
		},
		{
			name:       "numeric suffix",
			targetName: "app1",
			roleRef:    "role2",
			want:       "app1-role2-binding",
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

func TestBuildBindingNameTruncation(t *testing.T) {
	t.Run("truncates long names to 253 chars", func(t *testing.T) {
		// Create a name that would exceed 253 chars
		longTargetName := strings.Repeat("a", 200)
		longRoleRef := strings.Repeat("b", 100)
		// Full name would be: 200 + 1 + 100 + 1 + 7 = 309 chars

		result := BuildBindingName(longTargetName, longRoleRef)

		if len(result) > 253 {
			t.Errorf("BuildBindingName() returned name of length %d, want <= 253", len(result))
		}
		if len(result) != 253 {
			t.Errorf("BuildBindingName() returned name of length %d, want exactly 253", len(result))
		}
	})

	t.Run("consistent hash for same inputs", func(t *testing.T) {
		longTargetName := strings.Repeat("x", 200)
		longRoleRef := strings.Repeat("y", 100)

		result1 := BuildBindingName(longTargetName, longRoleRef)
		result2 := BuildBindingName(longTargetName, longRoleRef)

		if result1 != result2 {
			t.Errorf("BuildBindingName() not deterministic: %q != %q", result1, result2)
		}
	})

	t.Run("different hashes for different long names", func(t *testing.T) {
		longTargetName1 := strings.Repeat("a", 200) + "1"
		longTargetName2 := strings.Repeat("a", 200) + "2"
		roleRef := strings.Repeat("b", 100)

		result1 := BuildBindingName(longTargetName1, roleRef)
		result2 := BuildBindingName(longTargetName2, roleRef)

		if result1 == result2 {
			t.Errorf("BuildBindingName() should produce different results for different inputs")
		}
	})

	t.Run("no truncation for names at exactly 253 chars", func(t *testing.T) {
		// binding suffix is 7 chars, plus 2 hyphens = 9 chars overhead
		// So targetName + roleRef should be 244 chars to hit exactly 253
		targetName := strings.Repeat("a", 122)
		roleRef := strings.Repeat("b", 122)
		expectedName := targetName + "-" + roleRef + "-binding"

		if len(expectedName) != 253 {
			t.Fatalf("Test setup error: expected name length %d, want 253", len(expectedName))
		}

		result := BuildBindingName(targetName, roleRef)

		if result != expectedName {
			t.Errorf("BuildBindingName() = %q, want %q", result, expectedName)
		}
	})

	t.Run("truncates names at 254 chars", func(t *testing.T) {
		// One char over the limit
		targetName := strings.Repeat("a", 123)
		roleRef := strings.Repeat("b", 122)
		fullName := targetName + "-" + roleRef + "-binding"

		if len(fullName) != 254 {
			t.Fatalf("Test setup error: full name length %d, want 254", len(fullName))
		}

		result := BuildBindingName(targetName, roleRef)

		if len(result) > 253 {
			t.Errorf("BuildBindingName() returned name of length %d, want <= 253", len(result))
		}
		// Should have hash suffix
		if !strings.Contains(result, "-") {
			t.Errorf("BuildBindingName() truncated name should contain hash suffix")
		}
	})
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
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
		{
			name:         "empty source labels",
			sourceLabels: map[string]string{},
			wantLabels: map[string]string{
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
				ManagedByLabelStandard: ManagedByValue,
				AppNameLabel:           ManagedByValue,
			},
		},
		{
			name: "managed-by-standard label is overwritten",
			sourceLabels: map[string]string{
				ManagedByLabelStandard: "other-controller",
			},
			wantLabels: map[string]string{
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
	if _, exists := source[ManagedByLabelStandard]; exists {
		t.Error("BuildResourceLabels added ManagedByLabelStandard to the source map")
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
