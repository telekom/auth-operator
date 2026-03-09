// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetMissingRolePolicy(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        MissingRolePolicy
	}{
		{
			name:        "no annotation defaults to warn",
			annotations: nil,
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "empty annotation defaults to warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: ""},
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "explicit warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: "warn"},
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "error policy",
			annotations: map[string]string{MissingRolePolicyAnnotation: "error"},
			want:        MissingRolePolicyError,
		},
		{
			name:        "ignore policy",
			annotations: map[string]string{MissingRolePolicyAnnotation: "ignore"},
			want:        MissingRolePolicyIgnore,
		},
		{
			name:        "unknown value defaults to warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: "invalid"},
			want:        MissingRolePolicyWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-bd",
					Annotations: tt.annotations,
				},
			}
			got := bd.GetMissingRolePolicy()
			if got != tt.want {
				t.Errorf("GetMissingRolePolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnmarshalRoleBindings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantErr  bool
		wantRefs [][]string // ClusterRoleRefs for each element.
	}{
		{
			name:     "JSON array with entries",
			input:    `[{"clusterRoleRefs":["view"],"namespace":"ns1"},{"clusterRoleRefs":["edit"]}]`,
			wantLen:  2,
			wantRefs: [][]string{{"view"}, {"edit"}},
		},
		{
			name:    "empty JSON array",
			input:   `[]`,
			wantLen: 0,
		},
		{
			name:    "null value",
			input:   `null`,
			wantLen: 0,
		},
		{
			name:     "legacy single object with content",
			input:    `{"clusterRoleRefs":["view"],"namespace":"ns1"}`,
			wantLen:  1,
			wantRefs: [][]string{{"view"}},
		},
		{
			name:    "legacy empty object",
			input:   `{}`,
			wantLen: 0,
		},
		{
			name:    "invalid JSON",
			input:   `not-json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb, err := unmarshalRoleBindings(json.RawMessage(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rb) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(rb), tt.wantLen)
			}
			for i, refs := range tt.wantRefs {
				if i >= len(rb) {
					t.Errorf("missing element %d", i)
					continue
				}
				if len(rb[i].ClusterRoleRefs) != len(refs) {
					t.Errorf("rb[%d].ClusterRoleRefs = %v, want %v", i, rb[i].ClusterRoleRefs, refs)
					continue
				}
				for j, ref := range refs {
					if rb[i].ClusterRoleRefs[j] != ref {
						t.Errorf("rb[%d].ClusterRoleRefs[%d] = %q, want %q", i, j, rb[i].ClusterRoleRefs[j], ref)
					}
				}
			}
		})
	}
}

func TestBindDefinitionSpecUnmarshalLegacyRoleBindings(t *testing.T) {
	// Simulate what the API server returns for old resources with roleBindings as object.
	specJSON := `{
		"targetName": "test",
		"subjects": [{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"devs"}],
		"clusterRoleBindings": {"clusterRoleRefs": ["admin"]},
		"roleBindings": {"clusterRoleRefs": ["view"], "namespace": "default"}
	}`

	var spec BindDefinitionSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("unexpected error unmarshaling spec with legacy roleBindings: %v", err)
	}

	if len(spec.RoleBindings) != 1 {
		t.Fatalf("RoleBindings len = %d, want 1", len(spec.RoleBindings))
	}
	if spec.RoleBindings[0].Namespace != "default" {
		t.Errorf("RoleBindings[0].Namespace = %q, want %q", spec.RoleBindings[0].Namespace, "default")
	}
	if len(spec.RoleBindings[0].ClusterRoleRefs) != 1 || spec.RoleBindings[0].ClusterRoleRefs[0] != "view" {
		t.Errorf("RoleBindings[0].ClusterRoleRefs = %v, want [view]", spec.RoleBindings[0].ClusterRoleRefs)
	}
}

func TestBindDefinitionSpecUnmarshalEmptyObjectRoleBindings(t *testing.T) {
	// Simulate what the API server returns for old resources with roleBindings: {}.
	specJSON := `{
		"targetName": "test",
		"subjects": [{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"devs"}],
		"clusterRoleBindings": {"clusterRoleRefs": ["admin"]},
		"roleBindings": {}
	}`

	var spec BindDefinitionSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("unexpected error unmarshaling spec with empty object roleBindings: %v", err)
	}

	if len(spec.RoleBindings) != 0 {
		t.Errorf("RoleBindings len = %d, want 0", len(spec.RoleBindings))
	}
}

func TestBindDefinitionSpecUnmarshalArrayRoleBindings(t *testing.T) {
	// Verify that normal array format still works and other fields are preserved.
	specJSON := `{
		"targetName": "test",
		"subjects": [{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"devs"}],
		"clusterRoleBindings": {"clusterRoleRefs": ["admin"]},
		"roleBindings": [{"clusterRoleRefs":["view"],"namespace":"ns1"},{"roleRefs":["edit"]}]
	}`

	var spec BindDefinitionSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.TargetName != "test" {
		t.Errorf("TargetName = %q, want %q", spec.TargetName, "test")
	}
	if len(spec.Subjects) != 1 {
		t.Fatalf("Subjects len = %d, want 1", len(spec.Subjects))
	}
	if len(spec.ClusterRoleBindings.ClusterRoleRefs) != 1 {
		t.Fatalf("ClusterRoleBindings.ClusterRoleRefs len = %d, want 1", len(spec.ClusterRoleBindings.ClusterRoleRefs))
	}
	if len(spec.RoleBindings) != 2 {
		t.Fatalf("RoleBindings len = %d, want 2", len(spec.RoleBindings))
	}
	if spec.RoleBindings[0].Namespace != "ns1" {
		t.Errorf("RoleBindings[0].Namespace = %q, want %q", spec.RoleBindings[0].Namespace, "ns1")
	}
	if len(spec.RoleBindings[1].RoleRefs) != 1 || spec.RoleBindings[1].RoleRefs[0] != "edit" {
		t.Errorf("RoleBindings[1].RoleRefs = %v, want [edit]", spec.RoleBindings[1].RoleRefs)
	}
}

func TestBindDefinitionSpecUnmarshalOmittedRoleBindings(t *testing.T) {
	// When roleBindings is absent from JSON, pre-existing RoleBindings must be preserved.
	spec := BindDefinitionSpec{
		RoleBindings: []NamespaceBinding{
			{Namespace: "kept"},
		},
	}
	specJSON := `{
		"targetName": "test",
		"subjects": [{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"devs"}],
		"clusterRoleBindings": {"clusterRoleRefs": ["admin"]}
	}`

	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(spec.RoleBindings) != 1 {
		t.Fatalf("RoleBindings len = %d, want 1 (preserved)", len(spec.RoleBindings))
	}
	if spec.RoleBindings[0].Namespace != "kept" {
		t.Errorf("RoleBindings[0].Namespace = %q, want %q", spec.RoleBindings[0].Namespace, "kept")
	}
}
