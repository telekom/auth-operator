// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func ptrInt32(v int32) *int32 { return &v }

func TestEvaluateBindDefinition_NoLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %v", violations)
	}
}

func TestEvaluateBindDefinition_CRBNotAllowed(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: false,
			},
		},
	}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.clusterRoleBindings" {
		t.Errorf("expected field spec.clusterRoleBindings, got %q", violations[0].Field)
	}
}

func TestEvaluateBindDefinition_CRBAllowed(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
			},
		},
	}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"viewer"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %v", violations)
	}
}

func TestEvaluateBindDefinition_RoleRefAllowedAndForbidden(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefs:   []string{"viewer", "team-*"},
					ForbiddenRoleRefs: []string{"cluster-admin"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		roleRefs       []string
		wantViolations int
	}{
		{name: "allowed exact", roleRefs: []string{"viewer"}, wantViolations: 0},
		{name: "allowed wildcard", roleRefs: []string{"team-alpha"}, wantViolations: 0},
		{name: "not in allowed list", roleRefs: []string{"editor"}, wantViolations: 1},
		{name: "forbidden", roleRefs: []string{"cluster-admin"}, wantViolations: 2},
		{name: "multiple mixed", roleRefs: []string{"viewer", "editor", "cluster-admin"}, wantViolations: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
						ClusterRoleRefs: tt.roleRefs,
					},
					Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
				},
			}

			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_RoleBindingLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				RoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefs: []string{"editor", "viewer"},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					ClusterRoleRefs: []string{"editor"},
					RoleRefs:        []string{"viewer"},
					Namespace:       "team-a",
				},
				{
					ClusterRoleRefs: []string{"admin"},
					Namespace:       "team-b",
				},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.roleBindings[1].clusterRoleRefs[0]" {
		t.Errorf("unexpected violation field: %q", violations[0].Field)
	}
}

func TestEvaluateBindDefinition_NamespaceLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				TargetNamespaceLimits: &authorizationv1alpha1.NamespaceLimits{
					ForbiddenNamespaces:        []string{"kube-system"},
					ForbiddenNamespacePrefixes: []string{"system-"},
					MaxTargetNamespaces:        ptrInt32(2),
				},
			},
		},
	}

	tests := []struct {
		name           string
		roleBindings   []authorizationv1alpha1.NamespaceBinding
		wantViolations int
	}{
		{
			name: "allowed namespaces",
			roleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"viewer"}},
				{Namespace: "team-b", ClusterRoleRefs: []string{"viewer"}},
			},
			wantViolations: 0,
		},
		{
			name: "forbidden namespace",
			roleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "kube-system", ClusterRoleRefs: []string{"viewer"}},
			},
			wantViolations: 1,
		},
		{
			name: "forbidden prefix",
			roleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "system-monitoring", ClusterRoleRefs: []string{"viewer"}},
			},
			wantViolations: 1,
		},
		{
			name: "exceeds max namespaces",
			roleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"viewer"}},
				{Namespace: "team-b", ClusterRoleRefs: []string{"viewer"}},
				{Namespace: "team-c", ClusterRoleRefs: []string{"viewer"}},
			},
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					RoleBindings: tt.roleBindings,
					Subjects:     []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_SubjectKindLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds:   []string{rbacv1.UserKind, rbacv1.GroupKind},
				ForbiddenKinds: []string{rbacv1.ServiceAccountKind},
			},
		},
	}

	tests := []struct {
		name           string
		subjects       []rbacv1.Subject
		wantViolations int
	}{
		{
			name:           "allowed user",
			subjects:       []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			wantViolations: 0,
		},
		{
			name:           "allowed group",
			subjects:       []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "developers"}},
			wantViolations: 0,
		},
		{
			name:           "forbidden SA",
			subjects:       []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "default", Namespace: "ns"}},
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: tt.subjects,
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_UserNameLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				UserLimits: &authorizationv1alpha1.NameMatchLimits{
					AllowedPrefixes:   []string{"team-"},
					ForbiddenNames:    []string{"root"},
					ForbiddenPrefixes: []string{"admin-"},
					ForbiddenSuffixes: []string{"-superuser"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		userName       string
		wantViolations int
	}{
		{name: "allowed prefix", userName: "team-alice", wantViolations: 0},
		{name: "forbidden name", userName: "root", wantViolations: 2}, // forbidden name + no allowed prefix
		{name: "wrong prefix", userName: "other-bob", wantViolations: 1},
		{name: "forbidden prefix", userName: "admin-carol", wantViolations: 2},    // forbidden prefix + no allowed prefix
		{name: "forbidden suffix", userName: "team-superuser", wantViolations: 1}, // allowed prefix but forbidden suffix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: tt.userName}},
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations for user %q, got %d: %v", tt.wantViolations, tt.userName, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_GroupNameLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				GroupLimits: &authorizationv1alpha1.NameMatchLimits{
					AllowedNames: []string{"developers", "viewers"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		groupName      string
		wantViolations int
	}{
		{name: "allowed", groupName: "developers", wantViolations: 0},
		{name: "not allowed", groupName: "admins", wantViolations: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: tt.groupName}},
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations for group %q, got %d: %v", tt.wantViolations, tt.groupName, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_ServiceAccountLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					ForbiddenNamespaces:        []string{"kube-system"},
					ForbiddenNamespacePrefixes: []string{"system-"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		saNamespace    string
		wantViolations int
	}{
		{name: "allowed namespace", saNamespace: "team-a", wantViolations: 0},
		{name: "forbidden namespace", saNamespace: "kube-system", wantViolations: 1},
		{name: "forbidden prefix", saNamespace: "system-monitoring", wantViolations: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{{
						Kind:      rbacv1.ServiceAccountKind,
						Name:      "test-sa",
						Namespace: tt.saNamespace,
					}},
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations for SA namespace %q, got %d: %v", tt.wantViolations, tt.saNamespace, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_AllDimensions(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: false,
				RoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefs: []string{"viewer"},
				},
				TargetNamespaceLimits: &authorizationv1alpha1.NamespaceLimits{
					ForbiddenNamespaces: []string{"kube-system"},
				},
			},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				ForbiddenKinds: []string{rbacv1.ServiceAccountKind},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					ClusterRoleRefs: []string{"admin"},
					Namespace:       "kube-system",
				},
			},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "default", Namespace: "ns"},
			},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	// Expected: CRB not allowed (1) + role ref not allowed (1) + forbidden namespace (1) + forbidden SA kind (1)
	if len(violations) != 4 {
		t.Errorf("expected 4 violations, got %d: %v", len(violations), violations)
	}
}

func TestEvaluateBindDefinition_SubjectAllowedKindsDefaultDeny(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.UserKind},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "devs"},
			},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.subjects[0].kind" {
		t.Errorf("unexpected field: %q", violations[0].Field)
	}
}

func TestEvaluateBindDefinition_UserAllowedAndForbiddenSuffixes(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				UserLimits: &authorizationv1alpha1.NameMatchLimits{
					AllowedSuffixes:   []string{"@example.com"},
					ForbiddenSuffixes: []string{"@evil.com"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		userName       string
		wantViolations int
	}{
		{name: "allowed suffix", userName: "alice@example.com", wantViolations: 0},
		{name: "wrong suffix", userName: "alice@other.com", wantViolations: 1},
		{name: "forbidden suffix", userName: "alice@evil.com", wantViolations: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbd := &authorizationv1alpha1.RestrictedBindDefinition{
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: tt.userName}},
				},
			}
			violations := EvaluateBindDefinition(policy, rbd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations for user %q, got %d: %v", tt.wantViolations, tt.userName, len(violations), violations)
			}
		})
	}
}

func TestEvaluateBindDefinition_MaxTargetNamespacesDeduplicated(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				TargetNamespaceLimits: &authorizationv1alpha1.NamespaceLimits{
					MaxTargetNamespaces: ptrInt32(2),
				},
			},
		},
	}

	// Same namespace referenced twice — should count as 1.
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"viewer"}},
				{Namespace: "team-a", RoleRefs: []string{"editor"}},
				{Namespace: "team-b", ClusterRoleRefs: []string{"viewer"}},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(policy, rbd)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations (2 unique namespaces <= max 2), got %d: %v", len(violations), violations)
	}
}
