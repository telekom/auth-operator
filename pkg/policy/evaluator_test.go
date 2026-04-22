// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func ptrInt32(v int32) *int32 { return &v }

// fakeLabelGetter is a test implementation of LabelGetter.
type fakeLabelGetter struct {
	namespaces   map[string]map[string]string
	clusterRoles map[string]map[string]string
	roles        map[string]map[string]string // key: "namespace/name"
	// selectorNamespaces maps a label-selector string to the namespace names it should return.
	selectorNamespaces map[string][]string
}

func (f *fakeLabelGetter) GetNamespaceLabels(_ context.Context, name string) (map[string]string, bool) {
	l, ok := f.namespaces[name]
	return l, ok
}

func (f *fakeLabelGetter) GetClusterRoleLabels(_ context.Context, name string) (map[string]string, bool) {
	l, ok := f.clusterRoles[name]
	return l, ok
}

func (f *fakeLabelGetter) GetRoleLabels(_ context.Context, namespace, name string) (map[string]string, bool) {
	l, ok := f.roles[namespace+"/"+name]
	return l, ok
}

func (f *fakeLabelGetter) ListNamespacesBySelector(_ context.Context, selector *metav1.LabelSelector) ([]string, error) {
	key := metav1.FormatLabelSelector(selector)
	if f.selectorNamespaces != nil {
		if ns, ok := f.selectorNamespaces[key]; ok {
			return ns, nil
		}
	}
	return nil, nil
}

func TestEvaluateBindDefinition_NoLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"viewer"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
					ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
						ClusterRoleRefs: tt.roleRefs,
					},
					Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
				},
			}

			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
				AllowedKinds: []string{rbacv1.UserKind},
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
				AllowedKinds: []string{rbacv1.GroupKind},
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
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

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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
				AllowedKinds: []string{rbacv1.UserKind},
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
			violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
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

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations (2 unique namespaces <= max 2), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateBindDefinition_SubjectKindsDefaultDenyEmpty(t *testing.T) {
	// When SubjectLimits is set but AllowedKinds is empty (nil), all kinds are denied.
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation (empty AllowedKinds = default-deny), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateBindDefinition_RoleRefDefaultDenyEmpty(t *testing.T) {
	// When RoleRefLimits is set but AllowedRoleRefs is empty, all refs are denied.
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"viewer"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation (empty AllowedRoleRefs = default-deny), got %d: %v", len(violations), violations)
	}
}

// --- Label-selector-based tests ---

func TestEvaluateBindDefinition_AllowedRoleRefSelector(t *testing.T) {
	// Test OR semantics: AllowedRoleRefs OR AllowedRoleRefSelector.
	t.Run("selector only - matching labels", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"viewer": {"managed-by": "auth-operator"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (selector matches), got %d: %v", len(violations), violations)
		}
	})

	t.Run("selector only - non-matching labels", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"viewer": {"managed-by": "other"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (selector does not match), got %d: %v", len(violations), violations)
		}
	})

	t.Run("OR semantics - name matches but selector does not", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefs: []string{"viewer"},
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"viewer": {"managed-by": "other"},
			},
		}
		// Name "viewer" is in AllowedRoleRefs → allowed via OR.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (name matches via OR), got %d: %v", len(violations), violations)
		}
	})

	t.Run("OR semantics - selector matches but name does not", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefs: []string{"editor"},
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"viewer": {"managed-by": "auth-operator"},
			},
		}
		// Name "viewer" not in AllowedRoleRefs but matches selector → allowed via OR.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (selector matches via OR), got %d: %v", len(violations), violations)
		}
	})

	t.Run("OR semantics - neither matches", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefs: []string{"editor"},
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"viewer": {"managed-by": "other"},
			},
		}
		// Neither name nor selector matches → violation.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (neither name nor selector matches), got %d: %v", len(violations), violations)
		}
	})

	t.Run("role not found skips selector", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		lg := &fakeLabelGetter{clusterRoles: map[string]map[string]string{}}
		// Role not found → selector can't match → rejected.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (role not found, selector can't match), got %d: %v", len(violations), violations)
		}
	})

	t.Run("nil LabelGetter with selector only", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				BindingLimits: &authorizationv1alpha1.BindingLimits{
					AllowClusterRoleBindings: true,
					ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
						AllowedRoleRefSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"managed-by": "auth-operator"},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"viewer"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		// No LabelGetter → selector treated as not configured → default-deny.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (no resolver, default-deny), got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_ForbiddenRoleRefSelector(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefs: []string{"*"},
					ForbiddenRoleRefSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"privileged": "true"},
					},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	t.Run("matching forbidden selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"admin": {"privileged": "true"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (forbidden selector match), got %d: %v", len(violations), violations)
		}
	})

	t.Run("non-matching forbidden selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			clusterRoles: map[string]map[string]string{
				"admin": {"privileged": "false"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_AllowedNamespaceSelector(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				TargetNamespaceLimits: &authorizationv1alpha1.NamespaceLimits{
					AllowedNamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"viewer"}},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	t.Run("namespace matches selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-a": {"env": "production"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("namespace does not match selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-a": {"env": "staging"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
		}
	})

	t.Run("namespace not found", func(t *testing.T) {
		lg := &fakeLabelGetter{namespaces: map[string]map[string]string{}}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (namespace not found), got %d: %v", len(violations), violations)
		}
	})

	t.Run("nil LabelGetter skips selector", func(t *testing.T) {
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (no resolver), got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_SAAllowedNamespaceSelector(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					AllowedNamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"team": "platform"},
					},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "deployer", Namespace: "platform-ns"},
			},
		},
	}

	t.Run("namespace matches", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"platform-ns": {"team": "platform"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("namespace does not match", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"platform-ns": {"team": "other"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_SAAllowedCreationNamespaces(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate:           true,
						AllowedCreationNamespaces: []string{"team-a", "team-b"},
					},
				},
			},
		},
	}

	t.Run("allowed namespace", func(t *testing.T) {
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-a"},
				},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("disallowed namespace", func(t *testing.T) {
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-c"},
				},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_SACreationNamespaceSelector(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: true,
						AllowedCreationNamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"auto-create": "enabled"},
						},
					},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-ns"},
			},
		},
	}

	t.Run("namespace matches selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-ns": {"auto-create": "enabled"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("namespace does not match selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-ns": {"auto-create": "disabled"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_RoleBindingRoleRefSelector(t *testing.T) {
	// Test that selector checks work for namespace-scoped RoleBinding role refs.
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				RoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"safe": "true"},
					},
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", RoleRefs: []string{"my-role"}},
			},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
		},
	}

	t.Run("role matches selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			roles: map[string]map[string]string{
				"team-a/my-role": {"safe": "true"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("role does not match selector", func(t *testing.T) {
		lg := &fakeLabelGetter{
			roles: map[string]map[string]string{
				"team-a/my-role": {"safe": "false"},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_SACreationNamespaceORSemantics(t *testing.T) {
	// Test OR semantics: AllowedCreationNamespaces OR AllowedCreationNamespaceSelector.
	t.Run("in static list but not matching selector", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				SubjectLimits: &authorizationv1alpha1.SubjectLimits{
					AllowedKinds: []string{rbacv1.ServiceAccountKind},
					ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
						Creation: &authorizationv1alpha1.SACreationConfig{
							AllowAutoCreate:           true,
							AllowedCreationNamespaces: []string{"team-a"},
							AllowedCreationNamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"auto-create": "enabled"},
							},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-a"},
				},
			},
		}
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-a": {"auto-create": "disabled"},
			},
		}
		// "team-a" is in the static list → allowed via OR, even though selector doesn't match.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (static list matches via OR), got %d: %v", len(violations), violations)
		}
	})

	t.Run("matches selector but not in static list", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				SubjectLimits: &authorizationv1alpha1.SubjectLimits{
					AllowedKinds: []string{rbacv1.ServiceAccountKind},
					ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
						Creation: &authorizationv1alpha1.SACreationConfig{
							AllowAutoCreate:           true,
							AllowedCreationNamespaces: []string{"team-a"},
							AllowedCreationNamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"auto-create": "enabled"},
							},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-b"},
				},
			},
		}
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-b": {"auto-create": "enabled"},
			},
		}
		// "team-b" not in static list, but matches selector → allowed via OR.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (selector matches via OR), got %d: %v", len(violations), violations)
		}
	})

	t.Run("matches neither", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				SubjectLimits: &authorizationv1alpha1.SubjectLimits{
					AllowedKinds: []string{rbacv1.ServiceAccountKind},
					ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
						Creation: &authorizationv1alpha1.SACreationConfig{
							AllowAutoCreate:           true,
							AllowedCreationNamespaces: []string{"team-a"},
							AllowedCreationNamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"auto-create": "enabled"},
							},
						},
					},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "runner", Namespace: "team-c"},
				},
			},
		}
		lg := &fakeLabelGetter{
			namespaces: map[string]map[string]string{
				"team-c": {"auto-create": "disabled"},
			},
		}
		// "team-c" not in static list, doesn't match selector → violation.
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, lg)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation (neither matches), got %d: %v", len(violations), violations)
		}
	})
}

func TestEvaluateBindDefinition_AppliesToScope(t *testing.T) {
	t.Run("namespace in static list is allowed", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				AppliesTo: authorizationv1alpha1.PolicyScope{
					Namespaces: []string{"namespace-a"},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "namespace-a"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 0 {
			t.Errorf("expected no violations for namespace in scope, got %v", violations)
		}
	})

	t.Run("namespace outside static list is a violation", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				AppliesTo: authorizationv1alpha1.PolicyScope{
					Namespaces: []string{"namespace-a"},
				},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "namespace-b"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation for namespace outside scope, got %d: %v", len(violations), violations)
		}
		if violations[0].Field != "spec.roleBindings[0].namespace" {
			t.Errorf("expected field spec.roleBindings[0].namespace, got %q", violations[0].Field)
		}
	})

	t.Run("empty Namespaces list (global scope) allows any namespace", func(t *testing.T) {
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				AppliesTo: authorizationv1alpha1.PolicyScope{},
			},
		}
		rbd := &authorizationv1alpha1.RestrictedBindDefinition{
			Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "any-namespace"},
				},
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			},
		}
		violations := EvaluateBindDefinition(context.Background(), policy, rbd, nil)
		if len(violations) != 0 {
			t.Errorf("expected no violations for global scope, got %v", violations)
		}
	})
}
