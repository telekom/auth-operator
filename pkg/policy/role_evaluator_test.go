// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func TestEvaluateRoleDefinition_NoLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "test-role",
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %v", violations)
	}
}

func TestEvaluateRoleDefinition_ClusterRoleNotAllowed(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: false,
			},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "test-role",
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.targetRole" {
		t.Errorf("expected field spec.targetRole, got %q", violations[0].Field)
	}
}

func TestEvaluateRoleDefinition_RoleAllowedWhenClusterRolesDisabled(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: false,
			},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 0 {
		t.Errorf("expected no violations for Role when ClusterRoles are disabled, got %v", violations)
	}
}

func TestEvaluateRoleDefinition_ForbiddenVerbs(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenVerbs: []string{"delete", "escalate"},
			},
		},
	}

	tests := []struct {
		name            string
		restrictedVerbs []string
		wantViolations  int
	}{
		{name: "no forbidden verbs excluded", restrictedVerbs: []string{"get", "list"}, wantViolations: 2},
		{name: "one forbidden verb excluded", restrictedVerbs: []string{"get", "delete"}, wantViolations: 1},
		{name: "all forbidden verbs excluded", restrictedVerbs: []string{"delete", "escalate"}, wantViolations: 0},
		{name: "wildcard covers all forbidden verbs", restrictedVerbs: []string{"*"}, wantViolations: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
					TargetName:      "test-role",
					TargetNamespace: "default",
					RestrictedVerbs: tt.restrictedVerbs,
				},
			}
			violations := EvaluateRoleDefinition(policy, rrd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}
		})
	}
}

func TestEvaluateRoleDefinition_ForbiddenAPIGroups(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenAPIGroups: []string{"certificates.k8s.io"},
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedAPIs: []authorizationv1alpha1.RestrictedAPIGroup{
				{Name: "apps"},
				{Name: "certificates.k8s.io"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations (forbidden API group is already excluded), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateRoleDefinition_ForbiddenAPIGroups_Missing(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenAPIGroups: []string{"certificates.k8s.io"},
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedAPIs: []authorizationv1alpha1.RestrictedAPIGroup{
				{Name: "apps"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation (forbidden API group not excluded), got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.restrictedApis" {
		t.Errorf("expected field spec.restrictedApis, got %q", violations[0].Field)
	}
}

func TestEvaluateRoleDefinition_ForbiddenAPIGroups_VersionBypass(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenAPIGroups: []string{"certificates.k8s.io"},
			},
		},
	}

	// A tenant includes the forbidden group but with a specific version,
	// which would not restrict other versions at runtime.
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedAPIs: []authorizationv1alpha1.RestrictedAPIGroup{
				{Name: "certificates.k8s.io", Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v999"},
				}},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation (version-specific restriction does not fully exclude group), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateRoleDefinition_ForbiddenResources(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenResources: []string{"secrets", "configmaps"},
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedResources: []metav1.APIResource{
				{Name: "pods"},
				{Name: "secrets"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	// "secrets" is in restrictedResources (excluded = compliant).
	// "configmaps" is NOT in restrictedResources (could appear in role = violation).
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.restrictedResources" {
		t.Errorf("expected field spec.restrictedResources, got %q", violations[0].Field)
	}
}

func TestEvaluateRoleDefinition_ForbiddenResources_GroupBypass(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				ForbiddenResources: []string{"secrets"},
			},
		},
	}

	// A tenant includes "secrets" but with a specific group, which would
	// only exclude secrets from that group at runtime, not from all groups.
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedResources: []metav1.APIResource{
				{Name: "secrets", Group: "non.existent.group"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation (group-specific restriction does not exclude from all groups), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateRoleDefinition_ClusterRoleAllowed(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "test-role",
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 0 {
		t.Errorf("expected no violations when ClusterRoles are allowed, got %v", violations)
	}
}

func TestEvaluateRoleDefinition_MultipleLimits(t *testing.T) {
	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles:  false,
				ForbiddenVerbs:     []string{"delete"},
				ForbiddenResources: []string{"secrets"},
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "test-role",
			RestrictedVerbs: []string{"delete"},
			RestrictedResources: []metav1.APIResource{
				{Name: "secrets"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	// ClusterRole not allowed (1). Forbidden verb "delete" and resource "secrets"
	// are both in the restricted lists (excluded from role), so no violations there.
	if len(violations) != 1 {
		t.Errorf("expected 1 violation (ClusterRole only), got %d: %v", len(violations), violations)
	}
}

func TestEvaluateRoleDefinition_ForbiddenResourceVerbs(t *testing.T) {
	tests := []struct {
		name            string
		rules           []authorizationv1alpha1.ResourceVerbRule
		restrictedVerbs []string
		restrictedAPIs  []authorizationv1alpha1.RestrictedAPIGroup
		restrictedRes   []metav1.APIResource
		wantViolations  int
	}{
		{
			name: "resource excluded via RestrictedResources",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "secrets", APIGroup: "", Verbs: []string{"delete"}},
			},
			restrictedRes:  []metav1.APIResource{{Name: "secrets"}},
			wantViolations: 0,
		},
		{
			name: "resource excluded via RestrictedResources with matching group",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "certificates", APIGroup: "cert-manager.io", Verbs: []string{"create"}},
			},
			restrictedRes:  []metav1.APIResource{{Name: "certificates", Group: "cert-manager.io"}},
			wantViolations: 0,
		},
		{
			name: "resource excluded via RestrictedResources with different group",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "certificates", APIGroup: "cert-manager.io", Verbs: []string{"create"}},
			},
			restrictedRes:  []metav1.APIResource{{Name: "certificates", Group: "certificates.k8s.io"}},
			wantViolations: 1,
		},
		{
			name: "API group excluded via RestrictedAPIs",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "certificates", APIGroup: "certificates.k8s.io", Verbs: []string{"create"}},
			},
			restrictedAPIs: []authorizationv1alpha1.RestrictedAPIGroup{{Name: "certificates.k8s.io"}},
			wantViolations: 0,
		},
		{
			name: "all verbs excluded via RestrictedVerbs",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "secrets", APIGroup: "", Verbs: []string{"delete", "patch"}},
			},
			restrictedVerbs: []string{"delete", "patch"},
			wantViolations:  0,
		},
		{
			name: "some verbs not restricted",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "secrets", APIGroup: "", Verbs: []string{"delete", "patch"}},
			},
			restrictedVerbs: []string{"delete"},
			wantViolations:  1,
		},
		{
			name: "no exclusion at all",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "secrets", APIGroup: "", Verbs: []string{"delete"}},
			},
			wantViolations: 1,
		},
		{
			name: "multiple rules mixed",
			rules: []authorizationv1alpha1.ResourceVerbRule{
				{Resource: "secrets", APIGroup: "", Verbs: []string{"delete"}},
				{Resource: "pods", APIGroup: "", Verbs: []string{"create"}},
			},
			restrictedRes:  []metav1.APIResource{{Name: "secrets"}},
			wantViolations: 1, // pods/create not excluded
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authorizationv1alpha1.RBACPolicy{
				Spec: authorizationv1alpha1.RBACPolicySpec{
					RoleLimits: &authorizationv1alpha1.RoleLimits{
						AllowClusterRoles:      true,
						ForbiddenResourceVerbs: tt.rules,
					},
				},
			}
			rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					TargetRole:          authorizationv1alpha1.DefinitionClusterRole,
					TargetName:          "test-role",
					RestrictedVerbs:     tt.restrictedVerbs,
					RestrictedAPIs:      tt.restrictedAPIs,
					RestrictedResources: tt.restrictedRes,
				},
			}
			violations := EvaluateRoleDefinition(p, rrd)
			if len(violations) != tt.wantViolations {
				t.Errorf("expected %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}
		})
	}
}

func TestCheckMaxRulesPerRole_NoLimit(t *testing.T) {
	limits := &authorizationv1alpha1.RoleLimits{}
	if v := CheckMaxRulesPerRole(limits, 100); v != nil {
		t.Errorf("expected no violation when MaxRulesPerRole is nil, got: %v", v)
	}
}

func TestCheckMaxRulesPerRole_NilLimits(t *testing.T) {
	if v := CheckMaxRulesPerRole(nil, 100); v != nil {
		t.Errorf("expected no violation when limits is nil, got: %v", v)
	}
}

func TestCheckMaxRulesPerRole_WithinLimit(t *testing.T) {
	maxRules := int32(10)
	limits := &authorizationv1alpha1.RoleLimits{MaxRulesPerRole: &maxRules}
	if v := CheckMaxRulesPerRole(limits, 10); v != nil {
		t.Errorf("expected no violation when rule count equals max, got: %v", v)
	}
}

func TestCheckMaxRulesPerRole_ExceedsLimit(t *testing.T) {
	maxRules := int32(5)
	limits := &authorizationv1alpha1.RoleLimits{MaxRulesPerRole: &maxRules}
	v := CheckMaxRulesPerRole(limits, 10)
	if v == nil {
		t.Fatal("expected violation when rule count exceeds max")
	}
	if v.Field != "generated rules" {
		t.Errorf("unexpected field: %q", v.Field)
	}
}
