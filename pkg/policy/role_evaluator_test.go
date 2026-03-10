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
			TargetRole: "ClusterRole",
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
			TargetRole: "ClusterRole",
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
			TargetRole:      "Role",
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
		{name: "no forbidden verbs used", restrictedVerbs: []string{"get", "list"}, wantViolations: 0},
		{name: "one forbidden verb", restrictedVerbs: []string{"get", "delete"}, wantViolations: 1},
		{name: "two forbidden verbs", restrictedVerbs: []string{"delete", "escalate"}, wantViolations: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					TargetRole:      "Role",
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
			TargetRole:      "Role",
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedAPIs: []metav1.APIGroup{
				{Name: "apps"},
				{Name: "certificates.k8s.io"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.restrictedApis[1]" {
		t.Errorf("expected field spec.restrictedApis[1], got %q", violations[0].Field)
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
			TargetRole:      "Role",
			TargetName:      "test-role",
			TargetNamespace: "default",
			RestrictedResources: []metav1.APIResource{
				{Name: "pods"},
				{Name: "secrets"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(violations), violations)
	}
	if violations[0].Field != "spec.restrictedResources[1]" {
		t.Errorf("expected field spec.restrictedResources[1], got %q", violations[0].Field)
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
			TargetRole: "ClusterRole",
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
			TargetRole:      "ClusterRole",
			TargetName:      "test-role",
			RestrictedVerbs: []string{"delete"},
			RestrictedResources: []metav1.APIResource{
				{Name: "secrets"},
			},
		},
	}

	violations := EvaluateRoleDefinition(policy, rrd)
	// ClusterRole not allowed (1) + forbidden verb (1) + forbidden resource (1)
	if len(violations) != 3 {
		t.Errorf("expected 3 violations, got %d: %v", len(violations), violations)
	}
}
