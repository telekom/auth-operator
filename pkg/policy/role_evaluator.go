// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// EvaluateRoleDefinition checks a RestrictedRoleDefinition against its
// governing RBACPolicy and returns all violations. An empty slice
// indicates full compliance.
func EvaluateRoleDefinition(policy *authorizationv1alpha1.RBACPolicy, rrd *authorizationv1alpha1.RestrictedRoleDefinition) []Violation {
	if policy.Spec.RoleLimits == nil {
		return nil
	}

	return evaluateRoleLimits(policy.Spec.RoleLimits, rrd)
}

// evaluateRoleLimits checks role-related constraints.
func evaluateRoleLimits(limits *authorizationv1alpha1.RoleLimits, rrd *authorizationv1alpha1.RestrictedRoleDefinition) []Violation {
	var violations []Violation

	// Check ClusterRole permission.
	if !limits.AllowClusterRoles && rrd.Spec.TargetRole == "ClusterRole" {
		violations = append(violations, Violation{
			Field:   "spec.targetRole",
			Message: "ClusterRoles are not allowed by policy",
		})
	}

	// Check forbidden verbs in RestrictedVerbs.
	for i, verb := range rrd.Spec.RestrictedVerbs {
		if containsString(limits.ForbiddenVerbs, verb) {
			violations = append(violations, Violation{
				Field:   fmt.Sprintf("spec.restrictedVerbs[%d]", i),
				Message: fmt.Sprintf("verb %q is forbidden by policy", verb),
			})
		}
	}

	// Check restricted APIs against forbidden API groups.
	for i, api := range rrd.Spec.RestrictedAPIs {
		if containsString(limits.ForbiddenAPIGroups, api.Name) {
			violations = append(violations, Violation{
				Field:   fmt.Sprintf("spec.restrictedApis[%d]", i),
				Message: fmt.Sprintf("API group %q is forbidden by policy", api.Name),
			})
		}
	}

	// Check restricted resources against forbidden resources.
	for i, res := range rrd.Spec.RestrictedResources {
		if containsString(limits.ForbiddenResources, res.Name) {
			violations = append(violations, Violation{
				Field:   fmt.Sprintf("spec.restrictedResources[%d]", i),
				Message: fmt.Sprintf("resource %q is forbidden by policy", res.Name),
			})
		}
	}

	return violations
}
