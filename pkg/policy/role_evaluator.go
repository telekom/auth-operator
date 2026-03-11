// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"

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

	// Check that all forbidden verbs are excluded via RestrictedVerbs.
	// RestrictedVerbs are verbs NOT included in the generated role, so
	// a forbidden verb missing from RestrictedVerbs means it could appear
	// in the generated role.
	for _, verb := range limits.ForbiddenVerbs {
		if !containsString(rrd.Spec.RestrictedVerbs, verb) {
			violations = append(violations, Violation{
				Field:   "spec.restrictedVerbs",
				Message: fmt.Sprintf("forbidden verb %q must be listed in restrictedVerbs", verb),
			})
		}
	}

	// Check that all forbidden API groups are excluded via RestrictedAPIs.
	for _, group := range limits.ForbiddenAPIGroups {
		found := false
		for _, api := range rrd.Spec.RestrictedAPIs {
			if api.Name == group {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, Violation{
				Field:   "spec.restrictedApis",
				Message: fmt.Sprintf("forbidden API group %q must be listed in restrictedApis", group),
			})
		}
	}

	// Check that all forbidden resources are excluded via RestrictedResources.
	for _, res := range limits.ForbiddenResources {
		found := false
		for _, rr := range rrd.Spec.RestrictedResources {
			if rr.Name == res {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, Violation{
				Field:   "spec.restrictedResources",
				Message: fmt.Sprintf("forbidden resource %q must be listed in restrictedResources", res),
			})
		}
	}

	// Check forbidden resource+verb combinations.
	for _, rule := range limits.ForbiddenResourceVerbs {
		// Skip if the entire resource is already excluded.
		if isResourceExcluded(rrd, rule.Resource) {
			continue
		}
		// Skip if the entire API group is already excluded.
		if isAPIGroupExcluded(rrd, rule.APIGroup) {
			continue
		}
		// Check which verbs are not globally restricted.
		var uncovered []string
		for _, verb := range rule.Verbs {
			if !containsString(rrd.Spec.RestrictedVerbs, verb) {
				uncovered = append(uncovered, verb)
			}
		}
		if len(uncovered) > 0 {
			violations = append(violations, Violation{
				Field: "spec.restrictedVerbs",
				Message: fmt.Sprintf(
					"forbidden resource+verb combination: resource %q (apiGroup %q) with verbs [%s] must be restricted",
					rule.Resource, rule.APIGroup, strings.Join(uncovered, ", "),
				),
			})
		}
	}

	return violations
}

// isResourceExcluded returns true if the resource is listed in RestrictedResources.
func isResourceExcluded(rrd *authorizationv1alpha1.RestrictedRoleDefinition, resource string) bool {
	for _, rr := range rrd.Spec.RestrictedResources {
		if rr.Name == resource {
			return true
		}
	}
	return false
}

// isAPIGroupExcluded returns true if the API group is listed in RestrictedAPIs.
func isAPIGroupExcluded(rrd *authorizationv1alpha1.RestrictedRoleDefinition, apiGroup string) bool {
	for _, api := range rrd.Spec.RestrictedAPIs {
		if api.Name == apiGroup {
			return true
		}
	}
	return false
}

// CheckMaxRulesPerRole validates that the number of generated rules does not
// exceed the MaxRulesPerRole limit. This is called from the controller after
// rule generation, since the rule count depends on API discovery.
func CheckMaxRulesPerRole(limits *authorizationv1alpha1.RoleLimits, ruleCount int) *Violation {
	if limits == nil || limits.MaxRulesPerRole == nil {
		return nil
	}
	maxRules := int(*limits.MaxRulesPerRole)
	if ruleCount > maxRules {
		return &Violation{
			Field:   "generated rules",
			Message: fmt.Sprintf("generated role has %d rules, exceeding maximum of %d", ruleCount, maxRules),
		}
	}
	return nil
}
