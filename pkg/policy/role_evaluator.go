// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"strings"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// EvaluateRoleDefinition checks a RestrictedRoleDefinition against its
// governing RBACPolicy and returns all violations. An empty slice
// indicates full compliance.
func EvaluateRoleDefinition(policy *authorizationv1alpha1.RBACPolicy, rrd *authorizationv1alpha1.RestrictedRoleDefinition) []Violation {
	return EvaluateRoleDefinitionWithLabels(context.Background(), policy, rrd, nil)
}

// EvaluateRoleDefinitionWithLabels checks a RestrictedRoleDefinition against
// its governing RBACPolicy, including selector-based appliesTo checks when a
// LabelGetter is provided.
func EvaluateRoleDefinitionWithLabels(
	ctx context.Context,
	policy *authorizationv1alpha1.RBACPolicy,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	labelGetter LabelGetter,
) []Violation {
	if policy == nil {
		return []Violation{{Field: "<policy>", Message: "policy must not be nil"}}
	}
	if rrd == nil {
		return []Violation{{Field: "<rrd>", Message: "RestrictedRoleDefinition must not be nil"}}
	}

	var violations []Violation

	if rrd.Spec.TargetRole == authorizationv1alpha1.DefinitionClusterRole &&
		!scopeAllowsClusterResources(policy.Spec.AppliesTo) {
		violations = append(violations, Violation{
			Field:   "spec.targetRole",
			Message: `ClusterRoles require appliesTo.namespaces to include "*"`,
		})
	}

	// Enforce appliesTo scope: the Role's target namespace must be within the policy's
	// declared governance scope.
	if rrd.Spec.TargetNamespace != "" && !namespaceInScope(ctx, policy.Spec.AppliesTo, rrd.Spec.TargetNamespace, labelGetter) {
		violations = append(violations, Violation{
			Field:   "spec.targetNamespace",
			Message: fmt.Sprintf("namespace %q is outside the policy's appliesTo scope", rrd.Spec.TargetNamespace),
		})
	}

	if policy.Spec.RoleLimits == nil {
		return append(violations, Violation{
			Field:   "spec.policyRef",
			Message: "policy roleLimits must be configured to allow role generation",
		})
	}

	return append(violations, evaluateRoleLimits(policy.Spec.RoleLimits, rrd)...)
}

// evaluateRoleLimits checks role-related constraints.
func evaluateRoleLimits(limits *authorizationv1alpha1.RoleLimits, rrd *authorizationv1alpha1.RestrictedRoleDefinition) []Violation {
	violations := []Violation{}

	// Check ClusterRole permission.
	if !limits.AllowClusterRoles && rrd.Spec.TargetRole == authorizationv1alpha1.DefinitionClusterRole {
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
		if !ContainsStringOrWildcard(rrd.Spec.RestrictedVerbs, verb) {
			violations = append(violations, Violation{
				Field:   "spec.restrictedVerbs",
				Message: fmt.Sprintf("forbidden verb %q must be listed in restrictedVerbs", verb),
			})
		}
	}

	// Check that all forbidden API groups are excluded via RestrictedAPIs.
	for _, group := range limits.ForbiddenAPIGroups {
		if !isAPIGroupFullyRestricted(rrd, group) {
			violations = append(violations, Violation{
				Field:   "spec.restrictedApis",
				Message: fmt.Sprintf("forbidden API group %q must be listed in restrictedApis", group),
			})
		}
	}

	// Check that all forbidden resources are excluded via RestrictedResources.
	for _, res := range limits.ForbiddenResources {
		if !isResourceFullyRestricted(rrd, res) {
			violations = append(violations, Violation{
				Field:   "spec.restrictedResources",
				Message: fmt.Sprintf("forbidden resource %q must be listed in restrictedResources", res),
			})
		}
	}

	// Check forbidden resource+verb combinations.
	for _, rule := range limits.ForbiddenResourceVerbs {
		// Skip if the entire resource is already excluded in the matching API group.
		if isResourceExcludedForGroup(rrd, rule.Resource, rule.APIGroup) {
			continue
		}
		// Skip if the entire API group is already excluded.
		if isAPIGroupExcluded(rrd, rule.APIGroup) {
			continue
		}
		// Check which verbs are not globally restricted.
		var uncovered []string
		for _, verb := range rule.Verbs {
			if !ContainsStringOrWildcard(rrd.Spec.RestrictedVerbs, verb) &&
				!isAPIGroupVerbRestricted(rrd, rule.APIGroup, verb) {
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

// isAPIGroupFullyRestricted returns true if the API group is listed in
// RestrictedAPIs with empty Versions and empty Verbs lists, meaning the entire
// group (all versions and verbs) is restricted. Specifying versions or verbs
// leaves part of the group available at runtime.
func isAPIGroupFullyRestricted(rrd *authorizationv1alpha1.RestrictedRoleDefinition, group string) bool {
	for _, api := range rrd.Spec.RestrictedAPIs {
		if MatchesAPIGroup(api.Name, group) && len(api.Versions) == 0 && len(api.Verbs) == 0 {
			return true
		}
	}
	return false
}

// isResourceFullyRestricted returns true if the resource is listed in
// RestrictedResources with an empty or "*" Group, meaning the resource is
// restricted from all API groups. If a specific group is set, the resource
// would only be excluded from that group at runtime, allowing it through from
// other groups.
func isResourceFullyRestricted(rrd *authorizationv1alpha1.RestrictedRoleDefinition, res string) bool {
	for _, rr := range rrd.Spec.RestrictedResources {
		if MatchesResourceName(rr.Name, res) && APIGroupRestrictionCovers(rr.Group, "*") {
			return true
		}
	}
	return false
}

// isResourceExcludedForGroup returns true if the resource is listed in RestrictedResources
// and either the restricted resource has no Group set (applies to all groups) or its Group
// matches the given apiGroup.
func isResourceExcludedForGroup(rrd *authorizationv1alpha1.RestrictedRoleDefinition, resource, apiGroup string) bool {
	for _, rr := range rrd.Spec.RestrictedResources {
		if MatchesResourceName(rr.Name, resource) && APIGroupRestrictionCovers(rr.Group, apiGroup) {
			return true
		}
	}
	return false
}

// isAPIGroupExcluded returns true only if the API group is fully excluded in
// RestrictedAPIs, meaning it is listed with empty Versions and Verbs slices.
//
// A group listed with a specific subset of versions or verbs is only partially
// restricted: the remaining versions or verbs would still be accessible at
// runtime, so we cannot consider the group "excluded" for skipping
// ForbiddenResourceVerbs checks.
func isAPIGroupExcluded(rrd *authorizationv1alpha1.RestrictedRoleDefinition, apiGroup string) bool {
	for _, api := range rrd.Spec.RestrictedAPIs {
		if MatchesAPIGroup(api.Name, apiGroup) && len(api.Versions) == 0 && len(api.Verbs) == 0 {
			return true
		}
	}
	return false
}

// isAPIGroupVerbRestricted returns true if RestrictedAPIs removes the given verb
// from all versions in the API group. Version-scoped entries do not count here
// because Kubernetes RBAC rules are version-agnostic and another version can
// still expose the same resource.
func isAPIGroupVerbRestricted(rrd *authorizationv1alpha1.RestrictedRoleDefinition, apiGroup, verb string) bool {
	for _, api := range rrd.Spec.RestrictedAPIs {
		if MatchesAPIGroup(api.Name, apiGroup) && len(api.Versions) == 0 && len(api.Verbs) > 0 &&
			ContainsStringOrWildcard(api.Verbs, verb) {
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
