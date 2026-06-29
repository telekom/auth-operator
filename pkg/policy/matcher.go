// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"slices"
	"strings"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

const allNamespacesScope = "*"

// namespaceInScope returns true if namespace is within the policy's AppliesTo scope.
// Static namespace entries and NamespaceSelector are combined with OR semantics.
// A selector can only match when a LabelGetter is available and the target
// namespace labels can be resolved. Empty scope fails closed.
//
// namespaces: ["*"] by itself is an explicit all-namespaces scope. When "*"
// is combined with concrete namespaces or a selector, it only enables
// cluster-scoped resources; concrete namespaces and selectors continue to bound
// namespaced targets.
func namespaceInScope(ctx context.Context, scope authorizationv1alpha1.PolicyScope, namespace string, lg LabelGetter) bool {
	if len(scope.Namespaces) == 0 && scope.NamespaceSelector == nil {
		return false
	}
	bareAllNamespaces := slices.Contains(scope.Namespaces, allNamespacesScope) &&
		len(scope.Namespaces) == 1 && scope.NamespaceSelector == nil
	if slices.Contains(scope.Namespaces, namespace) {
		return true
	}
	if scope.NamespaceSelector == nil || lg == nil {
		return bareAllNamespaces
	}
	nsLabels, found := lg.GetNamespaceLabels(ctx, namespace)
	if !found {
		return bareAllNamespaces
	}
	if matchesSelector(scope.NamespaceSelector, nsLabels) {
		return true
	}
	return bareAllNamespaces
}

func scopeAllowsClusterResources(scope authorizationv1alpha1.PolicyScope) bool {
	return slices.Contains(scope.Namespaces, allNamespacesScope)
}

// MatchesWildcard checks if value matches a simple wildcard pattern.
// Supports patterns like "prefix*" (prefix match), "*suffix" (suffix match),
// "prefix*suffix" (prefix+suffix match), and "*mid*" (contains match).
// Multiple wildcards are supported by splitting on "*" and matching parts
// in order. A pattern without wildcards requires an exact match.
func MatchesWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// No wildcards — exact match.
		return pattern == value
	}

	// Check prefix (part before first *).
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	remaining := value[len(parts[0]):]

	// Check suffix (part after last *).
	last := parts[len(parts)-1]
	if !strings.HasSuffix(remaining, last) {
		return false
	}
	remaining = remaining[:len(remaining)-len(last)]

	// Check middle parts appear in order.
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(remaining, mid)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(mid):]
	}

	return true
}

// matchesAnyWildcard returns true if value matches any of the given patterns.
func matchesAnyWildcard(patterns []string, value string) bool {
	for _, p := range patterns {
		if MatchesWildcard(p, value) {
			return true
		}
	}
	return false
}

// ContainsStringOrWildcard checks if a string slice contains the specific value
// or the wildcard "*" (which matches any value).
func ContainsStringOrWildcard(slice []string, value string) bool {
	for _, s := range slice {
		if s == value || s == "*" {
			return true
		}
	}
	return false
}

// MatchesAPIGroup checks whether a configured API group pattern matches an API group.
func MatchesAPIGroup(pattern, apiGroup string) bool {
	return MatchesWildcard(pattern, apiGroup)
}

// MatchesResourceName checks whether a configured resource pattern matches a
// Kubernetes RBAC resource name. A parent resource also covers its subresources,
// so "pods" matches "pods/exec" and "pods/log".
func MatchesResourceName(pattern, resourceName string) bool {
	if MatchesWildcard(pattern, resourceName) {
		return true
	}
	if strings.Contains(pattern, "*") {
		return false
	}
	return strings.HasPrefix(resourceName, pattern+"/")
}

// APIGroupRestrictionCovers checks whether a restricted resource API group
// covers a required API group. An empty restricted group means all API groups,
// matching RestrictedRoleDefinition RestrictedResources semantics.
func APIGroupRestrictionCovers(restrictedGroup, requiredGroup string) bool {
	if restrictedGroup == "" || restrictedGroup == "*" {
		return true
	}
	if requiredGroup == "*" {
		return false
	}
	return MatchesAPIGroup(restrictedGroup, requiredGroup)
}

// hasAnyPrefix checks if value starts with any of the given prefixes.
func hasAnyPrefix(prefixes []string, value string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(value, p) {
			return true
		}
	}
	return false
}

// hasAnySuffix checks if value ends with any of the given suffixes.
func hasAnySuffix(suffixes []string, value string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(value, s) {
			return true
		}
	}
	return false
}
