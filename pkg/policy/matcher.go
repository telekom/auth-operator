// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// namespaceInScope returns true if namespace is within the policy's AppliesTo scope.
// If the scope has no static Namespaces list (i.e. only a NamespaceSelector), this
// function returns true to avoid false positives — selector-based scope enforcement
// requires a LabelGetter and is delegated to the controller.
// An empty scope (no Namespaces and no NamespaceSelector) is treated as global and
// always returns true (backward-compatible: all existing policies are unrestricted).
func namespaceInScope(scope authorizationv1alpha1.PolicyScope, namespace string) bool {
	if len(scope.Namespaces) == 0 {
		return true
	}
	return containsString(scope.Namespaces, namespace)
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

// containsString checks if a string slice contains a specific value.
func containsString(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
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
