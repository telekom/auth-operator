// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import "strings"

// MatchesWildcard checks if value matches a simple wildcard pattern.
// Supports patterns like "prefix*" (prefix match), "*suffix" (suffix match),
// and "prefix*suffix" (prefix+suffix match). A pattern without wildcards
// requires an exact match.
func MatchesWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}

	idx := strings.Index(pattern, "*")
	if idx < 0 {
		return pattern == value
	}

	prefix := pattern[:idx]
	suffix := pattern[idx+1:]

	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix) && len(value) >= len(prefix)+len(suffix)
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
