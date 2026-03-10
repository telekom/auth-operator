// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{name: "exact match", pattern: "admin", value: "admin", want: true},
		{name: "exact mismatch", pattern: "admin", value: "viewer", want: false},
		{name: "star matches all", pattern: "*", value: "anything", want: true},
		{name: "star matches empty", pattern: "*", value: "", want: true},
		{name: "prefix wildcard", pattern: "team-*", value: "team-alpha", want: true},
		{name: "prefix wildcard mismatch", pattern: "team-*", value: "other-alpha", want: false},
		{name: "prefix wildcard exact prefix", pattern: "team-*", value: "team-", want: true},
		{name: "suffix wildcard", pattern: "*-admin", value: "cluster-admin", want: true},
		{name: "suffix wildcard mismatch", pattern: "*-admin", value: "cluster-viewer", want: false},
		{name: "suffix wildcard exact suffix", pattern: "*-admin", value: "-admin", want: true},
		{name: "prefix+suffix wildcard", pattern: "team-*-role", value: "team-alpha-role", want: true},
		{name: "prefix+suffix too short", pattern: "team-*-role", value: "team-role", want: false},
		{name: "prefix+suffix mismatch suffix", pattern: "team-*-role", value: "team-alpha-binding", want: false},
		{name: "prefix+suffix mismatch prefix", pattern: "team-*-role", value: "group-alpha-role", want: false},
		{name: "empty pattern empty value", pattern: "", value: "", want: true},
		{name: "empty pattern non-empty value", pattern: "", value: "x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesWildcard(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyWildcard(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		value    string
		want     bool
	}{
		{name: "matches first", patterns: []string{"admin", "viewer"}, value: "admin", want: true},
		{name: "matches second", patterns: []string{"admin", "viewer"}, value: "viewer", want: true},
		{name: "no match", patterns: []string{"admin", "viewer"}, value: "editor", want: false},
		{name: "empty patterns", patterns: nil, value: "admin", want: false},
		{name: "wildcard match", patterns: []string{"team-*"}, value: "team-alpha", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesAnyWildcard(tt.patterns, tt.value)
			if got != tt.want {
				t.Errorf("matchesAnyWildcard(%v, %q) = %v, want %v", tt.patterns, tt.value, got, tt.want)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		value string
		want  bool
	}{
		{name: "found", slice: []string{"a", "b", "c"}, value: "b", want: true},
		{name: "not found", slice: []string{"a", "b", "c"}, value: "d", want: false},
		{name: "empty slice", slice: nil, value: "a", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsString(tt.slice, tt.value)
			if got != tt.want {
				t.Errorf("containsString(%v, %q) = %v, want %v", tt.slice, tt.value, got, tt.want)
			}
		})
	}
}

func TestHasAnyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		value    string
		want     bool
	}{
		{name: "matches", prefixes: []string{"kube-", "system-"}, value: "kube-system", want: true},
		{name: "no match", prefixes: []string{"kube-", "system-"}, value: "default", want: false},
		{name: "empty prefixes", prefixes: nil, value: "anything", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAnyPrefix(tt.prefixes, tt.value)
			if got != tt.want {
				t.Errorf("hasAnyPrefix(%v, %q) = %v, want %v", tt.prefixes, tt.value, got, tt.want)
			}
		})
	}
}

func TestHasAnySuffix(t *testing.T) {
	tests := []struct {
		name     string
		suffixes []string
		value    string
		want     bool
	}{
		{name: "matches", suffixes: []string{"-admin", "-viewer"}, value: "cluster-admin", want: true},
		{name: "no match", suffixes: []string{"-admin", "-viewer"}, value: "cluster-editor", want: false},
		{name: "empty suffixes", suffixes: nil, value: "anything", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAnySuffix(tt.suffixes, tt.value)
			if got != tt.want {
				t.Errorf("hasAnySuffix(%v, %q) = %v, want %v", tt.suffixes, tt.value, got, tt.want)
			}
		})
	}
}

func TestViolationString(t *testing.T) {
	tests := []struct {
		name      string
		violation Violation
		want      string
	}{
		{
			name:      "with field",
			violation: Violation{Field: "spec.subjects[0]", Message: "not allowed"},
			want:      "spec.subjects[0]: not allowed",
		},
		{
			name:      "without field",
			violation: Violation{Message: "generic violation"},
			want:      "generic violation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.violation.String()
			if got != tt.want {
				t.Errorf("Violation.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
