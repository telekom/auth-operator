// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import "fmt"

// Violation represents a single policy compliance failure.
type Violation struct {
	// Field is the field path that caused the violation (e.g., "spec.subjects[0].name").
	Field string

	// Message is a human-readable description of the violation.
	Message string
}

// String returns a human-readable representation of the violation.
func (v Violation) String() string {
	if v.Field != "" {
		return fmt.Sprintf("%s: %s", v.Field, v.Message)
	}
	return v.Message
}

// ViolationStrings converts a slice of violations to their string representations.
func ViolationStrings(violations []Violation) []string {
	result := make([]string, len(violations))
	for i, v := range violations {
		result[i] = v.String()
	}
	return result
}
