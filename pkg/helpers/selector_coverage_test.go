// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsLabelSelectorEmpty(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector *metav1.LabelSelector
		empty    bool
	}{
		{name: "nil", empty: true},
		{name: "zero value", selector: &metav1.LabelSelector{}, empty: true},
		{name: "empty collections", selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{}, MatchExpressions: []metav1.LabelSelectorRequirement{},
		}, empty: true},
		{name: "labels", selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}},
		{name: "expressions", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "team", Operator: metav1.LabelSelectorOpExists,
		}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLabelSelectorEmpty(tc.selector); got != tc.empty {
				t.Fatalf("empty = %v, want %v", got, tc.empty)
			}
		})
	}
}
