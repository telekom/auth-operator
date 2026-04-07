// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRBACPolicyReferenceFields(t *testing.T) {
	ref := RBACPolicyReference{
		Name: "my-policy",
	}

	if ref.Name != "my-policy" {
		t.Errorf("expected name 'my-policy', got %q", ref.Name)
	}
}

func TestRBACPolicyReferenceDeepCopy(t *testing.T) {
	original := &RBACPolicyReference{Name: testPolicyName}
	copied := original.DeepCopy()

	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	original.Name = testModifiedValue
	if copied.Name != testPolicyName {
		t.Errorf("copy was modified: %q", copied.Name)
	}
}

func TestUnifiedSelectorFields(t *testing.T) {
	selector := UnifiedSelector{
		Names:    []string{"exact-1", "exact-2"},
		Prefixes: []string{"prefix-"},
		Suffixes: []string{"-suffix"},
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "test"},
		},
	}

	if len(selector.Names) != 2 {
		t.Errorf("expected 2 names, got %d", len(selector.Names))
	}
	if len(selector.Prefixes) != 1 {
		t.Errorf("expected 1 prefix, got %d", len(selector.Prefixes))
	}
	if len(selector.Suffixes) != 1 {
		t.Errorf("expected 1 suffix, got %d", len(selector.Suffixes))
	}
	if selector.LabelSelector == nil {
		t.Error("expected non-nil LabelSelector")
	}
}

func TestUnifiedSelectorDeepCopy(t *testing.T) {
	original := &UnifiedSelector{
		Names:    []string{"name-1"},
		Prefixes: []string{"prefix-"},
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "test"},
		},
	}
	copied := original.DeepCopy()

	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	original.Names[0] = testModifiedValue
	if copied.Names[0] != "name-1" {
		t.Errorf("copy name was modified: %q", copied.Names[0])
	}
}

func TestUnifiedSelectorEmpty(t *testing.T) {
	selector := UnifiedSelector{}

	if selector.Names != nil {
		t.Error("expected nil Names")
	}
	if selector.Prefixes != nil {
		t.Error("expected nil Prefixes")
	}
	if selector.Suffixes != nil {
		t.Error("expected nil Suffixes")
	}
	if selector.LabelSelector != nil {
		t.Error("expected nil LabelSelector")
	}
}
