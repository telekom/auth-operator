// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"
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
