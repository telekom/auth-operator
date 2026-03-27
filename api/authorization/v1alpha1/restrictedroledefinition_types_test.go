// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRestrictedRoleDefinitionGetConditions(t *testing.T) {
	rrd := &RestrictedRoleDefinition{
		Status: RestrictedRoleDefinitionStatus{
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
				{Type: string(PolicyCompliantCondition), Status: metav1.ConditionTrue, Reason: "AllChecksPass"},
			},
		},
	}

	conditions := rrd.GetConditions()
	if len(conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conditions))
	}
	if conditions[0].Type != string(ReadyCondition) {
		t.Errorf("expected 'Ready', got %q", conditions[0].Type)
	}
	if conditions[1].Type != string(PolicyCompliantCondition) {
		t.Errorf("expected 'PolicyCompliant', got %q", conditions[1].Type)
	}
}

func TestRestrictedRoleDefinitionGetConditionsEmpty(t *testing.T) {
	rrd := &RestrictedRoleDefinition{}
	conditions := rrd.GetConditions()
	if conditions != nil {
		t.Errorf("expected nil conditions, got %v", conditions)
	}
}

func TestRestrictedRoleDefinitionSetConditions(t *testing.T) {
	rrd := &RestrictedRoleDefinition{}
	expected := []metav1.Condition{
		{Type: string(ReadyCondition), Status: metav1.ConditionFalse, Reason: "Error"},
	}

	rrd.SetConditions(expected)

	if len(rrd.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rrd.Status.Conditions))
	}
	if rrd.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("expected ConditionFalse, got %q", rrd.Status.Conditions[0].Status)
	}
}

func TestRestrictedRoleDefinitionSetConditionsOverwrite(t *testing.T) {
	rrd := &RestrictedRoleDefinition{
		Status: RestrictedRoleDefinitionStatus{
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionFalse},
				{Type: string(PolicyCompliantCondition), Status: metav1.ConditionFalse},
			},
		},
	}

	rrd.SetConditions([]metav1.Condition{
		{Type: string(ReadyCondition), Status: metav1.ConditionTrue},
	})

	if len(rrd.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition after overwrite, got %d", len(rrd.Status.Conditions))
	}
}

func TestRestrictedRoleDefinitionConstants(t *testing.T) {
	if RestrictedRoleDefinitionFinalizer != "restrictedroledefinition.authorization.t-caas.telekom.com/finalizer" {
		t.Errorf("unexpected finalizer: %s", RestrictedRoleDefinitionFinalizer)
	}
}

func TestRestrictedRoleDefinitionSpecFields(t *testing.T) {
	rrd := &RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
		},
		Spec: RestrictedRoleDefinitionSpec{
			PolicyRef: RBACPolicyReference{
				Name: "tenant-policy",
			},
			TargetRole:      DefinitionNamespacedRole,
			TargetName:      "tenant-role",
			TargetNamespace: "tenant-ns",
			ScopeNamespaced: true,
			RestrictedAPIs: []RestrictedAPIGroup{
				{Name: "apps"},
			},
			RestrictedResources: []metav1.APIResource{
				{Name: "secrets"},
			},
			RestrictedVerbs: []string{"delete"},
		},
	}

	if rrd.Spec.PolicyRef.Name != "tenant-policy" {
		t.Errorf("expected policyRef 'tenant-policy', got %q", rrd.Spec.PolicyRef.Name)
	}
	if rrd.Spec.TargetRole != DefinitionNamespacedRole {
		t.Errorf("expected targetRole 'Role', got %q", rrd.Spec.TargetRole)
	}
	if rrd.Spec.TargetName != "tenant-role" {
		t.Errorf("expected targetName 'tenant-role', got %q", rrd.Spec.TargetName)
	}
	if rrd.Spec.TargetNamespace != "tenant-ns" {
		t.Errorf("expected targetNamespace 'tenant-ns', got %q", rrd.Spec.TargetNamespace)
	}
	if !rrd.Spec.ScopeNamespaced {
		t.Error("expected ScopeNamespaced true")
	}
	if len(rrd.Spec.RestrictedAPIs) != 1 {
		t.Errorf("expected 1 restricted API, got %d", len(rrd.Spec.RestrictedAPIs))
	}
	if len(rrd.Spec.RestrictedResources) != 1 {
		t.Errorf("expected 1 restricted resource, got %d", len(rrd.Spec.RestrictedResources))
	}
	if len(rrd.Spec.RestrictedVerbs) != 1 {
		t.Errorf("expected 1 restricted verb, got %d", len(rrd.Spec.RestrictedVerbs))
	}
}

func TestRestrictedRoleDefinitionClusterRoleSpec(t *testing.T) {
	rrd := &RestrictedRoleDefinition{
		Spec: RestrictedRoleDefinitionSpec{
			PolicyRef:       RBACPolicyReference{Name: "policy"},
			TargetRole:      DefinitionClusterRole,
			TargetName:      "cluster-role-name",
			ScopeNamespaced: false,
		},
	}

	if rrd.Spec.TargetRole != DefinitionClusterRole {
		t.Errorf("expected 'ClusterRole', got %q", rrd.Spec.TargetRole)
	}
	if rrd.Spec.TargetNamespace != "" {
		t.Errorf("expected empty targetNamespace, got %q", rrd.Spec.TargetNamespace)
	}
}

func TestRestrictedRoleDefinitionStatusFields(t *testing.T) {
	rrd := &RestrictedRoleDefinition{
		Status: RestrictedRoleDefinitionStatus{
			ObservedGeneration: 4,
			RoleReconciled:     true,
			PolicyViolations:   []string{"forbidden API group: apps", "forbidden verb: delete"},
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionFalse},
			},
		},
	}

	if rrd.Status.ObservedGeneration != 4 {
		t.Errorf("expected ObservedGeneration 4, got %d", rrd.Status.ObservedGeneration)
	}
	if !rrd.Status.RoleReconciled {
		t.Error("expected RoleReconciled true")
	}
	if len(rrd.Status.PolicyViolations) != 2 {
		t.Errorf("expected 2 policy violations, got %d", len(rrd.Status.PolicyViolations))
	}
}

func TestRestrictedRoleDefinitionDeepCopy(t *testing.T) {
	original := &RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
		},
		Spec: RestrictedRoleDefinitionSpec{
			PolicyRef:       RBACPolicyReference{Name: testPolicyName},
			TargetRole:      DefinitionClusterRole,
			TargetName:      "target-role",
			ScopeNamespaced: false,
			RestrictedAPIs: []RestrictedAPIGroup{
				{Name: "apps"},
			},
			RestrictedVerbs: []string{"delete"},
		},
		Status: RestrictedRoleDefinitionStatus{
			ObservedGeneration: 3,
			RoleReconciled:     true,
			PolicyViolations:   []string{"violation-1"},
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionTrue},
			},
		},
	}

	copied := original.DeepCopy()

	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	// Modify original and verify copy is unaffected.
	original.Name = testModifiedValue
	original.Spec.PolicyRef.Name = "modified-policy"
	original.Spec.RestrictedAPIs[0].Name = testModifiedValue
	original.Status.PolicyViolations[0] = testModifiedValue

	if copied.Name != "test-rrd" {
		t.Errorf("copy name was modified: %q", copied.Name)
	}
	if copied.Spec.PolicyRef.Name != testPolicyName {
		t.Errorf("copy policyRef was modified: %q", copied.Spec.PolicyRef.Name)
	}
	if copied.Spec.RestrictedAPIs[0].Name != "apps" {
		t.Errorf("copy restricted API was modified: %q", copied.Spec.RestrictedAPIs[0].Name)
	}
	if copied.Status.PolicyViolations[0] != "violation-1" {
		t.Errorf("copy violation was modified: %q", copied.Status.PolicyViolations[0])
	}
}

func TestRestrictedRoleDefinitionListDeepCopy(t *testing.T) {
	original := &RestrictedRoleDefinitionList{
		Items: []RestrictedRoleDefinition{
			{ObjectMeta: metav1.ObjectMeta{Name: "rrd1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "rrd2"}},
		},
	}

	copied := original.DeepCopy()
	if len(copied.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(copied.Items))
	}

	original.Items[0].Name = testModifiedValue
	if copied.Items[0].Name != "rrd1" {
		t.Errorf("copy item was modified: %q", copied.Items[0].Name)
	}
}
