// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRestrictedBindDefinitionGetConditions(t *testing.T) {
	rbd := &RestrictedBindDefinition{
		Status: RestrictedBindDefinitionStatus{
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
				{Type: string(PolicyCompliantCondition), Status: metav1.ConditionTrue, Reason: "AllChecksPass"},
			},
		},
	}

	conditions := rbd.GetConditions()
	if len(conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conditions))
	}
	if conditions[0].Type != string(ReadyCondition) {
		t.Errorf("expected first condition type 'Ready', got %q", conditions[0].Type)
	}
	if conditions[1].Type != string(PolicyCompliantCondition) {
		t.Errorf("expected second condition type 'PolicyCompliant', got %q", conditions[1].Type)
	}
}

func TestRestrictedBindDefinitionGetConditionsEmpty(t *testing.T) {
	rbd := &RestrictedBindDefinition{}
	conditions := rbd.GetConditions()
	if conditions != nil {
		t.Errorf("expected nil conditions, got %v", conditions)
	}
}

func TestRestrictedBindDefinitionSetConditions(t *testing.T) {
	rbd := &RestrictedBindDefinition{}
	expected := []metav1.Condition{
		{Type: string(ReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}

	rbd.SetConditions(expected)

	if len(rbd.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rbd.Status.Conditions))
	}
}

func TestRestrictedBindDefinitionSetConditionsOverwrite(t *testing.T) {
	rbd := &RestrictedBindDefinition{
		Status: RestrictedBindDefinitionStatus{
			Conditions: []metav1.Condition{
				{Type: string(ReadyCondition), Status: metav1.ConditionFalse},
				{Type: string(PolicyCompliantCondition), Status: metav1.ConditionFalse},
			},
		},
	}

	newConditions := []metav1.Condition{
		{Type: string(ReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}
	rbd.SetConditions(newConditions)

	if len(rbd.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition after overwrite, got %d", len(rbd.Status.Conditions))
	}
}

func TestRestrictedBindDefinitionConstants(t *testing.T) {
	if RestrictedBindDefinitionFinalizer != "restrictedbinddefinition.authorization.t-caas.telekom.com/finalizer" {
		t.Errorf("unexpected finalizer: %s", RestrictedBindDefinitionFinalizer)
	}
}

func TestRestrictedBindDefinitionSpecFields(t *testing.T) {
	automount := false

	rbd := &RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rbd",
		},
		Spec: RestrictedBindDefinitionSpec{
			PolicyRef: RBACPolicyReference{
				Name: "tenant-policy",
			},
			TargetName: "my-tenant",
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "my-sa",
					Namespace: "tenant-ns",
				},
				{
					Kind:     "Group",
					APIGroup: "rbac.authorization.k8s.io",
					Name:     "developers",
				},
			},
			ClusterRoleBindings: &ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
			RoleBindings: []NamespaceBinding{
				{
					ClusterRoleRefs: []string{"edit"},
					NamespaceSelector: []metav1.LabelSelector{
						{MatchLabels: map[string]string{"env": "dev"}},
					},
				},
			},
			AutomountServiceAccountToken: &automount,
		},
	}

	if rbd.Spec.PolicyRef.Name != "tenant-policy" {
		t.Errorf("expected policyRef 'tenant-policy', got %q", rbd.Spec.PolicyRef.Name)
	}
	if rbd.Spec.TargetName != "my-tenant" {
		t.Errorf("expected targetName 'my-tenant', got %q", rbd.Spec.TargetName)
	}
	if len(rbd.Spec.Subjects) != 2 {
		t.Errorf("expected 2 subjects, got %d", len(rbd.Spec.Subjects))
	}
	if len(rbd.Spec.ClusterRoleBindings.ClusterRoleRefs) != 1 {
		t.Errorf("expected 1 CRB ref, got %d", len(rbd.Spec.ClusterRoleBindings.ClusterRoleRefs))
	}
	if len(rbd.Spec.RoleBindings) != 1 {
		t.Errorf("expected 1 RB, got %d", len(rbd.Spec.RoleBindings))
	}
	if *rbd.Spec.AutomountServiceAccountToken {
		t.Error("expected AutomountServiceAccountToken false")
	}
}

func TestRestrictedBindDefinitionStatusFields(t *testing.T) {
	rbd := &RestrictedBindDefinition{
		Status: RestrictedBindDefinitionStatus{
			ObservedGeneration: 7,
			BindReconciled:     true,
			GeneratedServiceAccounts: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "auto-sa", Namespace: "ns-1"},
			},
			MissingRoleRefs:         []string{"ClusterRole/missing-role"},
			ExternalServiceAccounts: []string{"ns-1/external-sa"},
			PolicyViolations:        []string{"forbidden verb: delete"},
		},
	}

	if rbd.Status.ObservedGeneration != 7 {
		t.Errorf("expected ObservedGeneration 7, got %d", rbd.Status.ObservedGeneration)
	}
	if !rbd.Status.BindReconciled {
		t.Error("expected BindReconciled true")
	}
	if len(rbd.Status.GeneratedServiceAccounts) != 1 {
		t.Errorf("expected 1 generated SA, got %d", len(rbd.Status.GeneratedServiceAccounts))
	}
	if len(rbd.Status.MissingRoleRefs) != 1 {
		t.Errorf("expected 1 missing role ref, got %d", len(rbd.Status.MissingRoleRefs))
	}
	if len(rbd.Status.ExternalServiceAccounts) != 1 {
		t.Errorf("expected 1 external SA, got %d", len(rbd.Status.ExternalServiceAccounts))
	}
	if len(rbd.Status.PolicyViolations) != 1 {
		t.Errorf("expected 1 policy violation, got %d", len(rbd.Status.PolicyViolations))
	}
}

func TestRestrictedBindDefinitionDeepCopy(t *testing.T) {
	automount := true
	original := &RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rbd",
		},
		Spec: RestrictedBindDefinitionSpec{
			PolicyRef:  RBACPolicyReference{Name: testPolicyName},
			TargetName: "target",
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "devs"},
			},
			ClusterRoleBindings: &ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
			RoleBindings: []NamespaceBinding{
				{ClusterRoleRefs: []string{"edit"}, Namespace: "ns-1"},
			},
			AutomountServiceAccountToken: &automount,
		},
		Status: RestrictedBindDefinitionStatus{
			ObservedGeneration: 2,
			BindReconciled:     true,
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
	original.Spec.Subjects[0].Name = "modified-group"
	original.Status.PolicyViolations[0] = testModifiedValue

	if copied.Name != "test-rbd" {
		t.Errorf("copy name was modified: %q", copied.Name)
	}
	if copied.Spec.PolicyRef.Name != testPolicyName {
		t.Errorf("copy policyRef was modified: %q", copied.Spec.PolicyRef.Name)
	}
	if copied.Spec.Subjects[0].Name != "devs" {
		t.Errorf("copy subject was modified: %q", copied.Spec.Subjects[0].Name)
	}
	if copied.Status.PolicyViolations[0] != "violation-1" {
		t.Errorf("copy violation was modified: %q", copied.Status.PolicyViolations[0])
	}
}

func TestRestrictedBindDefinitionListDeepCopy(t *testing.T) {
	original := &RestrictedBindDefinitionList{
		Items: []RestrictedBindDefinition{
			{ObjectMeta: metav1.ObjectMeta{Name: "rbd1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "rbd2"}},
		},
	}

	copied := original.DeepCopy()
	if len(copied.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(copied.Items))
	}

	original.Items[0].Name = testModifiedValue
	if copied.Items[0].Name != "rbd1" {
		t.Errorf("copy item was modified: %q", copied.Items[0].Name)
	}
}
