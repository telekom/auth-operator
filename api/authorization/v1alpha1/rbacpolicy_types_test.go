// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testModifiedValue = "modified"
const testPolicyName = "policy-1"

func TestRBACPolicyGetConditions(t *testing.T) {
	policy := &RBACPolicy{
		Status: RBACPolicyStatus{
			Conditions: []metav1.Condition{
				{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionTrue, Reason: string(ReadyReasonReconciled)},
			},
		},
	}

	conditions := policy.GetConditions()
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}
	if conditions[0].Type != string(WebhookAuthorizerReadyCondition) {
		t.Errorf("expected condition type 'Ready', got %q", conditions[0].Type)
	}
}

func TestRBACPolicyGetConditionsEmpty(t *testing.T) {
	policy := &RBACPolicy{}
	conditions := policy.GetConditions()
	if conditions != nil {
		t.Errorf("expected nil conditions, got %v", conditions)
	}
}

func TestRBACPolicySetConditions(t *testing.T) {
	policy := &RBACPolicy{}
	expected := []metav1.Condition{
		{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionTrue, Reason: string(ReadyReasonReconciled)},
		{Type: string(PolicyCompliantCondition), Status: metav1.ConditionTrue, Reason: string(PolicyCompliantReasonAllChecksPass)},
	}

	policy.SetConditions(expected)

	if len(policy.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(policy.Status.Conditions))
	}
	if policy.Status.Conditions[0].Type != string(WebhookAuthorizerReadyCondition) {
		t.Errorf("expected first condition type 'Ready', got %q", policy.Status.Conditions[0].Type)
	}
	if policy.Status.Conditions[1].Type != string(PolicyCompliantCondition) {
		t.Errorf("expected second condition type 'PolicyCompliant', got %q", policy.Status.Conditions[1].Type)
	}
}

func TestRBACPolicySetConditionsOverwrite(t *testing.T) {
	policy := &RBACPolicy{
		Status: RBACPolicyStatus{
			Conditions: []metav1.Condition{
				{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionFalse, Reason: "Error"},
			},
		},
	}

	newConditions := []metav1.Condition{
		{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}
	policy.SetConditions(newConditions)

	if len(policy.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(policy.Status.Conditions))
	}
	if policy.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected condition status True, got %q", policy.Status.Conditions[0].Status)
	}
}

func TestRBACPolicyConstants(t *testing.T) {
	if RBACPolicyFinalizer != "rbacpolicy.authorization.t-caas.telekom.com/finalizer" {
		t.Errorf("unexpected finalizer: %s", RBACPolicyFinalizer)
	}
}

func TestRBACPolicySpecFields(t *testing.T) {
	maxNS := int32(10)
	maxRules := int32(50)
	automount := false

	policy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "dev"},
				},
				Namespaces: []string{"ns-1", "ns-2"},
			},
			BindingLimits: &BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &RoleRefLimits{
					AllowedRoleRefs:   []string{"view", "edit"},
					ForbiddenRoleRefs: []string{"cluster-admin"},
				},
				RoleBindingLimits: &RoleRefLimits{
					AllowedRoleRefs: []string{"*-viewer"},
				},
				TargetNamespaceLimits: &NamespaceLimits{
					ForbiddenNamespaces:        []string{"kube-system"},
					ForbiddenNamespacePrefixes: []string{"kube-"},
					MaxTargetNamespaces:        &maxNS,
				},
			},
			RoleLimits: &RoleLimits{
				AllowClusterRoles:  false,
				ForbiddenVerbs:     []string{"delete", "deletecollection"},
				ForbiddenResources: []string{"secrets"},
				ForbiddenAPIGroups: []string{""},
				ForbiddenResourceVerbs: []ResourceVerbRule{
					{Resource: "pods", Verbs: []string{"delete"}},
				},
				MaxRulesPerRole: &maxRules,
			},
			SubjectLimits: &SubjectLimits{
				AllowedKinds:   []string{"ServiceAccount", "Group"},
				ForbiddenKinds: []string{"User"},
				UserLimits: &NameMatchLimits{
					AllowedPrefixes:   []string{"dev-"},
					ForbiddenPrefixes: []string{"admin-"},
				},
				GroupLimits: &NameMatchLimits{
					AllowedNames:   []string{"developers"},
					ForbiddenNames: []string{"cluster-admins"},
				},
				ServiceAccountLimits: &ServiceAccountLimits{
					ForbiddenNamespaces: []string{"kube-system"},
					Creation: &SACreationConfig{
						AllowAutoCreate:              true,
						AutomountServiceAccountToken: &automount,
						DisableAdoption:              true,
					},
				},
			},
		},
	}

	// Verify AppliesTo.
	if policy.Spec.AppliesTo.NamespaceSelector == nil {
		t.Error("expected non-nil NamespaceSelector")
	}
	if len(policy.Spec.AppliesTo.Namespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(policy.Spec.AppliesTo.Namespaces))
	}

	// Verify BindingLimits.
	if !policy.Spec.BindingLimits.AllowClusterRoleBindings {
		t.Error("expected AllowClusterRoleBindings to be true")
	}
	if len(policy.Spec.BindingLimits.ClusterRoleBindingLimits.AllowedRoleRefs) != 2 {
		t.Errorf("expected 2 allowed CRB role refs, got %d",
			len(policy.Spec.BindingLimits.ClusterRoleBindingLimits.AllowedRoleRefs))
	}
	if *policy.Spec.BindingLimits.TargetNamespaceLimits.MaxTargetNamespaces != 10 {
		t.Errorf("expected MaxTargetNamespaces 10, got %d",
			*policy.Spec.BindingLimits.TargetNamespaceLimits.MaxTargetNamespaces)
	}

	// Verify RoleLimits.
	if policy.Spec.RoleLimits.AllowClusterRoles {
		t.Error("expected AllowClusterRoles to be false")
	}
	if *policy.Spec.RoleLimits.MaxRulesPerRole != 50 {
		t.Errorf("expected MaxRulesPerRole 50, got %d", *policy.Spec.RoleLimits.MaxRulesPerRole)
	}

	// Verify SubjectLimits.
	if len(policy.Spec.SubjectLimits.AllowedKinds) != 2 {
		t.Errorf("expected 2 allowed kinds, got %d", len(policy.Spec.SubjectLimits.AllowedKinds))
	}
	if !policy.Spec.SubjectLimits.ServiceAccountLimits.Creation.AllowAutoCreate {
		t.Error("expected AllowAutoCreate to be true")
	}
	if *policy.Spec.SubjectLimits.ServiceAccountLimits.Creation.AutomountServiceAccountToken {
		t.Error("expected AutomountServiceAccountToken to be false")
	}
}

func TestRBACPolicyStatusFields(t *testing.T) {
	policy := &RBACPolicy{
		Status: RBACPolicyStatus{
			ObservedGeneration: 5,
			BoundResourceCount: 3,
			Conditions: []metav1.Condition{
				{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionTrue, Reason: "Reconciled"},
			},
		},
	}

	if policy.Status.ObservedGeneration != 5 {
		t.Errorf("expected ObservedGeneration 5, got %d", policy.Status.ObservedGeneration)
	}
	if policy.Status.BoundResourceCount != 3 {
		t.Errorf("expected BoundResourceCount 3, got %d", policy.Status.BoundResourceCount)
	}
}

func TestPolicyScopeFields(t *testing.T) {
	tests := []struct {
		name  string
		scope PolicyScope
	}{
		{
			name: "selector only",
			scope: PolicyScope{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"team": "alpha"},
				},
			},
		},
		{
			name: "namespaces only",
			scope: PolicyScope{
				Namespaces: []string{"ns-a", "ns-b"},
			},
		},
		{
			name: "both",
			scope: PolicyScope{
				NamespaceSelector: &metav1.LabelSelector{},
				Namespaces:        []string{"ns-c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &RBACPolicy{
				Spec: RBACPolicySpec{
					AppliesTo: tt.scope,
				},
			}
			// Verify fields are set correctly.
			if tt.scope.NamespaceSelector != nil && policy.Spec.AppliesTo.NamespaceSelector == nil {
				t.Error("expected non-nil NamespaceSelector")
			}
			if len(tt.scope.Namespaces) > 0 && len(policy.Spec.AppliesTo.Namespaces) == 0 {
				t.Error("expected non-empty Namespaces")
			}
		})
	}
}

func TestRoleRefLimitsFields(t *testing.T) {
	limits := &RoleRefLimits{
		AllowedRoleRefs:   []string{"view", "edit"},
		ForbiddenRoleRefs: []string{"cluster-admin"},
		AllowedRoleRefSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"tier": "read"},
		},
		ForbiddenRoleRefSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"tier": "admin"},
		},
	}

	if len(limits.AllowedRoleRefs) != 2 {
		t.Errorf("expected 2 allowed refs, got %d", len(limits.AllowedRoleRefs))
	}
	if len(limits.ForbiddenRoleRefs) != 1 {
		t.Errorf("expected 1 forbidden ref, got %d", len(limits.ForbiddenRoleRefs))
	}
	if limits.AllowedRoleRefSelector == nil {
		t.Error("expected non-nil AllowedRoleRefSelector")
	}
	if limits.ForbiddenRoleRefSelector == nil {
		t.Error("expected non-nil ForbiddenRoleRefSelector")
	}
}

func TestNamespaceLimitsFields(t *testing.T) {
	maxNS := int32(5)
	limits := &NamespaceLimits{
		AllowedNamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "dev"},
		},
		ForbiddenNamespaces:        []string{"kube-system", "kube-public"},
		ForbiddenNamespacePrefixes: []string{"kube-"},
		MaxTargetNamespaces:        &maxNS,
	}

	if limits.AllowedNamespaceSelector == nil {
		t.Error("expected non-nil AllowedNamespaceSelector")
	}
	if len(limits.ForbiddenNamespaces) != 2 {
		t.Errorf("expected 2 forbidden namespaces, got %d", len(limits.ForbiddenNamespaces))
	}
	if *limits.MaxTargetNamespaces != 5 {
		t.Errorf("expected MaxTargetNamespaces 5, got %d", *limits.MaxTargetNamespaces)
	}
}

func TestResourceVerbRuleFields(t *testing.T) {
	rule := ResourceVerbRule{
		Resource: "secrets",
		APIGroup: "",
		Verbs:    []string{"get", "list", "watch"},
	}

	if rule.Resource != "secrets" {
		t.Errorf("expected resource 'secrets', got %q", rule.Resource)
	}
	if rule.APIGroup != "" {
		t.Errorf("expected empty API group, got %q", rule.APIGroup)
	}
	if len(rule.Verbs) != 3 {
		t.Errorf("expected 3 verbs, got %d", len(rule.Verbs))
	}
}

func TestSARefFields(t *testing.T) {
	ref := SARef{
		Name:      "my-sa",
		Namespace: "my-ns",
	}

	if ref.Name != "my-sa" {
		t.Errorf("expected name 'my-sa', got %q", ref.Name)
	}
	if ref.Namespace != "my-ns" {
		t.Errorf("expected namespace 'my-ns', got %q", ref.Namespace)
	}
}

func TestSACreationConfigFields(t *testing.T) {
	automount := true
	config := &SACreationConfig{
		AllowAutoCreate: true,
		AllowedCreationNamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "dev"},
		},
		AllowedCreationNamespaces:    []string{"ns-a"},
		AutomountServiceAccountToken: &automount,
		DisableAdoption:              false,
	}

	if !config.AllowAutoCreate {
		t.Error("expected AllowAutoCreate true")
	}
	if config.AllowedCreationNamespaceSelector == nil {
		t.Error("expected non-nil AllowedCreationNamespaceSelector")
	}
	if len(config.AllowedCreationNamespaces) != 1 {
		t.Errorf("expected 1 creation namespace, got %d", len(config.AllowedCreationNamespaces))
	}
	if !*config.AutomountServiceAccountToken {
		t.Error("expected AutomountServiceAccountToken true")
	}
}

func TestNameMatchLimitsFields(t *testing.T) {
	limits := &NameMatchLimits{
		AllowedNames:      []string{"alice", "bob"},
		ForbiddenNames:    []string{"admin"},
		AllowedPrefixes:   []string{"dev-"},
		ForbiddenPrefixes: []string{"system:"},
		AllowedSuffixes:   []string{"-reader"},
		ForbiddenSuffixes: []string{"-admin"},
	}

	if len(limits.AllowedNames) != 2 {
		t.Errorf("expected 2 allowed names, got %d", len(limits.AllowedNames))
	}
	if len(limits.ForbiddenNames) != 1 {
		t.Errorf("expected 1 forbidden name, got %d", len(limits.ForbiddenNames))
	}
	if len(limits.AllowedPrefixes) != 1 {
		t.Errorf("expected 1 allowed prefix, got %d", len(limits.AllowedPrefixes))
	}
	if len(limits.ForbiddenPrefixes) != 1 {
		t.Errorf("expected 1 forbidden prefix, got %d", len(limits.ForbiddenPrefixes))
	}
}

func TestRBACPolicyDeepCopy(t *testing.T) {
	maxNS := int32(10)
	automount := false

	original := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"env": "dev"},
				},
				Namespaces: []string{"ns-1"},
			},
			BindingLimits: &BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &RoleRefLimits{
					AllowedRoleRefs: []string{"view"},
				},
				TargetNamespaceLimits: &NamespaceLimits{
					MaxTargetNamespaces: &maxNS,
				},
			},
			SubjectLimits: &SubjectLimits{
				ServiceAccountLimits: &ServiceAccountLimits{
					Creation: &SACreationConfig{
						AllowAutoCreate:              true,
						AutomountServiceAccountToken: &automount,
					},
				},
			},
		},
		Status: RBACPolicyStatus{
			ObservedGeneration: 3,
			BoundResourceCount: 2,
			Conditions: []metav1.Condition{
				{Type: string(WebhookAuthorizerReadyCondition), Status: metav1.ConditionTrue},
			},
		},
	}

	copied := original.DeepCopy()

	// Verify it's a different object.
	if copied == original {
		t.Fatal("DeepCopy returned same pointer")
	}

	// Modify original and verify copy is unaffected.
	original.Name = testModifiedValue
	original.Spec.AppliesTo.Namespaces[0] = "modified-ns"
	original.Spec.BindingLimits.AllowClusterRoleBindings = false
	original.Status.BoundResourceCount = 99

	if copied.Name != "test-policy" {
		t.Errorf("copy name was modified: %q", copied.Name)
	}
	if copied.Spec.AppliesTo.Namespaces[0] != "ns-1" {
		t.Errorf("copy namespace was modified: %q", copied.Spec.AppliesTo.Namespaces[0])
	}
	if !copied.Spec.BindingLimits.AllowClusterRoleBindings {
		t.Error("copy AllowClusterRoleBindings was modified")
	}
	if copied.Status.BoundResourceCount != 2 {
		t.Errorf("copy BoundResourceCount was modified: %d", copied.Status.BoundResourceCount)
	}
}

func TestRBACPolicyListDeepCopy(t *testing.T) {
	original := &RBACPolicyList{
		Items: []RBACPolicy{
			{ObjectMeta: metav1.ObjectMeta{Name: "p1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "p2"}},
		},
	}

	copied := original.DeepCopy()
	if len(copied.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(copied.Items))
	}

	original.Items[0].Name = testModifiedValue
	if copied.Items[0].Name != "p1" {
		t.Errorf("copy item was modified: %q", copied.Items[0].Name)
	}
}
