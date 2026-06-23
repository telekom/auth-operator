// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"reflect"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestParseRequesterServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		username string
		expectSA bool
		expectNS string
		expectN  string
	}{
		{name: "valid serviceaccount username", username: "system:serviceaccount:team-a:rbac-applier", expectSA: true, expectNS: "team-a", expectN: "rbac-applier"},
		{name: "regular user", username: "alice", expectSA: false},
		{name: "malformed serviceaccount", username: "system:serviceaccount:missing-parts", expectSA: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := parseRequesterServiceAccount(tt.username)
			if sa.IsServiceAccount != tt.expectSA {
				t.Fatalf("expected IsServiceAccount=%v, got %v", tt.expectSA, sa.IsServiceAccount)
			}
			if sa.Namespace != tt.expectNS {
				t.Fatalf("expected namespace %q, got %q", tt.expectNS, sa.Namespace)
			}
			if sa.Name != tt.expectN {
				t.Fatalf("expected name %q, got %q", tt.expectN, sa.Name)
			}
		})
	}
}

func newAdmissionIndexedClient(t *testing.T, scheme *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&RestrictedBindDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*RestrictedBindDefinition).Spec.TargetName}
		}).
		WithIndex(&BindDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*BindDefinition).Spec.TargetName}
		}).
		WithIndex(&RestrictedRoleDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*RestrictedRoleDefinition).Spec.TargetName}
		}).
		WithIndex(&RestrictedRoleDefinition{}, TargetRoleField, func(obj client.Object) []string {
			return []string{obj.(*RestrictedRoleDefinition).Spec.TargetRole}
		}).
		WithIndex(&RestrictedRoleDefinition{}, TargetNamespaceField, func(obj client.Object) []string {
			return []string{obj.(*RestrictedRoleDefinition).Spec.TargetNamespace}
		}).
		WithIndex(&RoleDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*RoleDefinition).Spec.TargetName}
		}).
		WithIndex(&RoleDefinition{}, TargetRoleField, func(obj client.Object) []string {
			return []string{obj.(*RoleDefinition).Spec.TargetRole}
		}).
		WithIndex(&RoleDefinition{}, TargetNamespaceField, func(obj client.Object) []string {
			return []string{obj.(*RoleDefinition).Spec.TargetNamespace}
		}).
		Build()
}

func TestRestrictedValidatorsUseReaderForDefaultPolicyAssignment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	selectedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "selected-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
		},
	}
	assignedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "assigned-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:team-a-admins"},
			},
		},
	}

	newIndexedClient := func(objs ...client.Object) client.Client {
		return fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...).
			WithIndex(&RestrictedBindDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*RestrictedBindDefinition).Spec.TargetName}
			}).
			WithIndex(&BindDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*BindDefinition).Spec.TargetName}
			}).
			WithIndex(&RestrictedRoleDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*RestrictedRoleDefinition).Spec.TargetName}
			}).
			WithIndex(&RestrictedRoleDefinition{}, TargetRoleField, func(obj client.Object) []string {
				return []string{obj.(*RestrictedRoleDefinition).Spec.TargetRole}
			}).
			WithIndex(&RestrictedRoleDefinition{}, TargetNamespaceField, func(obj client.Object) []string {
				return []string{obj.(*RestrictedRoleDefinition).Spec.TargetNamespace}
			}).
			WithIndex(&RoleDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*RoleDefinition).Spec.TargetName}
			}).
			WithIndex(&RoleDefinition{}, TargetRoleField, func(obj client.Object) []string {
				return []string{obj.(*RoleDefinition).Spec.TargetRole}
			}).
			WithIndex(&RoleDefinition{}, TargetNamespaceField, func(obj client.Object) []string {
				return []string{obj.(*RoleDefinition).Spec.TargetNamespace}
			}).
			Build()
	}

	cachedClient := newIndexedClient(selectedPolicy.DeepCopy())
	apiReader := newIndexedClient(selectedPolicy.DeepCopy(), assignedPolicy)

	ctxGroup := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:team-a-admins"},
			},
		},
	})

	t.Run("RestrictedBindDefinition", func(t *testing.T) {
		validator := &RestrictedBindDefinitionValidator{Client: cachedClient, Reader: apiReader}
		rbd := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "reader-rbd"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: selectedPolicy.Name},
				TargetName: "reader-rbd",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		if _, err := validator.ValidateCreate(ctxGroup, rbd); err == nil {
			t.Fatal("expected stale cached client not to hide default-policy assignment")
		} else if !strings.Contains(err.Error(), "assigned-policy") {
			t.Fatalf("expected error to mention API-reader assignment, got: %v", err)
		}

		oldRBD := rbd.DeepCopy()
		newRBD := rbd.DeepCopy()
		newRBD.Spec.Subjects = []rbacv1.Subject{
			{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "bob"},
		}
		if _, err := validator.ValidateUpdate(ctxGroup, oldRBD, newRBD); err == nil {
			t.Fatal("expected update to enforce API-reader default-policy assignment")
		} else if !strings.Contains(err.Error(), "assigned-policy") {
			t.Fatalf("expected update error to mention API-reader assignment, got: %v", err)
		}

		metaRBD := rbd.DeepCopy()
		metaRBD.Labels = map[string]string{"team": "alpha"}
		if _, err := validator.ValidateUpdate(ctxGroup, rbd, metaRBD); err == nil {
			t.Fatal("expected metadata update to enforce API-reader default-policy assignment")
		} else if !strings.Contains(err.Error(), "assigned-policy") {
			t.Fatalf("expected metadata update error to mention API-reader assignment, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{Client: cachedClient, Reader: apiReader}
		rrd := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "reader-rrd"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: selectedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "reader-rrd",
				ScopeNamespaced: false,
			},
		}
		if _, err := validator.ValidateCreate(ctxGroup, rrd); err == nil {
			t.Fatal("expected stale cached client not to hide default-policy assignment")
		} else if !strings.Contains(err.Error(), "assigned-policy") {
			t.Fatalf("expected error to mention API-reader assignment, got: %v", err)
		}
	})
}

func TestUnrestrictedValidatorsUseReaderForAdmissionCriticalLookups(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	cachedClient := newAdmissionIndexedClient(t, scheme)

	t.Run("BindDefinition sees live RestrictedBindDefinition target collision", func(t *testing.T) {
		existing := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "restricted-binding"},
			Spec: RestrictedBindDefinitionSpec{
				TargetName: "shared-binding-target",
			},
		}
		validator := &BindDefinitionValidator{
			Client: cachedClient,
			Reader: newAdmissionIndexedClient(t, scheme,
				existing,
			),
		}
		bd := &BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "plain-binding"},
			Spec: BindDefinitionSpec{
				TargetName: "shared-binding-target",
				Subjects: []rbacv1.Subject{{
					Kind:     rbacv1.UserKind,
					APIGroup: rbacv1.GroupName,
					Name:     "alice",
				}},
			},
		}

		if _, err := validator.ValidateCreate(context.Background(), bd); err == nil {
			t.Fatal("expected stale cached client not to hide RestrictedBindDefinition targetName collision")
		} else if !strings.Contains(err.Error(), "RestrictedBindDefinition") {
			t.Fatalf("expected RestrictedBindDefinition collision, got: %v", err)
		}
	})

	t.Run("RoleDefinition sees live RestrictedRoleDefinition target collision", func(t *testing.T) {
		existing := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "restricted-role"},
			Spec: RestrictedRoleDefinitionSpec{
				TargetName: "shared-role-target",
				TargetRole: DefinitionClusterRole,
			},
		}
		validator := &RoleDefinitionValidator{
			Client: cachedClient,
			Reader: newAdmissionIndexedClient(t, scheme,
				existing,
			),
		}
		rd := &RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "plain-role"},
			Spec: RoleDefinitionSpec{
				TargetName: "shared-role-target",
				TargetRole: DefinitionClusterRole,
			},
		}

		if _, err := validator.ValidateCreate(context.Background(), rd); err == nil {
			t.Fatal("expected stale cached client not to hide RestrictedRoleDefinition targetName collision")
		} else if !strings.Contains(err.Error(), "RestrictedRoleDefinition") {
			t.Fatalf("expected RestrictedRoleDefinition collision, got: %v", err)
		}
	})
}

func TestRestrictedValidatorsUseReaderForAdmissionCriticalLookups(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	policy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "reader-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
		},
	}
	newClient := func(objs ...client.Object) client.Client {
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	}
	cachedClient := newClient()

	t.Run("RestrictedBindDefinition policy existence uses reader", func(t *testing.T) {
		validator := &RestrictedBindDefinitionValidator{
			Client: cachedClient,
			Reader: newClient(policy.DeepCopy()),
		}
		rbd := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "reader-policy-rbd"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: policy.Name},
				TargetName: "reader-policy-rbd",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-a"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		if _, err := validator.ValidateCreate(context.Background(), rbd); err != nil {
			t.Fatalf("expected live reader policy lookup to admit create, got: %v", err)
		}
	})

	t.Run("RestrictedBindDefinition duplicate target uses reader", func(t *testing.T) {
		existing := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-rbd"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: policy.Name},
				TargetName: "shared-rbd-target",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-a"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		validator := &RestrictedBindDefinitionValidator{
			Client: cachedClient,
			Reader: newClient(policy.DeepCopy(), existing),
		}
		rbd := existing.DeepCopy()
		rbd.Name = "new-rbd"
		if _, err := validator.ValidateCreate(context.Background(), rbd); err == nil {
			t.Fatal("expected duplicate target from live reader to be rejected")
		} else if !strings.Contains(err.Error(), "shared-rbd-target") {
			t.Fatalf("expected duplicate target in error, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition duplicate target uses reader", func(t *testing.T) {
		existing := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-rrd"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: policy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "shared-rrd-target",
				ScopeNamespaced: false,
			},
		}
		validator := &RestrictedRoleDefinitionValidator{
			Client: cachedClient,
			Reader: newClient(policy.DeepCopy(), existing),
		}
		rrd := existing.DeepCopy()
		rrd.Name = "new-rrd"
		if _, err := validator.ValidateCreate(context.Background(), rrd); err == nil {
			t.Fatal("expected duplicate target from live reader to be rejected")
		} else if !strings.Contains(err.Error(), "shared-rrd-target") {
			t.Fatalf("expected duplicate target in error, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition rejects ClusterRole aggregation labels", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{
			Client: cachedClient,
			Reader: newClient(policy.DeepCopy()),
		}
		rrd := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aggregate-rrd",
				Labels: map[string]string{
					rbacv1.GroupName + "/aggregate-to-admin": "true",
				},
			},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: policy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "aggregate-rrd",
				ScopeNamespaced: false,
			},
		}
		if _, err := validator.ValidateCreate(context.Background(), rrd); err == nil {
			t.Fatal("expected ClusterRole aggregation label to be rejected")
		} else if !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("expected reserved label error, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition rejects metadata-only aggregation label update", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{
			Client: cachedClient,
			Reader: newClient(policy.DeepCopy()),
		}
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "aggregate-update-rrd"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: policy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "aggregate-update-rrd",
				ScopeNamespaced: false,
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Labels = map[string]string{
			rbacv1.GroupName + "/aggregate-to-admin": "true",
		}
		if _, err := validator.ValidateUpdate(context.Background(), oldRRD, newRRD); err == nil {
			t.Fatal("expected metadata-only ClusterRole aggregation label update to be rejected")
		} else if !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("expected reserved label error, got: %v", err)
		}
	})
}

func TestRestrictedValidatorsEnforceDefaultPolicyAssignmentOnUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	assignedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "assigned-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:team-a-admins"},
			},
		},
	}
	otherAssignedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-assigned-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:team-b-admins"},
			},
		},
	}

	ctxGroup := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:team-a-admins"},
			},
		},
	})
	newClient := func(objs ...client.Object) client.Client {
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	}

	t.Run("RestrictedBindDefinition rejects update for unassigned selected policy", func(t *testing.T) {
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rbd-reject"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetName: "default-policy-update-rbd-reject",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-b"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Spec.Subjects = []rbacv1.Subject{
			{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-b-updated"},
		}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRBD.DeepCopy())
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRBD, newRBD); err == nil {
			t.Fatal("expected update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedBindDefinition allows update for assigned selected policy", func(t *testing.T) {
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rbd-allow"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: assignedPolicy.Name},
				TargetName: "default-policy-update-rbd-allow",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-a"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Spec.Subjects = []rbacv1.Subject{
			{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-a-updated"},
		}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRBD.DeepCopy())
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRBD, newRBD); err != nil {
			t.Fatalf("expected update using assigned selected policy to be allowed, got: %v", err)
		}
	})

	t.Run("RestrictedBindDefinition rejects metadata update for unassigned selected policy", func(t *testing.T) {
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rbd-unchanged"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetName: "default-policy-update-rbd-unchanged",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-b"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Labels = map[string]string{"controller": "touched"}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRBD.DeepCopy())
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRBD, newRBD); err == nil {
			t.Fatal("expected metadata update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedBindDefinition rejects semantic no-op spec and metadata update for unassigned selected policy", func(t *testing.T) {
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rbd-semantic"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetName: "default-policy-update-rbd-semantic",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-b"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Labels = map[string]string{"controller": "touched"}
		newRBD.Spec.RoleBindings = []NamespaceBinding{}
		if reflect.DeepEqual(oldRBD.Spec, newRBD.Spec) {
			t.Fatal("test setup requires reflect-visible spec drift")
		}
		if !equality.Semantic.DeepEqual(oldRBD.Spec, newRBD.Spec) {
			t.Fatal("test setup requires semantically equal spec drift")
		}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRBD.DeepCopy())
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRBD, newRBD); err == nil {
			t.Fatal("expected semantic no-op metadata update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition rejects update for unassigned selected policy", func(t *testing.T) {
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rrd-reject"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "default-policy-update-rrd-reject",
				ScopeNamespaced: false,
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Spec.RestrictedVerbs = []string{"delete"}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRRD.DeepCopy())
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRRD, newRRD); err == nil {
			t.Fatal("expected update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition allows update for assigned selected policy", func(t *testing.T) {
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rrd-allow"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: assignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "default-policy-update-rrd-allow",
				ScopeNamespaced: false,
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Spec.RestrictedVerbs = []string{"delete"}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRRD.DeepCopy())
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRRD, newRRD); err != nil {
			t.Fatalf("expected update using assigned selected policy to be allowed, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition rejects metadata update for unassigned selected policy", func(t *testing.T) {
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rrd-unchanged"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "default-policy-update-rrd-unchanged",
				ScopeNamespaced: false,
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Labels = map[string]string{"controller": "touched"}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRRD.DeepCopy())
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRRD, newRRD); err == nil {
			t.Fatal("expected metadata update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition rejects semantic no-op spec and metadata update for unassigned selected policy", func(t *testing.T) {
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy-update-rrd-semantic"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "default-policy-update-rrd-semantic",
				ScopeNamespaced: false,
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Labels = map[string]string{"controller": "touched"}
		newRRD.Spec.RestrictedVerbs = []string{}
		if reflect.DeepEqual(oldRRD.Spec, newRRD.Spec) {
			t.Fatal("test setup requires reflect-visible spec drift")
		}
		if !equality.Semantic.DeepEqual(oldRRD.Spec, newRRD.Spec) {
			t.Fatal("test setup requires semantically equal spec drift")
		}
		reader := newClient(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy(), oldRRD.DeepCopy())
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxGroup, oldRRD, newRRD); err == nil {
			t.Fatal("expected semantic no-op metadata update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRestrictedValidatorsSkipDefaultPolicyAssignmentForSpecUnchangedUpdates(t *testing.T) {
	ctxOperator := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:auth-operator-system:auth-operator-manager",
			},
		},
	})

	t.Run("RestrictedBindDefinition finalizer update", func(t *testing.T) {
		validator := &RestrictedBindDefinitionValidator{}
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-rbd"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: "default-policy"},
				TargetName: "metadata-rbd",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Finalizers = []string{RestrictedBindDefinitionFinalizer}

		if _, err := validator.ValidateUpdate(ctxOperator, oldRBD, newRBD); err != nil {
			t.Fatalf("expected spec-unchanged finalizer update to bypass requester default-policy checks, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition finalizer update", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{}
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-rrd"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: "default-policy"},
				TargetRole: DefinitionClusterRole,
				TargetName: "metadata-rrd",
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Finalizers = []string{RestrictedRoleDefinitionFinalizer}

		if _, err := validator.ValidateUpdate(ctxOperator, oldRRD, newRRD); err != nil {
			t.Fatalf("expected spec-unchanged finalizer update to bypass requester default-policy checks, got: %v", err)
		}
	})
}

func TestRestrictedValidatorsEnforceDefaultPolicyAssignmentForUserFinalizerUpdates(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	defaultPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-policy"},
		Spec: RBACPolicySpec{
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:platform-admins"},
			},
		},
	}
	reader := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(defaultPolicy.DeepCopy()).
		Build()
	ctxUnassigned := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:tenant-admins"},
			},
		},
	})

	t.Run("RestrictedBindDefinition finalizer update", func(t *testing.T) {
		oldRBD := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-rbd-user"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: defaultPolicy.Name},
				TargetName: "metadata-rbd-user",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		newRBD := oldRBD.DeepCopy()
		newRBD.Finalizers = []string{RestrictedBindDefinitionFinalizer}
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxUnassigned, oldRBD, newRBD); err == nil {
			t.Fatal("expected user finalizer update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition finalizer update", func(t *testing.T) {
		oldRRD := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "metadata-rrd-user"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: defaultPolicy.Name},
				TargetRole: DefinitionClusterRole,
				TargetName: "metadata-rrd-user",
			},
		}
		newRRD := oldRRD.DeepCopy()
		newRRD.Finalizers = []string{RestrictedRoleDefinitionFinalizer}
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}

		if _, err := validator.ValidateUpdate(ctxUnassigned, oldRRD, newRRD); err == nil {
			t.Fatal("expected user finalizer update using unassigned selected policy to be rejected")
		} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRequesterMatchesDefaultAssignment(t *testing.T) {
	da := &DefaultPolicyAssignment{
		Groups: []string{"oidc:platform-operators"},
		ServiceAccounts: []SARef{
			{Name: "rbac-applier", Namespace: "team-a"},
		},
	}

	if !requesterMatchesDefaultAssignment(da, "alice", []string{"oidc:platform-operators"}) {
		t.Fatal("expected group match to be true")
	}

	if !requesterMatchesDefaultAssignment(da, "system:serviceaccount:team-a:rbac-applier", nil) {
		t.Fatal("expected serviceaccount match to be true")
	}

	if requesterMatchesDefaultAssignment(da, "system:serviceaccount:team-b:rbac-applier", nil) {
		t.Fatal("expected non-matching serviceaccount to be false")
	}
}

func TestRestrictedValidatorsAllowDeleteRegardlessOfDefaultPolicyAssignment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	assignedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-assigned-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:team-a-admins"},
			},
		},
	}
	otherAssignedPolicy := &RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-other-assigned-policy"},
		Spec: RBACPolicySpec{
			AppliesTo: PolicyScope{Namespaces: []string{"default"}},
			DefaultAssignment: &DefaultPolicyAssignment{
				Groups: []string{"oidc:team-b-admins"},
			},
		},
	}

	ctxGroup := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:team-a-admins"},
			},
		},
	})
	reader := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(assignedPolicy.DeepCopy(), otherAssignedPolicy.DeepCopy()).
		Build()

	t.Run("RestrictedBindDefinition allows delete for unassigned selected policy", func(t *testing.T) {
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}
		rbd := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-rbd-reject"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetName: "delete-rbd-reject",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-b"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		if _, err := validator.ValidateDelete(ctxGroup, rbd); err != nil {
			t.Fatalf("expected delete using unassigned selected policy to be allowed, got: %v", err)
		}
	})

	t.Run("RestrictedBindDefinition allows delete for assigned selected policy", func(t *testing.T) {
		validator := &RestrictedBindDefinitionValidator{Client: reader, Reader: reader}
		rbd := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-rbd-allow"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:  RBACPolicyReference{Name: assignedPolicy.Name},
				TargetName: "delete-rbd-allow",
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "team-a"},
				},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"view"}},
			},
		}
		if _, err := validator.ValidateDelete(ctxGroup, rbd); err != nil {
			t.Fatalf("expected delete using assigned selected policy to be allowed, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition allows delete for unassigned selected policy", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}
		rrd := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-rrd-reject"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: otherAssignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "delete-rrd-reject",
				ScopeNamespaced: false,
			},
		}
		if _, err := validator.ValidateDelete(ctxGroup, rrd); err != nil {
			t.Fatalf("expected delete using unassigned selected policy to be allowed, got: %v", err)
		}
	})

	t.Run("RestrictedRoleDefinition allows delete for assigned selected policy", func(t *testing.T) {
		validator := &RestrictedRoleDefinitionValidator{Client: reader, Reader: reader}
		rrd := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-rrd-allow"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: assignedPolicy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "delete-rrd-allow",
				ScopeNamespaced: false,
			},
		}
		if _, err := validator.ValidateDelete(ctxGroup, rrd); err != nil {
			t.Fatalf("expected delete using assigned selected policy to be allowed, got: %v", err)
		}
	})
}

func TestValidateDefaultPolicyForRequester(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{Namespaces: []string{"default"}},
				DefaultAssignment: &DefaultPolicyAssignment{
					Groups: []string{"oidc:team-a-admins"},
				},
			},
		},
		&RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-b"},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{Namespaces: []string{"default"}},
				DefaultAssignment: &DefaultPolicyAssignment{
					ServiceAccounts: []SARef{{Name: "rbac-applier", Namespace: "team-a"}},
				},
			},
		},
		&RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-c"},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{Namespaces: []string{"default"}},
				DefaultAssignment: &DefaultPolicyAssignment{
					Groups: []string{"oidc:team-a-admins"},
				},
			},
		},
	).Build()

	gk := schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind}

	ctxGroup := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:team-a-admins"},
			},
		},
	})
	if err := validateDefaultPolicyForRequester(ctxGroup, client, gk, "rrd-a", "policy-a"); err == nil {
		t.Fatal("expected ambiguous overlapping default policies to be rejected")
	} else if !strings.Contains(err.Error(), "matches multiple default policies") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateDefaultPolicyForRequester(ctxGroup, client, gk, "rrd-a", "policy-b"); err == nil {
		t.Fatal("expected ambiguous overlapping default policies to be rejected")
	} else if !strings.Contains(err.Error(), "matches multiple default policies") {
		t.Fatalf("unexpected error: %v", err)
	}

	ctxSA := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:team-a:rbac-applier",
			},
		},
	})
	if err := validateDefaultPolicyForRequester(ctxSA, client, gk, "rrd-b", "policy-b"); err != nil {
		t.Fatalf("expected policy-b to be allowed, got err: %v", err)
	}

	ctxUnassigned := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "bob",
				Groups:   []string{"oidc:unassigned"},
			},
		},
	})
	if err := validateDefaultPolicyForRequester(ctxUnassigned, client, gk, "rrd-unassigned", "policy-a"); err == nil {
		t.Fatal("expected unassigned requester to be rejected when selecting a policy with defaultAssignment")
	} else if !strings.Contains(err.Error(), "is not assigned to selected default policy") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateDefaultPolicyForRequester(ctxGroup, client, gk, "rrd-missing", "missing-policy"); err == nil {
		t.Fatal("expected missing selected policy to fail validation")
	} else if !apierrors.IsInvalid(err) {
		t.Fatalf("expected invalid error for missing selected policy, got: %v", err)
	} else if apierrors.IsInternalError(err) {
		t.Fatalf("expected missing selected policy not to become internal error, got: %v", err)
	} else if !strings.Contains(err.Error(), "spec.policyRef.name") {
		t.Fatalf("expected error to identify spec.policyRef.name, got: %v", err)
	} else if !strings.Contains(err.Error(), "missing-policy") {
		t.Fatalf("expected error to mention missing policy, got: %v", err)
	}

	// No admission request in context: skip enforcement.
	if err := validateDefaultPolicyForRequester(context.Background(), client, gk, "rrd-c", "anything"); err != nil {
		t.Fatalf("expected no error without admission context, got: %v", err)
	}
}

func TestSelectedPolicyMatchesRequesterReturnsNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	matches, err := selectedPolicyMatchesRequester(context.Background(), client, "missing-policy", "alice", nil)
	if err == nil {
		t.Fatal("expected missing selected policy to return an error")
	}
	if matches {
		t.Fatal("expected missing selected policy not to match requester")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound error for missing selected policy, got: %v", err)
	}
}
