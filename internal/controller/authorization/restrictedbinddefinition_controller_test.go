// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/trace/noop"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
	"github.com/telekom/auth-operator/pkg/metrics"
)

func TestRBD_Reconcile_ImpersonationEnabled_UsesImpersonatedClient(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "impersonation-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
			},
			Impersonation: &authorizationv1alpha1.ImpersonationConfig{
				Enabled: true,
				ServiceAccountRef: &authorizationv1alpha1.SARef{
					Name:      "rbac-applier",
					Namespace: "team-alpha",
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "impersonated-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "impersonated-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd)
	r.restConfig = &rest.Config{Host: "https://cluster.local"}

	var capturedUsername string
	var impersonationFactoryCalled bool
	r.impersonatedClientFactory = func(_ *rest.Config, _ *runtime.Scheme, username string) (client.Client, error) {
		impersonationFactoryCalled = true
		capturedUsername = username
		return c, nil
	}

	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))
	g.Expect(impersonationFactoryCalled).To(gomega.BeTrue())
	g.Expect(capturedUsername).To(gomega.Equal("system:serviceaccount:team-alpha:rbac-applier"))

	var crb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "impersonated-target-view-binding"}, &crb)).To(gomega.Succeed())
}

func TestRBD_Reconcile_ImpersonationFactoryError_MarksStalled(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "impersonation-fail-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
			},
			Impersonation: &authorizationv1alpha1.ImpersonationConfig{
				Enabled: true,
				ServiceAccountRef: &authorizationv1alpha1.SARef{
					Name:      "rbac-applier",
					Namespace: "team-alpha",
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "impersonation-fail-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "impersonation-fail-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd)
	r.restConfig = &rest.Config{Host: "https://cluster.local"}
	r.impersonatedClientFactory = func(_ *rest.Config, _ *runtime.Scheme, _ string) (client.Client, error) {
		return nil, fmt.Errorf("failed to build impersonated client")
	}

	_, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("resolve apply client"))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
}

func newRBDTestReconciler(objs ...client.Object) (*RestrictedBindDefinitionReconciler, client.Client) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	recorder := events.NewFakeRecorder(10)
	return NewRestrictedBindDefinitionReconciler(c, scheme, recorder), c
}

func rbdCtx() context.Context {
	return ctrllog.IntoContext(context.Background(), logr.Discard())
}

func ptrBool(v bool) *bool { return &v }

func restrictedTestOwnerRef(kind, name string, uid types.UID) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion:         authorizationv1alpha1.GroupVersion.String(),
		Kind:               kind,
		Name:               name,
		UID:                uid,
		Controller:         &controller,
		BlockOwnerDeletion: ptrBool(false),
	}
}

func readGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := gauge.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("write gauge: %v", err)
	}
	return metric.GetGauge().GetValue()
}

func rbdPolicyWithDefaultAllowances(policy *authorizationv1alpha1.RBACPolicy) *authorizationv1alpha1.RBACPolicy {
	if policy.Spec.BindingLimits == nil {
		policy.Spec.BindingLimits = &authorizationv1alpha1.BindingLimits{AllowClusterRoleBindings: true}
	}
	if policy.Spec.BindingLimits.ClusterRoleBindingLimits == nil {
		policy.Spec.BindingLimits.ClusterRoleBindingLimits = &authorizationv1alpha1.RoleRefLimits{
			AllowedRoleRefs: []string{"edit", "view"},
		}
	}
	if policy.Spec.BindingLimits.RoleBindingLimits == nil {
		policy.Spec.BindingLimits.RoleBindingLimits = &authorizationv1alpha1.RoleRefLimits{
			AllowedRoleRefs: []string{"edit", "my-role", "view"},
		}
	}
	if policy.Spec.SubjectLimits == nil {
		policy.Spec.SubjectLimits = &authorizationv1alpha1.SubjectLimits{
			AllowedKinds: []string{rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind},
		}
	}
	return policy
}

func TestRBD_Reconcile_NotFound(t *testing.T) {
	g := gomega.NewWithT(t)
	r, _ := newRBDTestReconciler()

	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))
}

func TestRBD_Reconcile_PolicyNotFound(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-rbd",
			UID:        "test-rbd-uid",
			Generation: 1,
		},
		Status: authorizationv1alpha1.RestrictedBindDefinitionStatus{
			BindReconciled: true,
			GeneratedServiceAccounts: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "stale-sa", Namespace: "default"},
			},
			ExternalServiceAccounts: []string{"default/external-sa"},
			MissingRoleRefs:         []string{"ClusterRole/stale-role"},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "missing-policy"},
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
	ownedCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-target-view-binding",
			Labels:          map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)},
		},
	}
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "stale-sa",
			Namespace:       "default",
			Labels:          map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)},
		},
	}

	r, c := newRBDTestReconciler(rbd, ownedCRB, ownedSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "test-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.PolicyViolations).To(gomega.HaveLen(1))
	g.Expect(updated.Status.PolicyViolations[0]).To(gomega.ContainSubstring("missing-policy"))
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())

	var deletedCRB rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: ownedCRB.Name}, &deletedCRB)).NotTo(gomega.Succeed())
	var deletedSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: ownedSA.Namespace, Name: ownedSA.Name}, &deletedSA)).NotTo(gomega.Succeed())
}

func TestRBD_Reconcile_PolicyViolation_Deprovision(t *testing.T) {
	g := gomega.NewWithT(t)

	// Policy that disallows ClusterRoleBindings.
	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "strict-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: false,
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "violating-rbd",
			UID:        "violating-rbd-uid",
			Generation: 1,
		},
		Status: authorizationv1alpha1.RestrictedBindDefinitionStatus{
			BindReconciled: true,
			GeneratedServiceAccounts: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "violating-sa", Namespace: "default"},
			},
			ExternalServiceAccounts: []string{"default/external-sa"},
			MissingRoleRefs:         []string{"ClusterRole/admin"},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "strict-policy"},
			TargetName: "violating-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
		},
	}
	ownedCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "violating-target-admin-binding",
			Labels:          map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)},
		},
	}
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "violating-sa",
			Namespace:       "default",
			Labels:          map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ownedCRB, ownedSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "violating-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "violating-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.PolicyViolations).NotTo(gomega.BeEmpty())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeFalse())

	var deletedCRB rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: ownedCRB.Name}, &deletedCRB)).NotTo(gomega.Succeed())
	var deletedSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: ownedSA.Namespace, Name: ownedSA.Name}, &deletedSA)).NotTo(gomega.Succeed())
}

func TestRBD_Reconcile_Deletion(t *testing.T) {
	g := gomega.NewWithT(t)

	now := metav1.Now()
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-rbd",
			Generation:        1,
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RestrictedBindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "any-policy"},
			TargetName: "deleting-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbd)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "deleting-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	// Object should be gone (fake client GCs after removing last finalizer).
	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "deleting-rbd"}, &updated)).NotTo(gomega.Succeed())
}

func TestRBD_Reconcile_GetError(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	errClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("API unavailable")
			},
		}).
		Build()
	recorder := events.NewFakeRecorder(10)
	r := NewRestrictedBindDefinitionReconciler(errClient, scheme, recorder)

	_, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any-rbd"},
	})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("API unavailable"))
}

func TestRBD_HasOwnerRef(t *testing.T) {
	g := gomega.NewWithT(t)

	owner := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owner",
			UID:  "uid-123",
		},
	}

	owned := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owned",
			OwnerReferences: []metav1.OwnerReference{
				{UID: "uid-123"},
			},
		},
	}

	notOwned := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-owned",
			OwnerReferences: []metav1.OwnerReference{
				{UID: "uid-other"},
			},
		},
	}

	noRefs := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-refs",
		},
	}

	g.Expect(hasOwnerRef(owned, owner)).To(gomega.BeTrue())
	g.Expect(hasOwnerRef(notOwned, owner)).To(gomega.BeFalse())
	g.Expect(hasOwnerRef(noRefs, owner)).To(gomega.BeFalse())
}

func TestNewRestrictedBindDefinitionReconciler(t *testing.T) {
	g := gomega.NewWithT(t)
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := events.NewFakeRecorder(10)

	r := NewRestrictedBindDefinitionReconciler(c, scheme, recorder)
	g.Expect(r).NotTo(gomega.BeNil())
	g.Expect(r.client).To(gomega.Equal(c))
	g.Expect(r.scheme).To(gomega.Equal(scheme))
}

func TestRBD_RbdResolveNamespaces_DirectNamespace(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "resolve-ns"},
	}

	r, _ := newRBDTestReconciler(ns)
	binding := authorizationv1alpha1.NamespaceBinding{
		Namespace: "resolve-ns",
	}

	namespaces, err := r.rbdResolveNamespaces(rbdCtx(), binding)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(namespaces).To(gomega.HaveLen(1))
	g.Expect(namespaces[0].Name).To(gomega.Equal("resolve-ns"))
}

func TestRBD_RbdResolveNamespaces_NotFound(t *testing.T) {
	g := gomega.NewWithT(t)

	r, _ := newRBDTestReconciler()
	binding := authorizationv1alpha1.NamespaceBinding{
		Namespace: "nonexistent",
	}

	namespaces, err := r.rbdResolveNamespaces(rbdCtx(), binding)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(namespaces).To(gomega.BeEmpty())
}

func TestRBD_RbdResolveNamespaces_Selector(t *testing.T) {
	g := gomega.NewWithT(t)

	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "match-ns-1",
			Labels: map[string]string{"env": "dev"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "match-ns-2",
			Labels: map[string]string{"env": "dev"},
		},
	}
	ns3 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "no-match-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}

	r, _ := newRBDTestReconciler(ns1, ns2, ns3)
	binding := authorizationv1alpha1.NamespaceBinding{
		NamespaceSelector: []metav1.LabelSelector{
			{MatchLabels: map[string]string{"env": "dev"}},
		},
	}

	namespaces, err := r.rbdResolveNamespaces(rbdCtx(), binding)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(namespaces).To(gomega.HaveLen(2))
}

func TestRBD_Reconcile_PolicyCompliant_CreatesClusterRoleBindings(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "permissive-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "compliant-rbd",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "permissive-policy"},
			TargetName: "compliant-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "testuser", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "compliant-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// CRB should be created by SSA Apply.
	var crb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "compliant-target-view-binding"}, &crb)).To(gomega.Succeed())
	g.Expect(crb.RoleRef.Name).To(gomega.Equal("view"))
	g.Expect(crb.Subjects).To(gomega.HaveLen(1))
	g.Expect(crb.Subjects[0].Name).To(gomega.Equal("testuser"))

	// Status should be ready.
	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "compliant-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.BindReconciled).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
	g.Expect(updated.Status.PolicyViolations).To(gomega.BeEmpty())
}

func TestRBD_ReconcileResources_UnownedClusterRoleBindingIsPreserved(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-rbd", UID: "safe-rbd-uid"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			TargetName: "safe-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
	existing := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-target-view-binding"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, Name: "existing", APIGroup: rbacv1.GroupName},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
	}

	r, c := newRBDTestReconciler(rbd, existing)
	err := r.rbdReconcileResources(rbdCtx(), rbd, c, nil)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already exists and is not owned"))

	var kept rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "safe-target-view-binding"}, &kept)).To(gomega.Succeed())
	g.Expect(kept.RoleRef.Name).To(gomega.Equal("admin"))
	g.Expect(kept.Subjects).To(gomega.ConsistOf(existing.Subjects))
	g.Expect(kept.OwnerReferences).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_UnownedClusterRoleBindingStallsAndPreservesObject(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := rbdPolicyWithDefaultAllowances(&authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	})
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-rbd", UID: "ownership-rbd-uid", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "ownership-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
	existing := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-target-view-binding"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, Name: "existing", APIGroup: rbacv1.GroupName},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
	}

	r, c := newRBDTestReconciler(pol, rbd, existing)
	_, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already exists and is not owned"))

	var kept rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: existing.Name}, &kept)).To(gomega.Succeed())
	g.Expect(kept.RoleRef.Name).To(gomega.Equal("admin"))
	g.Expect(kept.Subjects).To(gomega.ConsistOf(existing.Subjects))
	g.Expect(kept.OwnerReferences).To(gomega.BeEmpty())

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.BindReconciled).To(gomega.BeFalse())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
}

func TestRBD_Reconcile_PolicyCompliant_CreatesRoleBindings(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ns-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"target-ns"},
			},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: false,
			},
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "target-ns",
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ns-rbd",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "ns-policy"},
			TargetName: "ns-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "testuser", APIGroup: rbacv1.GroupName},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					Namespace:       "target-ns",
					ClusterRoleRefs: []string{"edit"},
				},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "ns-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// RoleBinding should be created.
	var rb rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{
		Namespace: "target-ns",
		Name:      "ns-target-edit-binding",
	}, &rb)).To(gomega.Succeed())
	g.Expect(rb.RoleRef.Name).To(gomega.Equal("edit"))
}

func TestRBD_ReconcileResources_UnownedRoleBindingIsPreserved(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-rbd", UID: "safe-rbd-uid"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			TargetName: "safe-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "target-ns", ClusterRoleRefs: []string{"edit"}},
			},
		},
	}
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-target-edit-binding", Namespace: "target-ns"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, Name: "existing", APIGroup: rbacv1.GroupName},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
	}

	r, c := newRBDTestReconciler(rbd, ns, existing)
	err := r.rbdReconcileResources(rbdCtx(), rbd, c, nil)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already exists and is not owned"))

	var kept rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "safe-target-edit-binding", Namespace: "target-ns"}, &kept)).To(gomega.Succeed())
	g.Expect(kept.RoleRef.Name).To(gomega.Equal("admin"))
	g.Expect(kept.Subjects).To(gomega.ConsistOf(existing.Subjects))
	g.Expect(kept.OwnerReferences).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_UnownedRoleBindingStallsAndPreservesObject(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := rbdPolicyWithDefaultAllowances(&authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-rb-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"target-ns"}},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: false,
			},
		},
	})
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "target-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-rb-rbd", UID: "ownership-rb-rbd-uid", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "ownership-rb-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "target-ns", ClusterRoleRefs: []string{"edit"}},
			},
		},
	}
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ownership-rb-target-edit-binding", Namespace: "target-ns"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, Name: "existing", APIGroup: rbacv1.GroupName},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
	}

	r, c := newRBDTestReconciler(pol, rbd, ns, existing)
	_, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already exists and is not owned"))

	var kept rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: existing.Name, Namespace: existing.Namespace}, &kept)).To(gomega.Succeed())
	g.Expect(kept.RoleRef.Name).To(gomega.Equal("admin"))
	g.Expect(kept.Subjects).To(gomega.ConsistOf(existing.Subjects))
	g.Expect(kept.OwnerReferences).To(gomega.BeEmpty())

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.BindReconciled).To(gomega.BeFalse())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
}

func TestRBD_Reconcile_PolicyCompliant_CreatesServiceAccount(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "sa-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: true,
					},
				},
			},
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sa-ns",
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "sa-rbd",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "sa-policy"},
			TargetName: "sa-target",
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      "my-sa",
					Namespace: "sa-ns",
				},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "sa-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// ServiceAccount should be created.
	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{
		Namespace: "sa-ns",
		Name:      "my-sa",
	}, &sa)).To(gomega.Succeed())

	// Status should track the generated SA.
	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "sa-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.HaveLen(1))
	g.Expect(updated.Status.GeneratedServiceAccounts[0].Name).To(gomega.Equal("my-sa"))
	g.Expect(updated.Status.GeneratedServiceAccounts[0].Namespace).To(gomega.Equal("sa-ns"))
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_ServiceAccountPolicyAutomountFalse(t *testing.T) {
	g := gomega.NewWithT(t)
	automountFalse := false

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-policy-automount-false", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate:              true,
						AutomountServiceAccountToken: &automountFalse,
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sa-policy-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-policy-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "sa-policy-automount-false"},
			TargetName: "sa-policy-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "policy-sa", Namespace: "sa-policy-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "sa-policy-rbd"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "sa-policy-ns", Name: "policy-sa"}, &sa)).To(gomega.Succeed())
	g.Expect(sa.AutomountServiceAccountToken).NotTo(gomega.BeNil())
	g.Expect(*sa.AutomountServiceAccountToken).To(gomega.BeFalse())
}

func TestRBD_Reconcile_ServiceAccountPolicyAutomountFalseCapsRBDTrue(t *testing.T) {
	g := gomega.NewWithT(t)
	automountFalse := false
	automountTrue := true

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-policy-automount-cap", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate:              true,
						AutomountServiceAccountToken: &automountFalse,
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sa-cap-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-cap-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:                    authorizationv1alpha1.RBACPolicyReference{Name: "sa-policy-automount-cap"},
			TargetName:                   "sa-cap-target",
			AutomountServiceAccountToken: &automountTrue,
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "cap-sa", Namespace: "sa-cap-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "sa-cap-rbd"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "sa-cap-ns", Name: "cap-sa"}, &sa)).To(gomega.Succeed())
	g.Expect(sa.AutomountServiceAccountToken).NotTo(gomega.BeNil())
	g.Expect(*sa.AutomountServiceAccountToken).To(gomega.BeFalse())
}

func TestRBD_Reconcile_DetectsExternalServiceAccount(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-sa-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ext-ns"}}

	// Pre-existing SA not owned by any RestrictedBindDefinition.
	externalSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-sa", Namespace: "ext-ns"},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "ext-sa-policy"},
			TargetName: "ext-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "ext-sa", Namespace: "ext-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns, externalSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "ext-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// External SA should be tracked in status, not adopted.
	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "ext-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.ConsistOf("ext-ns/ext-sa"))
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_PrunesStaleGeneratedServiceAccount(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "prune-sa-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "prune-sa-rbd", UID: "prune-sa-rbd-uid", Generation: 2},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "prune-sa-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
		Status: authorizationv1alpha1.RestrictedBindDefinitionStatus{
			GeneratedServiceAccounts: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "stale-sa", Namespace: "default"},
			},
		},
	}
	staleSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "stale-sa",
			Namespace:       "default",
			Labels:          map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns, staleSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var deletedSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "default", Name: "stale-sa"}, &deletedSA)).NotTo(gomega.Succeed())

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.BindReconciled).To(gomega.BeTrue())
}

func TestRBD_ClearDeprovisionedStatus(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-status-rbd"},
		Status: authorizationv1alpha1.RestrictedBindDefinitionStatus{
			BindReconciled: true,
			GeneratedServiceAccounts: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "managed-sa", Namespace: "default"},
			},
			ExternalServiceAccounts: []string{"default/external-sa"},
			MissingRoleRefs:         []string{"ClusterRole/missing"},
		},
	}

	rbdClearDeprovisionedStatus(rbd)

	g.Expect(rbd.Status.BindReconciled).To(gomega.BeFalse())
	g.Expect(rbd.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())
	g.Expect(rbd.Status.ExternalServiceAccounts).To(gomega.BeEmpty())
	g.Expect(rbd.Status.MissingRoleRefs).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_AllowAutoCreateFalse_SkipsSACreation(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-autocreate-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: false,
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ac-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ac-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "no-autocreate-policy"},
			TargetName: "ac-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "ac-sa", Namespace: "ac-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "ac-rbd"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var sa corev1.ServiceAccount
	err = c.Get(rbdCtx(), types.NamespacedName{Namespace: "ac-ns", Name: "ac-sa"}, &sa)
	g.Expect(err).To(gomega.HaveOccurred(), "SA should not be created when AllowAutoCreate is false")

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "ac-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())

	var crb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "ac-target-view-binding"}, &crb)).To(gomega.Succeed())
	g.Expect(crb.Subjects).To(gomega.BeEmpty(), "missing SAs must not be pre-staged in RBAC subjects")
}

func TestRBD_Reconcile_ServiceAccountCreationNamespaceDenied_DoesNotBindMissingSA(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := rbdPolicyWithDefaultAllowances(&authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-namespace-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate:           true,
						AllowedCreationNamespaces: []string{"allowed-ns"},
					},
				},
			},
		},
	})
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "blocked-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-namespace-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "sa-namespace-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "blocked-sa", Namespace: "blocked-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "blocked-ns", Name: "blocked-sa"}, &sa)).NotTo(gomega.Succeed())

	var crb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "sa-namespace-target-view-binding"}, &crb)).To(gomega.Succeed())
	g.Expect(crb.Subjects).To(gomega.BeEmpty(), "missing SAs outside the creation scope must not be pre-staged")

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.BeEmpty())
}

func TestRBD_Reconcile_DisableAdoptionTrue_SkipsAdoption(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-adopt-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: true,
						DisableAdoption: true,
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "da-ns"}}

	rbdUID := types.UID("other-rbd-uid")
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "da-sa",
			Namespace: "da-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedBindDefinition",
					Name:       "other-rbd",
					UID:        rbdUID,
					Controller: func() *bool { v := true; return &v }(),
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "da-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "no-adopt-policy"},
			TargetName: "da-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "da-sa", Namespace: "da-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns, ownedSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "da-rbd"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "da-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.ConsistOf("da-ns/da-sa"))
}

func TestRBD_Reconcile_DisableAdoptionTrue_PreservesSameOwnerServiceAccount(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "same-owner-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: true,
						DisableAdoption: true,
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "same-owner-ns"}}
	rbdUID := types.UID("same-owner-rbd-uid")
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "same-owner-rbd", UID: rbdUID, Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "same-owner-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "same-owner-sa", Namespace: "same-owner-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-owner-sa",
			Namespace: "same-owner-ns",
			Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{
				restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbdUID),
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns, ownedSA)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "same-owner-ns", Name: "same-owner-sa"}, &sa)).To(gomega.Succeed())

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.ConsistOf(rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Name:      "same-owner-sa",
		Namespace: "same-owner-ns",
	}))
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.BeEmpty())
}

func TestRBD_DeprovisionCleansUpResources(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deprov-rbd",
			UID:  "deprov-uid",
		},
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "deprov-crb",
			Labels: map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{
				{UID: "deprov-uid"},
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deprov-rb",
			Namespace: "default",
			Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{
				{UID: "deprov-uid"},
			},
		},
	}
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deprov-sa",
			Namespace: "default",
			Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{
				{UID: "deprov-uid"},
			},
		},
	}
	unownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unowned-sa",
			Namespace: "default",
			Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
		},
	}

	unownedCrb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unowned-crb",
		},
	}

	r, c := newRBDTestReconciler(rbd, crb, rb, ownedSA, unownedSA, unownedCrb)
	err := r.rbdDeprovision(rbdCtx(), rbd)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Owned CRB should be deleted.
	var deletedCrb rbacv1.ClusterRoleBinding
	getErr := c.Get(rbdCtx(), types.NamespacedName{Name: "deprov-crb"}, &deletedCrb)
	g.Expect(getErr).To(gomega.HaveOccurred()) // NotFound

	// Owned RB should be deleted.
	var deletedRb rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "deprov-rb", Namespace: "default"}, &deletedRb)).To(gomega.HaveOccurred())

	// Owned SA should be deleted.
	var deletedSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "deprov-sa", Namespace: "default"}, &deletedSA)).To(gomega.HaveOccurred())

	// Unowned CRB should still exist.
	var keptCrb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "unowned-crb"}, &keptCrb)).To(gomega.Succeed())
	var keptSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "unowned-sa", Namespace: "default"}, &keptSA)).To(gomega.Succeed())

	recorder, ok := r.recorder.(*events.FakeRecorder)
	g.Expect(ok).To(gomega.BeTrue())
	close(recorder.Events)
	emitted := make([]string, 0, len(recorder.Events))
	for event := range recorder.Events {
		emitted = append(emitted, event)
	}
	g.Expect(emitted).NotTo(gomega.BeEmpty())
	g.Expect(emitted[len(emitted)-1]).To(gomega.ContainSubstring(authorizationv1alpha1.EventReasonDeprovisioned))
	g.Expect(emitted[len(emitted)-1]).NotTo(gomega.ContainSubstring("policy violations"))
}

func TestRBD_PruneStaleResources_UsesOwnerIndexWithoutManagedLabels(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "indexed-rbd", UID: "indexed-rbd-uid"},
	}
	ownerRef := restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID)
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "indexed-crb",
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "indexed-rb",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crb, rb).
		WithIndex(&rbacv1.ClusterRoleBinding{}, indexer.RestrictedBindDefinitionOwnerRefField, indexer.RestrictedBindDefinitionOwnerRefFunc).
		WithIndex(&rbacv1.RoleBinding{}, indexer.RestrictedBindDefinitionOwnerRefField, indexer.RestrictedBindDefinitionOwnerRefFunc).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	err := r.rbdPruneStaleResources(rbdCtx(), rbd, nil, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	var deletedCrb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "indexed-crb"}, &deletedCrb)).To(gomega.HaveOccurred())
	var deletedRb rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "default", Name: "indexed-rb"}, &deletedRb)).To(gomega.HaveOccurred())
}

func TestRBD_PruneStaleServiceAccounts_UsesOwnerIndexWithoutManagedLabel(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "indexed-sa-rbd", UID: "indexed-sa-rbd-uid"},
	}
	staleSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "indexed-stale-sa",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				restrictedTestOwnerRef(authorizationv1alpha1.RestrictedBindDefinitionKind, rbd.Name, rbd.UID),
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(staleSA).
		WithIndex(&corev1.ServiceAccount{}, indexer.RestrictedBindDefinitionOwnerRefField, indexer.RestrictedBindDefinitionOwnerRefFunc).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	err := r.rbdPruneStaleServiceAccounts(rbdCtx(), rbd, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	var deletedSA corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "default", Name: "indexed-stale-sa"}, &deletedSA)).To(gomega.HaveOccurred())
}

func TestRBD_MarkStalled(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "stall-rbd",
			Generation: 2,
		},
	}

	r, c := newRBDTestReconciler(rbd)
	r.rbdMarkStalled(rbdCtx(), rbd, fmt.Errorf("test error"))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "stall-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(2)))
}

func TestRBD_OwnerRefForRestricted(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owner-rbd",
			UID:  "test-uid-123",
		},
	}

	ref := ownerRefForRestricted(rbd, authorizationv1alpha1.RestrictedBindDefinitionKind)
	g.Expect(ref).NotTo(gomega.BeNil())
	g.Expect(*ref.Name).To(gomega.Equal("owner-rbd"))
	g.Expect(*ref.UID).To(gomega.Equal(types.UID("test-uid-123")))
	g.Expect(*ref.Controller).To(gomega.BeTrue())
	g.Expect(*ref.BlockOwnerDeletion).To(gomega.BeFalse())
}

func TestRBD_Reconcile_PatchFinalizerError(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "patch-err-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "patch-err-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "patch-err-policy"},
			TargetName: "patch-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pol, rbd).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("patch refused")
			},
		}).
		Build()
	recorder := events.NewFakeRecorder(10)
	r := NewRestrictedBindDefinitionReconciler(c, scheme, recorder)

	_, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "patch-err-rbd"},
	})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("patch refused"))
}

func TestRBD_Reconcile_TerminatingNamespaceSkipped(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "term-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}

	// Terminating namespace.
	now := metav1.Now()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "terminating-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceTerminating,
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "term-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "term-policy"},
			TargetName: "term-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "my-sa", Namespace: "terminating-ns"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "term-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// SA should NOT be created in the terminating namespace.
	var sa corev1.ServiceAccount
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Namespace: "terminating-ns", Name: "my-sa"}, &sa)).NotTo(gomega.Succeed())
}

func TestRBD_Reconcile_WithTracer(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "tracer-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tracer-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "tracer-pol"},
			TargetName: "tracer-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "devs"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pol, rbd).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	tracer := noop.NewTracerProvider().Tracer("test")
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10), WithTracer(tracer))

	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tracer-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))
}

func TestRBD_Reconcile_WithTracer_Error(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("injected error")
			},
		}).
		Build()
	tracer := noop.NewTracerProvider().Tracer("test")
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10), WithTracer(tracer))

	_, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any-rbd"},
	})
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestRBD_PolicyToRestrictedBindDefinitions(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "mapped-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "target-policy"},
		},
	}

	scheme := newTestScheme()
	idx := func(obj client.Object) []string {
		r := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
		return []string{r.Spec.PolicyRef.Name}
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rbd).
		WithIndex(&authorizationv1alpha1.RestrictedBindDefinition{}, ".spec.policyRef.name", idx).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	policy := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "target-policy"},
	}
	requests := r.policyToRestrictedBindDefinitions(rbdCtx(), policy)
	g.Expect(requests).To(gomega.HaveLen(1))
	g.Expect(requests[0].Name).To(gomega.Equal("mapped-rbd"))
}

func TestRBD_PolicyToRestrictedBindDefinitions_ListError(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	policy := &authorizationv1alpha1.RBACPolicy{ObjectMeta: metav1.ObjectMeta{Name: "any"}}
	requests := r.policyToRestrictedBindDefinitions(rbdCtx(), policy)
	g.Expect(requests).To(gomega.BeNil())
}

func TestRBD_ClusterRoleToRestrictedBindDefinitions(t *testing.T) {
	g := gomega.NewWithT(t)

	clusterBindingRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-binding-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
	roleBindingClusterRoleRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "role-binding-cluster-role-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"view"}},
			},
		},
	}
	localRoleOnlyRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "local-role-only-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", RoleRefs: []string{"view"}},
			},
		},
	}

	r, _ := newRBDTestReconciler(clusterBindingRBD, roleBindingClusterRoleRBD, localRoleOnlyRBD)
	requests := r.clusterRoleToRestrictedBindDefinitions(rbdCtx(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "view"},
	})

	g.Expect(requests).To(gomega.ConsistOf(
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "cluster-binding-rbd"}},
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "role-binding-cluster-role-rbd"}},
	))
}

func TestRBD_ClusterRoleToRestrictedBindDefinitions_ListError(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	requests := r.clusterRoleToRestrictedBindDefinitions(rbdCtx(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "view"},
	})
	g.Expect(requests).To(gomega.BeNil())
}

func TestRBD_RoleToRestrictedBindDefinitions(t *testing.T) {
	g := gomega.NewWithT(t)

	explicitNamespaceRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "explicit-role-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", RoleRefs: []string{"edit"}},
			},
		},
	}
	selectorRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-role-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{"team": "a"}}}, RoleRefs: []string{"edit"}},
			},
		},
	}
	otherNamespaceRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "other-namespace-role-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-b", RoleRefs: []string{"edit"}},
			},
		},
	}
	clusterRoleRefRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-role-ref-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "team-a", ClusterRoleRefs: []string{"edit"}},
			},
		},
	}

	r, _ := newRBDTestReconciler(explicitNamespaceRBD, selectorRBD, otherNamespaceRBD, clusterRoleRefRBD)
	requests := r.roleToRestrictedBindDefinitions(rbdCtx(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "edit", Namespace: "team-a"},
	})

	g.Expect(requests).To(gomega.ConsistOf(
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "explicit-role-rbd"}},
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "selector-role-rbd"}},
	))

	nonMatchingRequests := r.roleToRestrictedBindDefinitions(rbdCtx(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "view", Namespace: "team-a"},
	})
	g.Expect(nonMatchingRequests).To(gomega.BeEmpty())
}

func TestRBD_RoleToRestrictedBindDefinitions_ListError(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	requests := r.roleToRestrictedBindDefinitions(rbdCtx(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "edit", Namespace: "team-a"},
	})
	g.Expect(requests).To(gomega.BeNil())
}

func TestRBD_NamespaceToRestrictedBindDefinitions(t *testing.T) {
	g := gomega.NewWithT(t)

	// rbd1 has a roleBinding with an explicit namespace match.
	rbd1 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-rbd-1"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "some-namespace", ClusterRoleRefs: []string{"view"}},
			},
		},
	}
	// rbd2 has a roleBinding with a selector. It must be enqueued even when
	// current labels no longer match so stale RoleBindings are pruned promptly.
	rbd2 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-rbd-2"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					NamespaceSelector: []metav1.LabelSelector{
						{MatchLabels: map[string]string{"team": "alpha"}},
					},
					ClusterRoleRefs: []string{"edit"},
				},
			},
		},
	}
	// rbd3 has no roleBindings — should be skipped.
	rbd3 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-rbd-3"},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rbd1, rbd2, rbd3).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "some-namespace"},
	}
	requests := r.namespaceToRestrictedBindDefinitions(rbdCtx(), ns)
	g.Expect(requests).To(gomega.ConsistOf(
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "ns-rbd-1"}},
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "ns-rbd-2"}},
	))
}

func TestRBD_NamespaceToRestrictedBindDefinitions_IndexedSelectorEnqueuesOnLabelRemoval(t *testing.T) {
	g := gomega.NewWithT(t)

	explicitRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "indexed-explicit-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "some-namespace", ClusterRoleRefs: []string{"view"}},
			},
		},
	}
	selectorRBD := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "indexed-selector-rbd"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					NamespaceSelector: []metav1.LabelSelector{
						{MatchLabels: map[string]string{"team": "alpha"}},
					},
					ClusterRoleRefs: []string{"edit"},
				},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(explicitRBD, selectorRBD).
		WithIndex(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			indexer.RestrictedBindDefinitionRoleBindingNamespaceField,
			indexer.RestrictedBindDefinitionRoleBindingNamespaceFunc,
		).
		WithIndex(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			indexer.RestrictedBindDefinitionHasNamespaceSelectorField,
			indexer.RestrictedBindDefinitionHasNamespaceSelectorFunc,
		).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "some-namespace"}}
	requests := r.namespaceToRestrictedBindDefinitions(rbdCtx(), ns)
	g.Expect(requests).To(gomega.ConsistOf(
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "indexed-explicit-rbd"}},
		ctrl.Request{NamespacedName: types.NamespacedName{Name: "indexed-selector-rbd"}},
	))
}

func TestRBD_NamespaceToRestrictedBindDefinitions_ListError(t *testing.T) {
	g := gomega.NewWithT(t)

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "any-ns"}}
	requests := r.namespaceToRestrictedBindDefinitions(rbdCtx(), ns)
	g.Expect(requests).To(gomega.BeNil())
}

func TestRBD_Reconcile_DeleteWithDeprovisionError(t *testing.T) {
	g := gomega.NewWithT(t)

	now := metav1.Now()
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "delete-err-rbd",
			Generation:        1,
			Finalizers:        []string{authorizationv1alpha1.RestrictedBindDefinitionFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			TargetName: "delete-err-target",
		},
	}

	// CRB that will fail to delete.
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "delete-err-target-view-binding",
			Labels: map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedBindDefinition",
					Name:       "delete-err-rbd",
					UID:        rbd.UID,
				},
			},
		},
	}

	scheme := newTestScheme()
	callCount := 0
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rbd, crb).
		WithStatusSubresource(&authorizationv1alpha1.RestrictedBindDefinition{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
					callCount++
					return fmt.Errorf("injected delete error")
				}
				return nil
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	_, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "delete-err-rbd"},
	})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(callCount).To(gomega.BeNumerically(">", 0))
}

func TestRBD_Reconcile_FinalizerAlreadyPresent(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "fin-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fin-rbd",
			Generation: 1,
			Finalizers: []string{authorizationv1alpha1.RestrictedBindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "fin-pol"},
			TargetName: "fin-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "devs"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, _ := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "fin-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))
}

func TestRBD_ReconcileResources_RoleBindingsWithRoleRefs(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-ns"},
	}
	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-rr-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"rb-ns"}},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "rb-rr-rbd",
			Generation: 1,
			Finalizers: []string{authorizationv1alpha1.RestrictedBindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "rb-rr-pol"},
			TargetName: "rb-rr-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "devs"},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					Namespace:       "rb-ns",
					ClusterRoleRefs: []string{"view"},
					RoleRefs:        []string{"my-role"},
				},
			},
		},
	}

	r, c := newRBDTestReconciler(rbdPolicyWithDefaultAllowances(pol), rbd, ns)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "rb-rr-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// Verify CRB for ClusterRoleRef.
	var rbView rbacv1.RoleBinding
	rbViewName := "rb-rr-target-view-binding"
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbViewName, Namespace: "rb-ns"}, &rbView)).To(gomega.Succeed())
	g.Expect(rbView.RoleRef.Kind).To(gomega.Equal("ClusterRole"))

	// Verify RB for RoleRef.
	var rbRole rbacv1.RoleBinding
	rbRoleName := "rb-rr-target-my-role-binding"
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbRoleName, Namespace: "rb-ns"}, &rbRole)).To(gomega.Succeed())
	g.Expect(rbRole.RoleRef.Kind).To(gomega.Equal("Role"))
}

func TestRBD_Reconcile_ReportsMissingRoleRefsWhileReady(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-role-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			BindingLimits: &authorizationv1alpha1.BindingLimits{
				AllowClusterRoleBindings: true,
				ClusterRoleBindingLimits: &authorizationv1alpha1.RoleRefLimits{
					AllowedRoleRefs: []string{"missing-view"},
				},
			},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.UserKind},
			},
		},
	}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-role-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName: "missing-role-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"missing-view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: rbd.Name}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.MissingRoleRefs).To(gomega.ConsistOf("ClusterRole/missing-view"))
	g.Expect(updated.Status.BindReconciled).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())

	gauge, err := metrics.RoleRefsMissing.GetMetricWithLabelValues(rbd.Name)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(readGaugeValue(t, gauge)).To(gomega.Equal(float64(1)))
}

func TestRBD_ReconcileResources_RecreatesOwnedRoleBindingWhenRoleRefKindChanges(t *testing.T) {
	g := gomega.NewWithT(t)

	rbdUID := types.UID("transition-rbd-uid")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "transition-ns"}}
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "transition-rbd", UID: rbdUID, Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			TargetName: "transition-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{Namespace: "transition-ns", RoleRefs: []string{"edit"}},
			},
		},
	}
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "transition-target-edit-binding",
			Namespace: "transition-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         authorizationv1alpha1.GroupVersion.String(),
					Kind:               authorizationv1alpha1.RestrictedBindDefinitionKind,
					Name:               rbd.Name,
					UID:                rbdUID,
					Controller:         ptrBool(true),
					BlockOwnerDeletion: ptrBool(true),
				},
			},
		},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "edit"},
	}

	r, c := newRBDTestReconciler(rbd, ns, existing)
	err := r.rbdReconcileResources(rbdCtx(), rbd, c, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	var rb rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: existing.Name, Namespace: existing.Namespace}, &rb)).To(gomega.Succeed())
	g.Expect(rb.RoleRef).To(gomega.Equal(rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "edit"}))
	g.Expect(rb.Subjects).To(gomega.ConsistOf(rbd.Spec.Subjects))
}

func TestRBD_ReconcileResources_NamespaceGetError(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-err-rbd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			TargetName: "ns-err-target",
			Subjects: []rbacv1.Subject{
				{Kind: authorizationv1alpha1.BindSubjectServiceAccount, Name: "sa", Namespace: "error-ns"},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rbd).
		WithStatusSubresource(&authorizationv1alpha1.RestrictedBindDefinition{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok && key.Name == "error-ns" {
					return fmt.Errorf("injected ns error")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, events.NewFakeRecorder(10))

	err := r.rbdReconcileResources(rbdCtx(), rbd, c, nil)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("get namespace error-ns"))
}

func TestRBD_SAAdoption_UIDMismatch_TreatsAsExternal(t *testing.T) {
	g := gomega.NewWithT(t)

	// Policy that allows SA creation and adoption.
	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "uid-mismatch-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			SubjectLimits: &authorizationv1alpha1.SubjectLimits{
				AllowedKinds: []string{rbacv1.ServiceAccountKind},
				ServiceAccountLimits: &authorizationv1alpha1.ServiceAccountLimits{
					Creation: &authorizationv1alpha1.SACreationConfig{
						AllowAutoCreate: true,
						DisableAdoption: false, // adoption allowed, UID check must fire instead
					},
				},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	differentRBDUID := types.UID("different-rbd-uid-9999")
	// SA already exists and is owned by a *different* RestrictedBindDefinition.
	ownedSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "uid-sa",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedBindDefinition",
					Name:       "other-rbd",
					UID:        differentRBDUID,
					Controller: func() *bool { v := true; return &v }(),
				},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "uid-mismatch-rbd",
			UID:        "this-rbd-uid-1234",
			Generation: 1,
			Finalizers: []string{authorizationv1alpha1.RestrictedBindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "uid-mismatch-policy"},
			TargetName: "uid-mismatch-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "uid-sa", Namespace: "default"},
			},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	scheme := newTestScheme()
	recorder := events.NewFakeRecorder(10)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rbdPolicyWithDefaultAllowances(pol), rbd, ns, ownedSA).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	r := NewRestrictedBindDefinitionReconciler(c, scheme, recorder)

	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "uid-mismatch-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	// SA must NOT be in GeneratedServiceAccounts (it was rejected due to UID mismatch).
	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "uid-mismatch-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.GeneratedServiceAccounts).To(gomega.BeEmpty())
	g.Expect(updated.Status.ExternalServiceAccounts).To(gomega.ConsistOf("default/uid-sa"))

	// A Warning event must have been emitted describing the UID mismatch.
	close(recorder.Events)
	var foundOwnershipWarning bool
	for event := range recorder.Events {
		if containsAll(event, "Warning", authorizationv1alpha1.EventReasonOwnership, string(differentRBDUID)) {
			foundOwnershipWarning = true
		}
	}
	g.Expect(foundOwnershipWarning).To(gomega.BeTrue(), "expected Warning Ownership event for UID mismatch")
}

// containsAll returns true if s contains all of the given substrings.
func containsAll(s string, substrings ...string) bool {
	for _, sub := range substrings {
		found := false
		for i := range s {
			if len(s[i:]) >= len(sub) && s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
