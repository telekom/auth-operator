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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd)
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd)
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
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "missing-policy"},
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(rbd)
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
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "strict-policy"},
			TargetName: "violating-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd)
	result, err := r.Reconcile(rbdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "violating-rbd"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedBindDefinition
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "violating-rbd"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.BindReconciled).To(gomega.BeFalse())
	g.Expect(updated.Status.PolicyViolations).NotTo(gomega.BeEmpty())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeFalse())
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd)
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

func TestRBD_Reconcile_PolicyCompliant_CreatesRoleBindings(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ns-policy",
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

	r, c := newRBDTestReconciler(pol, rbd, ns)
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd, ns)
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd, ns, externalSA)
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

	unownedCrb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unowned-crb",
		},
	}

	r, c := newRBDTestReconciler(rbd, crb, rb, unownedCrb)
	err := r.rbdDeprovision(rbdCtx(), rbd)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Owned CRB should be deleted.
	var deletedCrb rbacv1.ClusterRoleBinding
	getErr := c.Get(rbdCtx(), types.NamespacedName{Name: "deprov-crb"}, &deletedCrb)
	g.Expect(getErr).To(gomega.HaveOccurred()) // NotFound

	// Owned RB should be deleted.
	var deletedRb rbacv1.RoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "deprov-rb", Namespace: "default"}, &deletedRb)).To(gomega.HaveOccurred())

	// Unowned CRB should still exist.
	var keptCrb rbacv1.ClusterRoleBinding
	g.Expect(c.Get(rbdCtx(), types.NamespacedName{Name: "unowned-crb"}, &keptCrb)).To(gomega.Succeed())
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

	ref := ownerRefForRestricted(rbd, "RestrictedBindDefinition")
	g.Expect(ref).NotTo(gomega.BeNil())
	g.Expect(*ref.Name).To(gomega.Equal("owner-rbd"))
	g.Expect(*ref.UID).To(gomega.Equal(types.UID("test-uid-123")))
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, c := newRBDTestReconciler(pol, rbd, ns)
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
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
	// rbd2 has a roleBinding with a selector that matches any namespace.
	rbd2 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-rbd-2"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{NamespaceSelector: []metav1.LabelSelector{{}}, ClusterRoleRefs: []string{"edit"}},
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
	// Only rbd1 (explicit match) and rbd2 (selector match) should be enqueued.
	g.Expect(requests).To(gomega.HaveLen(2))
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
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	r, _ := newRBDTestReconciler(pol, rbd)
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

	r, c := newRBDTestReconciler(pol, rbd, ns)
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

	err := r.rbdReconcileResources(rbdCtx(), rbd, c)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("get namespace error-ns"))
}
