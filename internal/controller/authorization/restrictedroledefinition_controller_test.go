// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.opentelemetry.io/otel/trace/noop"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/indexer"
)

// --- Standard Go tests (no envtest) ---

func newRRDTestReconcilerFake(objs ...client.Object) (*RestrictedRoleDefinitionReconciler, client.Client) {
	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	return &RestrictedRoleDefinitionReconciler{
		client:   c,
		reader:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}, c
}

func rrdCtx() context.Context {
	return ctrllog.IntoContext(context.Background(), logr.Discard())
}

func TestRRD_Reconcile_NotFound(t *testing.T) {
	g := NewWithT(t)
	r, _ := newRRDTestReconcilerFake()

	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(ctrl.Result{}))
}

func TestRRD_Reconcile_PolicyNotFound(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-rrd",
			UID:        "test-rrd-uid",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "missing-policy"},
			TargetName: "test-role-name",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
		Status: authorizationv1alpha1.RestrictedRoleDefinitionStatus{
			RoleReconciled: true,
		},
	}
	ownedRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-role-name",
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedRoleDefinitionKind, rrd.Name, rrd.UID)},
		},
	}

	r, c := newRRDTestReconcilerFake(rrd, ownedRole)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "test-rrd"}, &updated)).To(Succeed())
	g.Expect(updated.Status.PolicyViolations).To(HaveLen(1))
	g.Expect(updated.Status.PolicyViolations[0]).To(ContainSubstring("missing-policy"))
	g.Expect(conditions.IsStalled(&updated)).To(BeTrue())

	var deletedRole rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: ownedRole.Name}, &deletedRole)).NotTo(Succeed())
}

func TestRRD_Reconcile_PolicyNotFoundReturnsStatusApplyError(t *testing.T) {
	g := NewWithT(t)

	s := newTestScheme()
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "status-error-rrd", UID: "status-error-rrd-uid", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: "missing-policy"},
			TargetName:      "status-error-role",
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			ScopeNamespaced: false,
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rrd).
		WithStatusSubresource(&authorizationv1alpha1.RestrictedRoleDefinition{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				return fmt.Errorf("status apply failed")
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		reader:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: rrd.Name},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("stalled status"))
	g.Expect(err.Error()).To(ContainSubstring("status apply failed"))
}

func TestRRD_Reconcile_UsesReaderForPolicyEvaluation(t *testing.T) {
	g := NewWithT(t)

	stalePolicy := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}
	freshPolicy := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Generation: 2},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: false,
			},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "reader-policy-rrd", UID: "reader-policy-rrd-uid", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: stalePolicy.Name},
			TargetName:      "reader-policy-role",
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			ScopeNamespaced: false,
		},
	}

	r, c := newRRDTestReconcilerFake(stalePolicy, rrd)
	r.reader = fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(freshPolicy).
		Build()

	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: rrd.Name},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "reader-policy-role"}, &cr)).NotTo(Succeed())

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: rrd.Name}, &updated)).To(Succeed())
	g.Expect(updated.Status.PolicyViolations).NotTo(BeEmpty())
	g.Expect(conditions.IsReady(&updated)).To(BeFalse())
}

func TestRRD_Reconcile_DeletingPolicyIsUnavailable(t *testing.T) {
	g := NewWithT(t)
	now := metav1.Now()

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-policy",
			Generation:        1,
			DeletionTimestamp: &now,
			Finalizers:        []string{"test.finalizer"},
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deleting-policy-rrd", UID: "deleting-policy-rrd-uid", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName:      "deleting-policy-role",
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			ScopeNamespaced: false,
		},
	}

	r, c := newRRDTestReconcilerFake(pol, rrd)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: rrd.Name},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "deleting-policy-role"}, &cr)).NotTo(Succeed())

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: rrd.Name}, &updated)).To(Succeed())
	g.Expect(updated.Status.PolicyViolations).To(ConsistOf("policy \"deleting-policy\" is being deleted"))
	g.Expect(conditions.IsStalled(&updated)).To(BeTrue())
}

func TestRRD_Reconcile_PolicyViolation(t *testing.T) {
	g := NewWithT(t)

	// Policy forbids ClusterRoles.
	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "no-cr-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: false,
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "violating-rrd",
			UID:        "violating-rrd-uid",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "no-cr-policy"},
			TargetName: "violating-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
		Status: authorizationv1alpha1.RestrictedRoleDefinitionStatus{
			RoleReconciled: true,
		},
	}
	ownedRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "violating-role",
			OwnerReferences: []metav1.OwnerReference{restrictedTestOwnerRef(authorizationv1alpha1.RestrictedRoleDefinitionKind, rrd.Name, rrd.UID)},
		},
	}

	r, c := newRRDTestReconcilerFake(pol, rrd, ownedRole)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "violating-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "violating-rrd"}, &updated)).To(Succeed())
	g.Expect(updated.Status.PolicyViolations).NotTo(BeEmpty())
	g.Expect(conditions.IsReady(&updated)).To(BeFalse())

	var deletedRole rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: ownedRole.Name}, &deletedRole)).NotTo(Succeed())
}

func TestRRD_Reconcile_PolicyScopeSelectorGetError_MarksStalledAndRemovesOwnedRole(t *testing.T) {
	g := NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-policy", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"team": "a"},
				},
			},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "selector-error-rrd",
			UID:        "selector-error-rrd-uid",
			Generation: 1,
			Finalizers: []string{authorizationv1alpha1.RestrictedRoleDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
			TargetName:      "selector-role",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetNamespace: "team-a",
		},
	}
	ownedRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rrd.Spec.TargetName,
			Namespace: rrd.Spec.TargetNamespace,
			OwnerReferences: []metav1.OwnerReference{
				restrictedTestOwnerRef(authorizationv1alpha1.RestrictedRoleDefinitionKind, rrd.Name, rrd.UID),
			},
		},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(pol, rrd, ownedRole).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok && key.Name == rrd.Spec.TargetNamespace {
					return fmt.Errorf("injected namespace selector get error")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		reader:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	result, err := r.Reconcile(rrdCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: rrd.Name}})

	g.Expect(result).To(Equal(ctrl.Result{}))
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("evaluate policy selectors for RestrictedRoleDefinition"))

	var keptRole rbacv1.Role
	err = c.Get(rrdCtx(), types.NamespacedName{Namespace: ownedRole.Namespace, Name: ownedRole.Name}, &keptRole)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue())

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: rrd.Name}, &updated)).To(Succeed())
	g.Expect(conditions.IsStalled(&updated)).To(BeTrue())
	g.Expect(conditions.GetReason(&updated, conditions.StalledConditionType)).To(Equal(string(authorizationv1alpha1.StalledReasonError)))
	g.Expect(updated.Status.RoleReconciled).To(BeFalse())
}

func TestRRD_Reconcile_Deletion(t *testing.T) {
	g := NewWithT(t)

	now := metav1.Now()
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-rrd",
			Generation:        1,
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RestrictedRoleDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "any-policy"},
			TargetName: "deleting-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(rrd)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "deleting-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(ctrl.Result{}))

	// Object should be gone (fake client GCs after removing last finalizer).
	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "deleting-rrd"}, &updated)).NotTo(Succeed())
}

func TestRRD_Reconcile_Deletion_NoFinalizer(t *testing.T) {
	g := NewWithT(t)

	now := metav1.Now()
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-nofin",
			DeletionTimestamp: &now,
			Finalizers:        []string{"other-finalizer"},
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "any-policy"},
			TargetName: "deleting-role-2",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, _ := newRRDTestReconcilerFake(rrd)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "deleting-nofin"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(ctrl.Result{}))
}

func TestRRD_Reconcile_GetError(t *testing.T) {
	g := NewWithT(t)

	s := newTestScheme()
	errClient := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("API unavailable")
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   errClient,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any-rrd"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("API unavailable"))
}

func TestNewRestrictedRoleDefinitionReconciler(t *testing.T) {
	g := NewWithT(t)
	s := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(s).Build()
	recorder := events.NewFakeRecorder(10)
	tracker := discovery.NewResourceTracker(s, nil)
	tracer := noop.NewTracerProvider().Tracer("test")

	r, err := NewRestrictedRoleDefinitionReconciler(c, s, recorder, tracker, WithTracer(tracer))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(r).NotTo(BeNil())
	g.Expect(r.client).To(Equal(c))
	g.Expect(r.tracer).NotTo(BeNil())
}

func TestNewRestrictedRoleDefinitionReconciler_NilTracker(t *testing.T) {
	g := NewWithT(t)
	s := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(s).Build()
	recorder := events.NewFakeRecorder(10)

	_, err := NewRestrictedRoleDefinitionReconciler(c, s, recorder, nil)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("resourceTracker cannot be nil"))
}

func TestRRD_ResolveApplyClient_ImpersonationEnabled_UsesFactory(t *testing.T) {
	g := NewWithT(t)

	r, c := newRRDTestReconcilerFake()
	r.restConfig = &rest.Config{Host: "https://cluster.local"}

	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			Impersonation: &authorizationv1alpha1.ImpersonationConfig{
				Enabled: true,
				ServiceAccountRef: &authorizationv1alpha1.SARef{
					Name:      "rbac-applier",
					Namespace: "team-a",
				},
			},
		},
	}

	var capturedUsername string
	r.impersonatedClientFactory = func(_ *rest.Config, _ *runtime.Scheme, username string) (client.Client, error) {
		capturedUsername = username
		return c, nil
	}

	applyClient, impersonatedUser, err := r.rrdResolveApplyClient(policy)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(impersonatedUser).To(Equal("system:serviceaccount:team-a:rbac-applier"))
	g.Expect(capturedUsername).To(Equal(impersonatedUser))
	g.Expect(applyClient).To(Equal(c))
}

func TestRRD_ResolveApplyClient_ImpersonationFactoryError(t *testing.T) {
	g := NewWithT(t)

	r, _ := newRRDTestReconcilerFake()
	r.restConfig = &rest.Config{Host: "https://cluster.local"}

	policy := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "rrd-impersonation-policy"},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			Impersonation: &authorizationv1alpha1.ImpersonationConfig{
				Enabled: true,
				ServiceAccountRef: &authorizationv1alpha1.SARef{
					Name:      "rbac-applier",
					Namespace: "team-a",
				},
			},
		},
	}

	r.impersonatedClientFactory = func(_ *rest.Config, _ *runtime.Scheme, _ string) (client.Client, error) {
		return nil, fmt.Errorf("factory error")
	}

	_, _, err := r.rrdResolveApplyClient(policy)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("factory error"))
}

func TestRRD_Deprovision_ClusterRole(t *testing.T) {
	g := NewWithT(t)

	controller := true
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deprov-test-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       authorizationv1alpha1.RestrictedRoleDefinitionKind,
				Name:       "deprov-rrd",
				UID:        "deprov-rrd-uid",
				Controller: &controller,
			}},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd", UID: "deprov-rrd-uid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "deprov-test-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(cr, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	// ClusterRole should be deleted.
	var deleted rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "deprov-test-role"}, &deleted)).NotTo(Succeed())

	recorder, ok := r.recorder.(*events.FakeRecorder)
	g.Expect(ok).To(BeTrue())
	close(recorder.Events)
	emitted := make([]string, 0, len(recorder.Events))
	for event := range recorder.Events {
		emitted = append(emitted, event)
	}
	g.Expect(emitted).NotTo(BeEmpty())
	g.Expect(emitted[len(emitted)-1]).To(ContainSubstring(authorizationv1alpha1.EventReasonDeprovisioned))
	g.Expect(emitted[len(emitted)-1]).NotTo(ContainSubstring("policy violations"))
}

func TestRRD_Deprovision_UnownedClusterRoleIsPreserved(t *testing.T) {
	g := NewWithT(t)

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system-cluster-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		}},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd", UID: "deprov-rrd-uid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "system-cluster-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(cr, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	var kept rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "system-cluster-role"}, &kept)).To(Succeed())
	g.Expect(kept.Rules).To(HaveLen(1))
}

func TestRRD_Deprovision_UsesProvidedDeleteClient(t *testing.T) {
	g := NewWithT(t)

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "delete-client-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       authorizationv1alpha1.RestrictedRoleDefinitionKind,
				Name:       "delete-client-rrd",
				UID:        "delete-client-rrd-uid",
			}},
		},
	}
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-client-rrd", UID: "delete-client-rrd-uid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "delete-client-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	testScheme := newTestScheme()
	deleteCalled := false
	deleteClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				deleteCalled = true
				return fmt.Errorf("impersonated delete denied")
			},
		}).
		Build()
	r, _ := newRRDTestReconcilerFake(cr, rrd)

	err := r.rrdDeprovision(rrdCtx(), rrd, deleteClient)
	g.Expect(err).To(MatchError(ContainSubstring("impersonated delete denied")))
	g.Expect(deleteCalled).To(BeTrue())
}

func TestRRD_Deprovision_AlreadyDeleted(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd-gone"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "nonexistent-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, _ := newRRDTestReconcilerFake(rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).NotTo(HaveOccurred()) // Should succeed even if role doesn't exist.
}

func TestRRD_Deprovision_NamespacedRole(t *testing.T) {
	g := NewWithT(t)

	controller := true
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deprov-ns-role",
			Namespace: "my-ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       authorizationv1alpha1.RestrictedRoleDefinitionKind,
				Name:       "deprov-rrd-ns",
				UID:        "deprov-rrd-ns-uid",
				Controller: &controller,
			}},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd-ns", UID: "deprov-rrd-ns-uid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName:      "deprov-ns-role",
			TargetNamespace: "my-ns",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
		},
	}

	r, c := newRRDTestReconcilerFake(role, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	var deleted rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{
		Name: "deprov-ns-role", Namespace: "my-ns",
	}, &deleted)).NotTo(Succeed())
}

func TestRRD_Deprovision_UnownedNamespacedRoleIsPreserved(t *testing.T) {
	g := NewWithT(t)

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "system-role", Namespace: "my-ns"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		}},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd-ns", UID: "deprov-rrd-ns-uid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName:      "system-role",
			TargetNamespace: "my-ns",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
		},
	}

	r, c := newRRDTestReconcilerFake(role, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	var kept rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{
		Name: "system-role", Namespace: "my-ns",
	}, &kept)).To(Succeed())
	g.Expect(kept.Rules).To(HaveLen(1))
}

func TestRRD_Deprovision_InvalidTargetRole(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd-invalid"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "some-role",
			TargetRole: "InvalidRole",
		},
	}

	r, _ := newRRDTestReconcilerFake(rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd, nil)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("invalid target role type"))
}

func TestRRD_MarkStalled(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "stall-rrd", Generation: 3},
	}

	r, c := newRRDTestReconcilerFake(rrd)
	r.rrdMarkStalled(rrdCtx(), rrd, fmt.Errorf("test err"))

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "stall-rrd"}, &updated)).To(Succeed())
	g.Expect(conditions.IsStalled(&updated)).To(BeTrue())
	g.Expect(updated.Status.ObservedGeneration).To(Equal(int64(3)))
}

func TestRRD_OwnerRefForRestricted(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-rrd", UID: "uid-456"},
	}

	ref := ownerRefForRestricted(rrd, authorizationv1alpha1.RestrictedRoleDefinitionKind)
	g.Expect(ref).NotTo(BeNil())
	g.Expect(*ref.Name).To(Equal("owner-rrd"))
	g.Expect(*ref.UID).To(Equal(types.UID("uid-456")))
	g.Expect(*ref.Controller).To(BeTrue())
	g.Expect(*ref.BlockOwnerDeletion).To(BeFalse())
}

func TestRRD_DiscoverAndFilter_TrackerNotStarted(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tracker-ns-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "tracker-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	s := newTestScheme()
	tracker := discovery.NewResourceTracker(s, nil)
	// Tracker not started — GetAPIResources will return ErrResourceTrackerNotStarted.
	r := &RestrictedRoleDefinitionReconciler{
		client:          fake.NewClientBuilder().WithScheme(s).Build(),
		scheme:          s,
		recorder:        events.NewFakeRecorder(10),
		resourceTracker: tracker,
	}

	rules, requeue, err := r.rrdDiscoverAndFilter(rrdCtx(), rrd)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(requeue).To(BeTrue())
	g.Expect(rules).To(BeNil())
}

func TestRRD_Reconcile_TrackerNotStarted_Requeues(t *testing.T) {
	g := NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "tracker-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tracker-rrd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "tracker-pol"},
			TargetName: "tracker-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(pol, rrd).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	tracker := discovery.NewResourceTracker(s, nil)
	r := &RestrictedRoleDefinitionReconciler{
		client:          c,
		scheme:          s,
		recorder:        events.NewFakeRecorder(10),
		resourceTracker: tracker,
	}

	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tracker-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).NotTo(BeZero())
}

func TestRRD_EnsureRole_InvalidTargetRole(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-role-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "some-role",
			TargetRole: "InvalidRole",
		},
	}

	r, _ := newRRDTestReconcilerFake(rrd)
	err := r.rrdEnsureRole(rrdCtx(), rrd, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, r.client)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("unknown targetRole"))
}

func TestRRD_EnsureRole_ClusterRole(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ensure-cr-rrd", UID: "uid-ensure"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "ensured-cluster-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(rrd)
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
	}
	err := r.rrdEnsureRole(rrdCtx(), rrd, rules, c)
	g.Expect(err).NotTo(HaveOccurred())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "ensured-cluster-role"}, &cr)).To(Succeed())
	g.Expect(cr.Rules).To(HaveLen(1))
	g.Expect(cr.Rules[0].Resources).To(ContainElement("pods"))
}

func TestRRD_EnsureRole_DoesNotPropagateSourceLabels(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ensure-cr-label-rrd",
			UID:  "uid-ensure-label",
			Labels: map[string]string{
				rbacv1.GroupName + "/aggregate-to-admin": "true",
				"custom.example.com/tenant":              "team-a",
			},
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "ensured-cluster-role-labels",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(rrd)
	err := r.rrdEnsureRole(rrdCtx(), rrd, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, c)
	g.Expect(err).NotTo(HaveOccurred())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "ensured-cluster-role-labels"}, &cr)).To(Succeed())
	g.Expect(cr.Labels).NotTo(HaveKey(rbacv1.GroupName + "/aggregate-to-admin"))
	g.Expect(cr.Labels).NotTo(HaveKey("custom.example.com/tenant"))
	g.Expect(cr.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "auth-operator"))
}

func TestRRD_EnsureRole_NormalizesOwnedClusterRoleMetadata(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-agg-rrd", UID: "uid-stale-agg"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "stale-agg-cluster-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stale-agg-cluster-role",
			Labels: map[string]string{
				rbacv1.GroupName + "/aggregate-to-admin": "true",
				"custom.example.com/keep":                "true",
				"app.kubernetes.io/managed-by":           "auth-operator",
			},
			OwnerReferences: []metav1.OwnerReference{
				restrictedTestOwnerRef(authorizationv1alpha1.RestrictedRoleDefinitionKind, rrd.Name, rrd.UID),
			},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{{
				MatchLabels: map[string]string{"custom.example.com/keep": "true"},
			}},
		},
	}

	r, c := newRRDTestReconcilerFake(rrd, existing)
	err := r.rrdEnsureRole(rrdCtx(), rrd, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	}, c)
	g.Expect(err).NotTo(HaveOccurred())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "stale-agg-cluster-role"}, &cr)).To(Succeed())
	g.Expect(cr.Labels).NotTo(HaveKey(rbacv1.GroupName + "/aggregate-to-admin"))
	g.Expect(cr.Labels).NotTo(HaveKey("custom.example.com/keep"))
	g.Expect(cr.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "auth-operator"))
	g.Expect(cr.AggregationRule).To(BeNil())
}

func TestRRD_EnsureRole_ClusterRoleClearsStaleRulesWhenDesiredRulesEmpty(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-cr-rrd", UID: "uid-clear-cr"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "clear-cluster-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clear-cluster-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       authorizationv1alpha1.RestrictedRoleDefinitionKind,
				Name:       rrd.Name,
				UID:        rrd.UID,
			}},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	r, c := newRRDTestReconcilerFake(rrd, existing)
	err := r.rrdEnsureRole(rrdCtx(), rrd, nil, c)
	g.Expect(err).NotTo(HaveOccurred())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "clear-cluster-role"}, &cr)).To(Succeed())
	g.Expect(cr.Rules).To(BeEmpty())
}

func TestRRD_EnsureRole_NamespacedRole(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "ensure-r-rrd", UID: "uid-ensure-r"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName:      "ensured-ns-role",
			TargetNamespace: "test-ns",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rrd, ns).
		WithStatusSubresource(&authorizationv1alpha1.RestrictedRoleDefinition{}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		reader:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get"}},
	}
	err := r.rrdEnsureRole(rrdCtx(), rrd, rules, c)
	g.Expect(err).NotTo(HaveOccurred())

	var role rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{
		Name: "ensured-ns-role", Namespace: "test-ns",
	}, &role)).To(Succeed())
	g.Expect(role.Rules).To(HaveLen(1))
	g.Expect(role.Rules[0].Resources).To(ContainElement("services"))
}

func TestRRD_EnsureRole_NamespacedRoleClearsStaleRulesWhenDesiredRulesEmpty(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-role-rrd", UID: "uid-clear-role"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName:      "clear-role",
			TargetNamespace: "clear-ns",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "clear-ns"}}
	existing := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "clear-role",
			Namespace: "clear-ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       authorizationv1alpha1.RestrictedRoleDefinitionKind,
				Name:       rrd.Name,
				UID:        rrd.UID,
			}},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	r, c := newRRDTestReconcilerFake(rrd, ns, existing)
	err := r.rrdEnsureRole(rrdCtx(), rrd, nil, c)
	g.Expect(err).NotTo(HaveOccurred())

	var role rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "clear-role", Namespace: "clear-ns"}, &role)).To(Succeed())
	g.Expect(role.Rules).To(BeEmpty())
}

func TestRRD_ClearRulesIfEmptySkipsUnownedRoles(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-unowned-rrd", UID: "uid-clear-unowned"},
	}
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-unowned-cluster-role"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-unowned-role", Namespace: "default"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	r, c := newRRDTestReconcilerFake(rrd, cr, role)
	g.Expect(r.rrdClearClusterRoleRulesIfEmpty(rrdCtx(), c, rrd, cr.Name, nil)).To(Succeed())
	g.Expect(r.rrdClearRoleRulesIfEmpty(rrdCtx(), c, rrd, role.Namespace, role.Name, nil)).To(Succeed())

	var gotCR rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: cr.Name}, &gotCR)).To(Succeed())
	g.Expect(gotCR.Rules).To(HaveLen(1))

	var gotRole rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Namespace: role.Namespace, Name: role.Name}, &gotRole)).To(Succeed())
	g.Expect(gotRole.Rules).To(HaveLen(1))
}

func TestRRD_Reconcile_WithTracer(t *testing.T) {
	g := NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "tracer-rrd-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
			RoleLimits: &authorizationv1alpha1.RoleLimits{
				AllowClusterRoles: true,
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tracer-rrd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "tracer-rrd-pol"},
			TargetName: "tracer-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(pol, rrd).
		WithStatusSubresource(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			&authorizationv1alpha1.RBACPolicy{},
		).
		Build()
	tracer := noop.NewTracerProvider().Tracer("test")
	tracker := discovery.NewResourceTracker(s, nil)
	r := &RestrictedRoleDefinitionReconciler{
		client:          c,
		scheme:          s,
		recorder:        events.NewFakeRecorder(10),
		resourceTracker: tracker,
		tracer:          tracer,
	}

	// Tracker not started, but with tracer set — covers tracing code path.
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tracer-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).NotTo(BeZero())
}

func TestRRD_Reconcile_WithTracer_Error(t *testing.T) {
	g := NewWithT(t)

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("injected get error")
			},
		}).
		Build()
	tracer := noop.NewTracerProvider().Tracer("test")
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
		tracer:   tracer,
	}

	_, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any-rrd"},
	})
	g.Expect(err).To(HaveOccurred())
}

func TestRRD_PolicyToRestrictedRoleDefinitions(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "mapped-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "rrd-policy"},
		},
	}

	s := newTestScheme()
	idx := func(obj client.Object) []string {
		r := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
		return []string{r.Spec.PolicyRef.Name}
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rrd).
		WithIndex(&authorizationv1alpha1.RestrictedRoleDefinition{}, ".spec.policyRef.name", idx).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	policy := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "rrd-policy"},
	}
	requests := r.policyToRestrictedRoleDefinitions(rrdCtx(), policy)
	g.Expect(requests).To(HaveLen(1))
	g.Expect(requests[0].Name).To(Equal("mapped-rrd"))
}

func TestRRD_PolicyToRestrictedRoleDefinitions_ListError(t *testing.T) {
	g := NewWithT(t)

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	policy := &authorizationv1alpha1.RBACPolicy{ObjectMeta: metav1.ObjectMeta{Name: "any"}}
	requests := r.policyToRestrictedRoleDefinitions(rrdCtx(), policy)
	g.Expect(requests).To(BeNil())
}

func TestRRD_NamespaceToRestrictedRoleDefinitions(t *testing.T) {
	g := NewWithT(t)

	matching := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "matching-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "matching-role",
			TargetNamespace: "team-a",
		},
	}
	otherNamespace := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "other-ns-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "other-role",
			TargetNamespace: "team-b",
		},
	}
	clusterRole := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "cluster-role",
		},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(matching, otherNamespace, clusterRole).
		WithIndex(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			indexer.RestrictedRoleDefinitionTargetNamespaceField,
			indexer.RestrictedRoleDefinitionTargetNamespaceFunc,
		).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	requests := r.namespaceToRestrictedRoleDefinitions(rrdCtx(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}})
	g.Expect(requests).To(Equal([]reconcile.Request{{NamespacedName: types.NamespacedName{Name: "matching-rrd"}}}))
}

func TestRRD_NamespaceToRestrictedRoleDefinitions_FallbackWithoutIndex(t *testing.T) {
	g := NewWithT(t)

	matching := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "fallback-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "fallback-role",
			TargetNamespace: "team-a",
		},
	}
	clusterRole := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "fallback-cluster-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "fallback-cluster-role",
		},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(matching, clusterRole).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	requests := r.namespaceToRestrictedRoleDefinitions(rrdCtx(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}})
	g.Expect(requests).To(Equal([]reconcile.Request{{NamespacedName: types.NamespacedName{Name: "fallback-rrd"}}}))
}

func TestRRD_FilterResource_ScopeNamespacedTrueExcludesClusterScoped(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			ScopeNamespaced: true,
		},
	}
	rulesByKey := make(map[string]*rbacv1.PolicyRule)

	rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"},
		metav1.APIResource{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"get"}},
		nil,
		rulesByKey)
	rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"},
		metav1.APIResource{Name: "nodes", Namespaced: false, Verbs: metav1.Verbs{"get"}},
		nil,
		rulesByKey)

	resources := make([]string, 0, len(rulesByKey))
	for _, rule := range rulesByKey {
		resources = append(resources, rule.Resources...)
	}
	g.Expect(resources).To(ContainElement("pods"))
	g.Expect(resources).NotTo(ContainElement("nodes"))
}

func TestRRD_FilterResource_RestrictedParentResourceExcludesSubresources(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			ScopeNamespaced: true,
			RestrictedResources: []metav1.APIResource{
				{Name: "pods"},
				{Name: "deployments/scale", Group: "apps"},
			},
		},
	}
	rulesByKey := make(map[string]*rbacv1.PolicyRule)

	for _, res := range []metav1.APIResource{
		{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"get"}},
		{Name: "pods/log", Namespaced: true, Verbs: metav1.Verbs{"get"}},
		{Name: "pods/exec", Namespaced: true, Verbs: metav1.Verbs{"create"}},
		{Name: "services", Namespaced: true, Verbs: metav1.Verbs{"get"}},
	} {
		rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"}, res, nil, rulesByKey)
	}
	rrdFilterResource(rrd, schema.GroupVersion{Group: "apps", Version: "v1"},
		metav1.APIResource{Name: "deployments", Namespaced: true, Verbs: metav1.Verbs{"get"}}, nil, rulesByKey)
	rrdFilterResource(rrd, schema.GroupVersion{Group: "apps", Version: "v1"},
		metav1.APIResource{Name: "deployments/scale", Namespaced: true, Verbs: metav1.Verbs{"update"}}, nil, rulesByKey)

	resources := make([]string, 0, len(rulesByKey))
	for _, rule := range rulesByKey {
		resources = append(resources, rule.Resources...)
	}
	g.Expect(resources).To(ConsistOf("services", "deployments"))
}

func TestRRD_FilterResource_RestrictedWildcardResourceExcludesAllResources(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			ScopeNamespaced: true,
			RestrictedResources: []metav1.APIResource{
				{Name: "*"},
			},
		},
	}
	rulesByKey := make(map[string]*rbacv1.PolicyRule)

	for _, res := range []metav1.APIResource{
		{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"get"}},
		{Name: "pods/log", Namespaced: true, Verbs: metav1.Verbs{"get"}},
		{Name: "services", Namespaced: true, Verbs: metav1.Verbs{"get"}},
	} {
		rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"}, res, nil, rulesByKey)
	}
	rrdFilterResource(rrd, schema.GroupVersion{Group: "apps", Version: "v1"},
		metav1.APIResource{Name: "deployments", Namespaced: true, Verbs: metav1.Verbs{"get"}}, nil, rulesByKey)

	g.Expect(rulesByKey).To(BeEmpty())
}

func TestRRD_CheckAPIRestriction_WildcardGroupMatchesEveryAPIGroup(t *testing.T) {
	g := NewWithT(t)

	for _, gv := range []schema.GroupVersion{
		{Version: "v1"},
		{Group: "apps", Version: "v1"},
		{Group: "authorization.k8s.io", Version: "v1"},
	} {
		restricted, verbs := rrdCheckAPIRestriction(
			[]authorizationv1alpha1.RestrictedAPIGroup{{Name: "*"}},
			gv,
		)
		g.Expect(restricted).To(BeTrue(), "groupVersion=%s", gv.String())
		g.Expect(verbs).To(BeEmpty(), "groupVersion=%s", gv.String())
	}
}

func TestRRD_CheckAPIRestriction_UnionsOverlappingMatches(t *testing.T) {
	g := NewWithT(t)

	restricted, verbs := rrdCheckAPIRestriction(
		[]authorizationv1alpha1.RestrictedAPIGroup{
			{Name: "*", Verbs: []string{"get"}},
			{Name: "apps"},
		},
		schema.GroupVersion{Group: "apps", Version: "v1"},
	)
	g.Expect(restricted).To(BeTrue())
	g.Expect(verbs).To(BeEmpty(), "specific full block must override earlier wildcard verb-only restriction")

	restricted, verbs = rrdCheckAPIRestriction(
		[]authorizationv1alpha1.RestrictedAPIGroup{
			{Name: "*", Verbs: []string{"get"}},
			{Name: "apps", Verbs: []string{"delete", "update"}},
		},
		schema.GroupVersion{Group: "apps", Version: "v1"},
	)
	g.Expect(restricted).To(BeTrue())
	g.Expect(verbs).To(Equal([]string{"delete", "get", "update"}))
}

func TestRRD_FilterResource_NormalizesVerbOrderForRuleGrouping(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			ScopeNamespaced: true,
		},
	}
	rulesByKey := make(map[string]*rbacv1.PolicyRule)

	rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"},
		metav1.APIResource{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"list", "get"}},
		nil,
		rulesByKey)
	rrdFilterResource(rrd, schema.GroupVersion{Version: "v1"},
		metav1.APIResource{Name: "services", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
		nil,
		rulesByKey)

	g.Expect(rulesByKey).To(HaveLen(1))
	for _, rule := range rulesByKey {
		g.Expect(rule.Verbs).To(Equal([]string{"get", "list"}))
		g.Expect(rule.Resources).To(ConsistOf("pods", "services"))
	}
}

func TestRRD_QueueAll(t *testing.T) {
	g := NewWithT(t)

	rrd1 := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "queue-rrd-1"},
	}
	rrd2 := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "queue-rrd-2"},
	}

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rrd1, rrd2).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	// queueAll returns a MapFunc that lists all RRDs.
	mapFn := r.queueAll()
	requests := mapFn(rrdCtx(), &corev1.ConfigMap{})
	g.Expect(requests).To(HaveLen(2))
}

func TestRRD_QueueAll_ListError(t *testing.T) {
	g := NewWithT(t)

	s := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	mapFn := r.queueAll()
	requests := mapFn(rrdCtx(), &corev1.ConfigMap{})
	g.Expect(requests).To(BeNil())
}

func TestRRD_Reconcile_PolicyGetError(t *testing.T) {
	g := NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "pol-err-rrd", Generation: 1},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "error-policy"},
			TargetName: "err-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	s := newTestScheme()
	callCount := 0
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(rrd).
		WithStatusSubresource(&authorizationv1alpha1.RestrictedRoleDefinition{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				callCount++
				// First call fetches RRD → succeed; second fetches policy → fail.
				if callCount == 1 {
					return cl.Get(ctx, key, obj, opts...)
				}
				return fmt.Errorf("injected policy get error")
			},
		}).
		Build()
	r := &RestrictedRoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "pol-err-rrd"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("fetch RBACPolicy"))
}

// --- Ginkgo envtest tests (require real API server for SSA) ---

var _ = Describe("RestrictedRoleDefinition Controller", func() {
	Context("When reconciling with envtest", func() {
		var rrd *authorizationv1alpha1.RestrictedRoleDefinition
		var reconciler *RestrictedRoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker
		ctx := context.Background()

		BeforeEach(func() {
			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				_ = resourceTracker.Start(ctx)
			}()
		})

		AfterEach(func() {
			if rrd != nil {
				_ = k8sClient.Delete(ctx, rrd)
				// Clean up ClusterRole if created.
				cr := &rbacv1.ClusterRole{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: rrd.Spec.TargetName}, cr); err == nil {
					_ = k8sClient.Delete(ctx, cr)
				}
			}
		})

		It("should reconcile a compliant RestrictedRoleDefinition with ClusterRole", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue())

			By("creating RBACPolicy")
			pol := &authorizationv1alpha1.RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("envtest-policy-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RBACPolicySpec{
					AppliesTo: authorizationv1alpha1.PolicyScope{
						Namespaces: []string{"*"},
					},
					RoleLimits: &authorizationv1alpha1.RoleLimits{
						AllowClusterRoles: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, pol) }()

			By("creating RestrictedRoleDefinition")
			rrd = &authorizationv1alpha1.RestrictedRoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedRoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("envtest-rrd-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
					TargetName:      "envtest-role",
					TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"delete", "deletecollection"},
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			// Re-set TypeMeta.
			rrd.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RestrictedRoleDefinition",
			}

			var err error
			reconciler, err = NewRestrictedRoleDefinitionReconciler(
				k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())

			By("reconciling")
			logCtx := ctrllog.IntoContext(ctx, logger)
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rrd.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying ClusterRole was created")
			cr := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "envtest-role"}, cr)).To(Succeed())
			Expect(cr.Rules).ToNot(BeEmpty())

			By("verifying status")
			var updated authorizationv1alpha1.RestrictedRoleDefinition
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: rrd.Name}, &updated)).To(Succeed())
			Expect(updated.Status.RoleReconciled).To(BeTrue())
			Expect(conditions.IsReady(&updated)).To(BeTrue())
		})

		It("should stall and preserve an unowned target ClusterRole", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue())

			suffix := time.Now().UnixNano()
			pol := &authorizationv1alpha1.RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("envtest-ownership-policy-%d", suffix),
				},
				Spec: authorizationv1alpha1.RBACPolicySpec{
					AppliesTo: authorizationv1alpha1.PolicyScope{
						Namespaces: []string{"*"},
					},
					RoleLimits: &authorizationv1alpha1.RoleLimits{
						AllowClusterRoles: true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, pol) }()

			targetName := fmt.Sprintf("envtest-unowned-role-%d", suffix)
			existing := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: targetName},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
				},
			}
			Expect(k8sClient.Create(ctx, existing)).To(Succeed())

			rrd = &authorizationv1alpha1.RestrictedRoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedRoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("envtest-ownership-rrd-%d", suffix),
				},
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					PolicyRef:       authorizationv1alpha1.RBACPolicyReference{Name: pol.Name},
					TargetName:      targetName,
					TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"delete", "deletecollection"},
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			rrd.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RestrictedRoleDefinition",
			}

			var err error
			reconciler, err = NewRestrictedRoleDefinitionReconciler(
				k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())

			By("reconciling")
			logCtx := ctrllog.IntoContext(ctx, logger)
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rrd.Name},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("already exists and is not owned"))

			By("verifying the existing ClusterRole was preserved")
			var kept rbacv1.ClusterRole
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: targetName}, &kept)).To(Succeed())
			Expect(kept.OwnerReferences).To(BeEmpty())
			Expect(kept.Rules).To(ConsistOf(existing.Rules))

			By("verifying stalled status")
			var updated authorizationv1alpha1.RestrictedRoleDefinition
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: rrd.Name}, &updated)).To(Succeed())
			Expect(updated.Status.RoleReconciled).To(BeFalse())
			Expect(conditions.IsStalled(&updated)).To(BeTrue())
		})
	})
})
