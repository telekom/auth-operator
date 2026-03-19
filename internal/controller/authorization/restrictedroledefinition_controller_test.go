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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "missing-policy"},
			TargetName: "test-role-name",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(rrd)
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
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "no-cr-policy"},
			TargetName: "violating-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(pol, rrd)
	result, err := r.Reconcile(rrdCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "violating-rrd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	var updated authorizationv1alpha1.RestrictedRoleDefinition
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "violating-rrd"}, &updated)).To(Succeed())
	g.Expect(updated.Status.PolicyViolations).NotTo(BeEmpty())
	g.Expect(updated.Status.RoleReconciled).To(BeFalse())
	g.Expect(conditions.IsReady(&updated)).To(BeFalse())
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

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-test-role"},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "deprov-test-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRRDTestReconcilerFake(cr, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd)
	g.Expect(err).NotTo(HaveOccurred())

	// ClusterRole should be deleted.
	var deleted rbacv1.ClusterRole
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{Name: "deprov-test-role"}, &deleted)).NotTo(Succeed())
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
	err := r.rrdDeprovision(rrdCtx(), rrd)
	g.Expect(err).NotTo(HaveOccurred()) // Should succeed even if role doesn't exist.
}

func TestRRD_Deprovision_NamespacedRole(t *testing.T) {
	g := NewWithT(t)

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-ns-role", Namespace: "my-ns"},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "deprov-rrd-ns"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName:      "deprov-ns-role",
			TargetNamespace: "my-ns",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
		},
	}

	r, c := newRRDTestReconcilerFake(role, rrd)
	err := r.rrdDeprovision(rrdCtx(), rrd)
	g.Expect(err).NotTo(HaveOccurred())

	var deleted rbacv1.Role
	g.Expect(c.Get(rrdCtx(), types.NamespacedName{
		Name: "deprov-ns-role", Namespace: "my-ns",
	}, &deleted)).NotTo(Succeed())
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
	err := r.rrdDeprovision(rrdCtx(), rrd)
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

	ref := ownerRefForRestricted(rrd, "RestrictedRoleDefinition")
	g.Expect(ref).NotTo(BeNil())
	g.Expect(*ref.Name).To(Equal("owner-rrd"))
	g.Expect(*ref.UID).To(Equal(types.UID("uid-456")))
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
	g.Expect(err.Error()).To(ContainSubstring("invalid target role type"))
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
						Namespaces: []string{"default"},
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
	})
})
