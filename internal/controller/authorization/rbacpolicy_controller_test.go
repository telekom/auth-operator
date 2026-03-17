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
	"go.opentelemetry.io/otel/trace/noop"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
)

func newRBACPolicyTestReconciler(objs ...client.Object) (*RBACPolicyReconciler, client.Client) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(
			&authorizationv1alpha1.RBACPolicy{},
		).
		WithIndex(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			".spec.policyRef.name",
			func(obj client.Object) []string {
				rbd := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
				if rbd.Spec.PolicyRef.Name == "" {
					return nil
				}
				return []string{rbd.Spec.PolicyRef.Name}
			},
		).
		WithIndex(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			".spec.policyRef.name",
			func(obj client.Object) []string {
				rrd := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
				if rrd.Spec.PolicyRef.Name == "" {
					return nil
				}
				return []string{rrd.Spec.PolicyRef.Name}
			},
		).
		Build()
	recorder := events.NewFakeRecorder(10)
	return NewRBACPolicyReconciler(c, scheme, recorder), c
}

func rbacPolicyRequest(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
}

func rbacPolicyCtx() context.Context {
	return ctrllog.IntoContext(context.Background(), logr.Discard())
}

func TestRBACPolicy_Reconcile_NotFound(t *testing.T) {
	g := gomega.NewWithT(t)
	r, _ := newRBACPolicyTestReconciler()

	result, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("nonexistent"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))
}

func TestRBACPolicy_Reconcile_NoBoundResources(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
		},
	}

	r, c := newRBACPolicyTestReconciler(pol)
	result, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("test-policy"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.RBACPolicy
	g.Expect(c.Get(rbacPolicyCtx(), types.NamespacedName{Name: "test-policy"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(1)))
	g.Expect(updated.Status.BoundResourceCount).To(gomega.Equal(int32(0)))
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestRBACPolicy_Reconcile_WithBoundResources(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "team-policy",
			Generation: 2,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"team-a"},
			},
		},
	}

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-bind"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "team-policy"},
			TargetName: "team-a",
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-role"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "team-policy"},
			TargetName: "team-a-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	r, c := newRBACPolicyTestReconciler(pol, rbd, rrd)
	result, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("team-policy"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.RBACPolicy
	g.Expect(c.Get(rbacPolicyCtx(), types.NamespacedName{Name: "team-policy"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(2)))
	g.Expect(updated.Status.BoundResourceCount).To(gomega.Equal(int32(2)))
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestRBACPolicy_Reconcile_ObservesGeneration(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gen-policy",
			Generation: 7,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"ns1"},
			},
		},
	}

	r, c := newRBACPolicyTestReconciler(pol)
	_, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("gen-policy"))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	var updated authorizationv1alpha1.RBACPolicy
	g.Expect(c.Get(rbacPolicyCtx(), types.NamespacedName{Name: "gen-policy"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(7)))
}

func TestRBACPolicy_Reconcile_GetError(t *testing.T) {
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
	r := NewRBACPolicyReconciler(errClient, scheme, recorder)

	_, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("any-policy"))
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("API unavailable"))
}

func TestRBACPolicy_Reconcile_ListError(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "list-error-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pol).
		WithStatusSubresource(&authorizationv1alpha1.RBACPolicy{}).
		WithIndex(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			".spec.policyRef.name",
			func(obj client.Object) []string {
				rbd := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
				return []string{rbd.Spec.PolicyRef.Name}
			},
		).
		WithIndex(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			".spec.policyRef.name",
			func(obj client.Object) []string {
				rrd := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
				return []string{rrd.Spec.PolicyRef.Name}
			},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*authorizationv1alpha1.RestrictedBindDefinitionList); ok {
					return fmt.Errorf("list failed")
				}
				return nil
			},
		}).
		Build()

	recorder := events.NewFakeRecorder(10)
	r := NewRBACPolicyReconciler(c, scheme, recorder)

	_, err := r.Reconcile(rbacPolicyCtx(), rbacPolicyRequest("list-error-policy"))
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("list RestrictedBindDefinitions"))
}

func TestNewRBACPolicyReconciler(t *testing.T) {
	g := gomega.NewWithT(t)
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := events.NewFakeRecorder(10)

	r := NewRBACPolicyReconciler(c, scheme, recorder)
	g.Expect(r).NotTo(gomega.BeNil())
	g.Expect(r.client).To(gomega.Equal(c))
	g.Expect(r.scheme).To(gomega.Equal(scheme))
	g.Expect(r.recorder).To(gomega.Equal(recorder))
}

func TestNewRBACPolicyReconciler_WithTracer(t *testing.T) {
	g := gomega.NewWithT(t)
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := events.NewFakeRecorder(10)

	r := NewRBACPolicyReconciler(c, scheme, recorder, WithTracer(nil))
	g.Expect(r).NotTo(gomega.BeNil())
}

func TestRBACPolicy_RestrictedResourceToPolicyRequests(t *testing.T) {
	g := gomega.NewWithT(t)
	r, _ := newRBACPolicyTestReconciler()

	// RestrictedBindDefinition
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "my-policy"},
		},
	}
	requests := r.restrictedResourceToPolicyRequests(rbacPolicyCtx(), rbd)
	g.Expect(requests).To(gomega.HaveLen(1))
	g.Expect(requests[0].Name).To(gomega.Equal("my-policy"))

	// RestrictedRoleDefinition
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "other-policy"},
		},
	}
	requests = r.restrictedResourceToPolicyRequests(rbacPolicyCtx(), rrd)
	g.Expect(requests).To(gomega.HaveLen(1))
	g.Expect(requests[0].Name).To(gomega.Equal("other-policy"))

	// Unknown type returns nil.
	requests = r.restrictedResourceToPolicyRequests(rbacPolicyCtx(), &authorizationv1alpha1.RoleDefinition{})
	g.Expect(requests).To(gomega.BeNil())

	// Empty policyRef returns nil.
	rbd2 := &authorizationv1alpha1.RestrictedBindDefinition{}
	requests = r.restrictedResourceToPolicyRequests(rbacPolicyCtx(), rbd2)
	g.Expect(requests).To(gomega.BeNil())
}

func TestRBACPolicy_MarkStalled(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "stalled-policy",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
		},
	}

	r, c := newRBACPolicyTestReconciler(pol)
	r.markStalled(rbacPolicyCtx(), pol, fmt.Errorf("something failed"))

	var updated authorizationv1alpha1.RBACPolicy
	g.Expect(c.Get(rbacPolicyCtx(), types.NamespacedName{Name: "stalled-policy"}, &updated)).To(gomega.Succeed())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeFalse())
}

func TestRBACPolicy_Reconcile_WithTracer(t *testing.T) {
	g := gomega.NewWithT(t)

	pol := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "traced-pol", Generation: 1},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{
				Namespaces: []string{"default"},
			},
		},
	}

	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pol).
		WithStatusSubresource(&authorizationv1alpha1.RBACPolicy{}).
		WithIndex(&authorizationv1alpha1.RestrictedBindDefinition{}, ".spec.policyRef.name",
			func(obj client.Object) []string {
				r := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
				return []string{r.Spec.PolicyRef.Name}
			}).
		WithIndex(&authorizationv1alpha1.RestrictedRoleDefinition{}, ".spec.policyRef.name",
			func(obj client.Object) []string {
				r := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
				return []string{r.Spec.PolicyRef.Name}
			}).
		Build()
	tracer := noop.NewTracerProvider().Tracer("test")
	r := NewRBACPolicyReconciler(c, scheme, events.NewFakeRecorder(10), WithTracer(tracer))

	result, err := r.Reconcile(rbacPolicyCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "traced-pol"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))
}

func TestRBACPolicy_Reconcile_WithTracer_Error(t *testing.T) {
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
	r := NewRBACPolicyReconciler(c, scheme, events.NewFakeRecorder(10), WithTracer(tracer))

	_, err := r.Reconcile(rbacPolicyCtx(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any-pol"},
	})
	g.Expect(err).To(gomega.HaveOccurred())
}
