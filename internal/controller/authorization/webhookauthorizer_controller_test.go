// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"

	"github.com/onsi/gomega"
)

func newWATestReconciler(objs ...client.Object) (*WebhookAuthorizerReconciler, client.Client) {
	scheme := newTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&authorizationv1alpha1.WebhookAuthorizer{}).
		Build()
	recorder := events.NewFakeRecorder(10)
	return NewWebhookAuthorizerReconciler(c, scheme, recorder), c
}

func reconcileRequest(name string) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name},
	}
}

func ctxWithLogger() context.Context {
	return ctrllog.IntoContext(context.Background(), logr.Discard())
}

func TestReconcile_NotFound(t *testing.T) {
	g := gomega.NewWithT(t)
	r, _ := newWATestReconciler()

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("nonexistent"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))
}

func TestReconcile_EmptySelector_Ready(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-authorizer",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{},
	}

	r, c := newWATestReconciler(wa)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("test-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	// Verify status was updated
	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "test-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(1)))
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeFalse())
	g.Expect(conditions.IsReconciling(&updated)).To(gomega.BeFalse())
}

func TestReconcile_WithMatchLabels_Ready(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"env": "dev"},
		},
	}
	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "label-authorizer",
			Generation: 2,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "dev"},
			},
		},
	}

	r, c := newWATestReconciler(wa, ns)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("label-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "label-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(2)))
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestReconcile_WithMatchExpressions_Ready(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod-ns",
			Labels: map[string]string{"tier": "frontend"},
		},
	}
	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "expr-authorizer",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"frontend", "backend"},
					},
				},
			},
		},
	}

	r, c := newWATestReconciler(wa, ns)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("expr-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "expr-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestReconcile_InvalidMatchExpression_Stalled(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "bad-authorizer",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOperator("InvalidOp"),
						Values:   []string{"frontend"},
					},
				},
			},
		},
	}

	r, c := newWATestReconciler(wa)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("bad-authorizer"))
	// Permanent validation errors do not requeue — GenerationChangedPredicate
	// ensures we re-reconcile only when the user fixes the spec.
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	// Verify stalled status
	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "bad-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(1)))
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeFalse())
	g.Expect(conditions.IsStalled(&updated)).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeFalse())
}

func TestReconcile_GenerationUpdate(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gen-authorizer",
			Generation: 5,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{},
	}

	r, c := newWATestReconciler(wa)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("gen-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "gen-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.ObservedGeneration).To(gomega.Equal(int64(5)))
}

func TestReconcile_WithPrincipals_Ready(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "principals-authorizer",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authorizationv1alpha1.Principal{
				{User: "admin", Groups: []string{"system:masters"}},
			},
			DeniedPrincipals: []authorizationv1alpha1.Principal{
				{User: "readonly"},
			},
		},
	}

	r, c := newWATestReconciler(wa)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("principals-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "principals-authorizer"}, &updated)).To(gomega.Succeed())
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestReconcile_NoMatchingNamespaces_StillReady(t *testing.T) {
	g := gomega.NewWithT(t)

	// No namespace with env=staging exists
	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "no-match-authorizer",
			Generation: 1,
		},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "staging"},
			},
		},
	}

	r, c := newWATestReconciler(wa)

	result, err := r.Reconcile(ctxWithLogger(), reconcileRequest("no-match-authorizer"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).To(gomega.Equal(ctrl.Result{}))

	var updated authorizationv1alpha1.WebhookAuthorizer
	g.Expect(c.Get(ctxWithLogger(), types.NamespacedName{Name: "no-match-authorizer"}, &updated)).To(gomega.Succeed())
	// Even with no matching namespaces, the authorizer is valid and configured
	g.Expect(updated.Status.AuthorizerConfigured).To(gomega.BeTrue())
	g.Expect(conditions.IsReady(&updated)).To(gomega.BeTrue())
}

func TestNewWebhookAuthorizerReconciler(t *testing.T) {
	g := gomega.NewWithT(t)
	scheme := newTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := events.NewFakeRecorder(10)

	r := NewWebhookAuthorizerReconciler(c, scheme, recorder)
	g.Expect(r).NotTo(gomega.BeNil())
	g.Expect(r.client).To(gomega.Equal(c))
	g.Expect(r.scheme).To(gomega.Equal(scheme))
	g.Expect(r.recorder).To(gomega.Equal(recorder))
}

func TestValidateNamespaceSelector_EmptySelector(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{},
		},
	}

	r, _ := newWATestReconciler(wa)
	err := r.validateNamespaceSelector(ctxWithLogger(), wa)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestValidateNamespaceSelector_ValidMatchLabels(t *testing.T) {
	g := gomega.NewWithT(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "match-ns",
			Labels: map[string]string{"app": "web"},
		},
	}
	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}

	r, _ := newWATestReconciler(wa, ns)
	err := r.validateNamespaceSelector(ctxWithLogger(), wa)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestValidateNamespaceSelector_InvalidExpression(t *testing.T) {
	g := gomega.NewWithT(t)

	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "key",
						Operator: metav1.LabelSelectorOperator("BadOperator"),
						Values:   []string{"value"},
					},
				},
			},
		},
	}

	r, _ := newWATestReconciler(wa)
	err := r.validateNamespaceSelector(ctxWithLogger(), wa)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("invalid NamespaceSelector"))
}

func TestConvertLabelSelector(t *testing.T) {
	g := gomega.NewWithT(t)

	ls := &metav1.LabelSelector{
		MatchLabels: map[string]string{"env": "prod"},
	}
	selector, err := convertLabelSelector(ls)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(selector).NotTo(gomega.BeNil())
	g.Expect(selector.String()).To(gomega.Equal("env=prod"))
}
