// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks_test

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/indexer"
)

type namespaceCountingReader struct {
	client.Reader
	reads int
}

func (r *namespaceCountingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Namespace); ok {
		r.reads++
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

var _ = Describe("Webhook discovery characterization", func() {
	var (
		ctx        context.Context
		authorizer *webhooks.Authorizer
		wa         *authorizationv1alpha1.WebhookAuthorizer
		ns         *corev1.Namespace
		sar        authzv1.SubjectAccessReview
	)

	BeforeEach(func() {
		ctx = context.Background()
		ns = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			GenerateName: "discovery-selector-", Labels: map[string]string{"team": "selected"},
		}}
		Expect(envClient.Create(ctx, ns)).To(Succeed())
		wa = &authorizationv1alpha1.WebhookAuthorizer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "discovery-coverage-"},
			Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
				AllowedPrincipals: []authorizationv1alpha1.Principal{{User: ns.Name}},
				ResourceRules: []authzv1.ResourceRule{{
					Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods", "nodes"},
				}},
				NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"team": "selected"}},
			},
		}
		createWAAndSync(ctx, wa)
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(envClient.Delete(ctx, wa))).To(Succeed())
			Expect(client.IgnoreNotFound(envClient.Delete(ctx, ns))).To(Succeed())
		})
		sar = authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: ns.Name, ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns.Name, Verb: "get", Resource: "pods",
			},
		}}
		authorizer = &webhooks.Authorizer{
			Client: envClient, LiveReader: envReader, Log: logr.Discard(), AllowUnauthenticatedAuthorize: true,
		}
		Eventually(func() bool {
			return sendSAR(authorizer, sar).Status.Allowed
		}).WithTimeout(10 * time.Second).Should(BeTrue())
	})

	It("matches expressions, rejects non-matches, missing namespaces and cluster-scoped requests", func() {
		wa.Spec.NamespaceSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"selected"},
		}}}
		Expect(envClient.Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
		for _, name := range []string{"default", ns.Name + "-missing", ""} {
			sar.Spec.ResourceAttributes.Namespace = name
			if name == "" {
				sar.Spec.ResourceAttributes.Resource = "nodes"
			}
			response := sendSAR(authorizer, sar)
			Expect(response.Status.Allowed).To(BeFalse())
			Expect(response.Status.Denied).To(Equal(name == ns.Name+"-missing"))
		}
	})

	DescribeTable("uses live state even when indexed candidates and cached objects are stale",
		func(change string) {
			indexValue := indexer.WebhookAuthorizerHasNamespaceSelectorTrue
			if change == "global-to-scoped" {
				wa.Spec.NamespaceSelector = metav1.LabelSelector{}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
				indexValue = indexer.WebhookAuthorizerHasNamespaceSelectorFalse
				Eventually(func() bool {
					var global authorizationv1alpha1.WebhookAuthorizerList
					Expect(envClient.List(ctx, &global, client.MatchingFields{
						indexer.WebhookAuthorizerHasNamespaceSelectorField: indexValue,
					})).To(Succeed())
					for _, candidate := range global.Items {
						if candidate.Name == wa.Name {
							return true
						}
					}
					return false
				}).WithTimeout(10 * time.Second).Should(BeTrue())
			}
			// Freeze a real indexed-cache snapshot to make revocation independent
			// of informer timing; the selected objects still come from envtest.
			var candidates authorizationv1alpha1.WebhookAuthorizerList
			Expect(envClient.List(ctx, &candidates, client.MatchingFields{
				indexer.WebhookAuthorizerHasNamespaceSelectorField: indexValue,
			})).To(Succeed())
			staleWA, staleNS := wa.DeepCopy(), ns.DeepCopy()
			snapshotClient, err := client.NewWithWatch(envCfg, client.Options{Scheme: envClient.Scheme()})
			Expect(err).NotTo(HaveOccurred())
			authorizer.Client = interceptor.NewClient(snapshotClient, interceptor.Funcs{
				List: func(ctx context.Context, _ client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					authorizers, ok := list.(*authorizationv1alpha1.WebhookAuthorizerList)
					if !ok {
						return envClient.List(ctx, list, opts...)
					}
					options := &client.ListOptions{}
					options.ApplyOptions(opts)
					snapshot := &authorizationv1alpha1.WebhookAuthorizerList{}
					if options.FieldSelector.Matches(fields.Set{
						indexer.WebhookAuthorizerHasNamespaceSelectorField: indexValue,
					}) {
						snapshot = candidates.DeepCopy()
					}
					*authorizers = *snapshot
					return nil
				},
				Get: func(ctx context.Context, _ client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					switch typed := obj.(type) {
					case *authorizationv1alpha1.WebhookAuthorizer:
						*typed = *staleWA.DeepCopy()
					case *corev1.Namespace:
						*typed = *staleNS.DeepCopy()
					default:
						return envClient.Get(ctx, key, obj, opts...)
					}
					return nil
				},
			})
			Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
			switch change {
			case "labels":
				ns.Labels["team"] = "revoked"
				Expect(envClient.Update(ctx, ns)).To(Succeed())
			case "principal":
				wa.Spec.AllowedPrincipals = []authorizationv1alpha1.Principal{{User: ns.Name + "-other"}}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
			case "rules":
				wa.Spec.ResourceRules[0].Verbs = []string{"delete"}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
			case "deny":
				wa.Spec.DeniedPrincipals = []authorizationv1alpha1.Principal{{User: ns.Name}}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
			case "delete":
				Expect(envClient.Delete(ctx, wa)).To(Succeed())
			case "scoped-to-global":
				wa.Spec.NamespaceSelector = metav1.LabelSelector{}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
			case "global-to-scoped":
				wa.Spec.NamespaceSelector = metav1.LabelSelector{MatchLabels: map[string]string{"team": "selected"}}
				Expect(envClient.Update(ctx, wa)).To(Succeed())
			}
			response := sendSAR(authorizer, sar)
			transition := change == "scoped-to-global" || change == "global-to-scoped"
			Expect(response.Status.Allowed).To(Equal(transition))
			Expect(response.Status.Denied).To(Equal(change == "deny"))
			if transition {
				// A new live scope must win over the frozen candidate's old index.
				sar.Spec.ResourceAttributes.Namespace = "default"
				Expect(sendSAR(authorizer, sar).Status.Allowed).To(Equal(change == "scoped-to-global"))
				sar.Spec.ResourceAttributes.Namespace = ""
				sar.Spec.ResourceAttributes.Resource = "nodes"
				Expect(sendSAR(authorizer, sar).Status.Allowed).To(Equal(change == "scoped-to-global"))
			}
		},
		Entry("namespace label revocation", "labels"),
		Entry("principal revocation", "principal"),
		Entry("resource rule revocation", "rules"),
		Entry("explicit deny", "deny"),
		Entry("authorizer deletion", "delete"),
		Entry("scoped candidate becomes global", "scoped-to-global"),
		Entry("global candidate becomes scoped", "global-to-scoped"),
	)

	It("returns an HTTP 200 denied SAR when a subject exhausts its burst", func() {
		authorizer.Limiter = rate.NewLimiter(0, 1)
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
		response := sendSAR(authorizer, sar)
		Expect(response.Status.Allowed).To(BeFalse())
		Expect(response.Status.Denied).To(BeTrue())
		Expect(response.Status.Reason).To(Equal("rate limit exceeded"))
		other := sar.DeepCopy()
		other.Spec.User += "-other"
		Expect(sendSAR(authorizer, *other).Status.Reason).NotTo(Equal("rate limit exceeded"))
	})

	It("requires live configured, Ready and current-generation status once status is initialized", func() {
		wa.Status.ObservedGeneration = wa.Generation
		wa.Status.AuthorizerConfigured = false
		conditions.Set(wa, &metav1.Condition{
			Type: "Ready", Status: metav1.ConditionTrue, Reason: "Configured", Message: "Configured",
			ObservedGeneration: wa.Generation,
		})
		Expect(envClient.Status().Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeFalse())
		wa.Status.AuthorizerConfigured = true
		Expect(envClient.Status().Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
		conditions.Set(wa, &metav1.Condition{
			Type: "Ready", Status: metav1.ConditionFalse, Reason: "Pending", Message: "Not ready",
			ObservedGeneration: wa.Generation,
		})
		Expect(envClient.Status().Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeFalse())
		conditions.Set(wa, &metav1.Condition{
			Type: "Ready", Status: metav1.ConditionTrue, Reason: "Configured", Message: "Configured",
			ObservedGeneration: wa.Generation,
		})
		Expect(envClient.Status().Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
		wa.Spec.ResourceRules[0].Verbs = []string{"get", "list"}
		Expect(envClient.Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeFalse())
		wa.Status.ObservedGeneration = wa.Generation
		Expect(envClient.Status().Update(ctx, wa)).To(Succeed())
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
	})

	It("treats an empty selector as global for cluster-scoped requests", func() {
		wa.Spec.NamespaceSelector = metav1.LabelSelector{}
		Expect(envClient.Update(ctx, wa)).To(Succeed())
		sar.Spec.ResourceAttributes.Namespace = ""
		sar.Spec.ResourceAttributes.Resource = "nodes"
		Eventually(func() bool {
			return sendSAR(authorizer, sar).Status.Allowed
		}).WithTimeout(10 * time.Second).Should(BeTrue())
	})

	It("memoizes namespace reads within a request but refreshes them on the next request", func() {
		wa.Spec.AllowedPrincipals = []authorizationv1alpha1.Principal{{User: ns.Name + "-other"}}
		Expect(envClient.Update(ctx, wa)).To(Succeed())
		second := &authorizationv1alpha1.WebhookAuthorizer{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "discovery-second-"}, Spec: wa.Spec,
		}
		createWAAndSync(ctx, second)
		DeferCleanup(func() { Expect(envClient.Delete(ctx, second)).To(Succeed()) })
		// Wait for both selector candidates, not just the Get cache.
		Eventually(func() int {
			var candidates authorizationv1alpha1.WebhookAuthorizerList
			Expect(envClient.List(ctx, &candidates, client.MatchingFields{
				indexer.WebhookAuthorizerHasNamespaceSelectorField: indexer.WebhookAuthorizerHasNamespaceSelectorTrue,
			})).To(Succeed())
			count := 0
			for _, candidate := range candidates.Items {
				if candidate.Name == wa.Name || candidate.Name == second.Name {
					count++
				}
			}
			return count
		}).WithTimeout(10 * time.Second).Should(Equal(2))
		reader := &namespaceCountingReader{Reader: envReader}
		authorizer.LiveReader = reader
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeFalse())
		Expect(reader.reads).To(Equal(1))
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeFalse())
		Expect(reader.reads).To(Equal(2))
	})
})
