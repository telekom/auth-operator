/*
Copyright © 2026 Deutsche Telekom AG.
*/

package webhooks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
)

// sendSAR is a test helper that sends a SubjectAccessReview to the authorizer
// and returns the parsed response.
func sendSAR(authorizer *webhooks.Authorizer, sar authzv1.SubjectAccessReview) authzv1.SubjectAccessReview {
	GinkgoHelper()
	body, err := json.Marshal(sar)
	Expect(err).NotTo(HaveOccurred())

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)
	Expect(w.Code).To(Equal(http.StatusOK))

	var resp authzv1.SubjectAccessReview
	Expect(json.NewDecoder(w.Body).Decode(&resp)).To(Succeed())
	return resp
}

var _ = Describe("WebhookAuthorizer Integration", func() {
	var (
		ctx        context.Context
		authorizer *webhooks.Authorizer
	)

	BeforeEach(func() {
		ctx = context.Background()
		authorizer = &webhooks.Authorizer{
			Client: envClient,
			Log:    zap.New(zap.WriteTo(io.Discard)),
		}
	})

	Describe("Basic Allow/Deny Flow", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "wa-basic-"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "allowed-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("allows matching SAR", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "allowed-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
			Expect(resp.Status.Reason).To(ContainSubstring("Access granted"))
		})

		It("denies non-matching user", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "unknown-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})

		It("denies non-matching verb", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "allowed-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "delete", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})
	})

	Describe("DeniedPrincipals Override", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-deny-override"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "dual-user"},
					},
					DeniedPrincipals: []authzv1alpha1.Principal{
						{User: "dual-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("deny overrides allow for the same user", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "dual-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
			Expect(resp.Status.Reason).To(ContainSubstring("denied"))
		})
	})

	Describe("NamespaceSelector Filtering", Ordered, func() {
		var nsProdName, nsDevName string

		BeforeAll(func() {
			setupCtx := context.Background()
			// Create namespaces with different labels using GenerateName.
			nsProd := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ns-prod-int-",
					Labels:       map[string]string{"env": "production"},
				},
			}
			nsDev := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ns-dev-int-",
					Labels:       map[string]string{"env": "development"},
				},
			}
			Expect(envClient.Create(setupCtx, nsProd)).To(Succeed())
			nsProdName = nsProd.Name
			Expect(envClient.Create(setupCtx, nsDev)).To(Succeed())
			nsDevName = nsDev.Name
			DeferCleanup(func() {
				_ = envClient.Delete(setupCtx, nsProd)
				_ = envClient.Delete(setupCtx, nsDev)
			})

			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-ns-selector"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "ns-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
					},
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
				},
			}
			Expect(envClient.Create(setupCtx, wa)).To(Succeed())
			waitForCachedWA(setupCtx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(setupCtx, wa)
			})
		})

		It("allows in matching namespace", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "ns-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "", Namespace: nsProdName,
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})

		It("denies in non-matching namespace", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "ns-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "", Namespace: nsDevName,
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})

		It("denies cluster-scoped request (no namespace)", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "ns-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "namespaces", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})
	})

	Describe("Multiple WebhookAuthorizers", func() {
		BeforeEach(func() {
			// Name the deny authorizer so it sorts before the allow one alphabetically,
			// since evaluateSAR iterates in API server list order (alphabetical).
			wa1 := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-aaa-deny"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					DeniedPrincipals: []authzv1alpha1.Principal{
						{User: "blocked-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
					},
				},
			}
			wa2 := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-bbb-allow"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "blocked-user"},
						{User: "normal-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa1)).To(Succeed())
			Expect(envClient.Create(ctx, wa2)).To(Succeed())
			waitForCachedWA(ctx, wa1.Name)
			waitForCachedWA(ctx, wa2.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa1)
				_ = envClient.Delete(ctx, wa2)
			})
		})

		It("deny from first authorizer blocks user even if allowed by second", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "blocked-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "configmaps", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
			Expect(resp.Status.Reason).To(ContainSubstring("denied"))
		})

		It("allows user not in deny list", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "normal-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "configmaps", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})
	})

	Describe("NonResourceRules", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-nonresource"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "health-checker"},
					},
					NonResourceRules: []authzv1.NonResourceRule{
						{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz", "/readyz"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("allows matching non-resource request", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "health-checker",
					NonResourceAttributes: &authzv1.NonResourceAttributes{
						Verb: "get", Path: "/healthz",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})

		It("denies non-matching path", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "health-checker",
					NonResourceAttributes: &authzv1.NonResourceAttributes{
						Verb: "get", Path: "/metrics",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})
	})

	Describe("Group-Based Principal Matching", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-groups"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{Groups: []string{"platform-admins"}},
					},
					DeniedPrincipals: []authzv1alpha1.Principal{
						{Groups: []string{"suspended-group"}},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("allows user in allowed group", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User:   "group-member",
					Groups: []string{"platform-admins"},
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "create", Resource: "deployments", Group: "apps",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})

		It("denies user in denied group", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User:   "suspended-member",
					Groups: []string{"suspended-group"},
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})

		It("denies user not in any matching group", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User:   "outsider",
					Groups: []string{"other-group"},
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})
	})

	Describe("ServiceAccount Principal Matching", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-serviceaccount"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "my-sa", Namespace: "kube-system"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("allows matching service account", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "system:serviceaccount:kube-system:my-sa",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "secrets", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})

		It("denies service account from wrong namespace", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "system:serviceaccount:default:my-sa",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "secrets", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
		})
	})

	Describe("Live Update", func() {
		It("reflects changes after updating the WebhookAuthorizer", func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-live-update"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "live-user"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})

			// Initially allowed.
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "live-user",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())

			// Update to remove the user from allowed principals.
			Expect(envClient.Get(ctx, client.ObjectKeyFromObject(wa), wa)).To(Succeed())
			wa.Spec.AllowedPrincipals = []authzv1alpha1.Principal{
				{User: "someone-else"},
			}
			Expect(envClient.Update(ctx, wa)).To(Succeed())

			// After update, user should be denied once the cache reflects the change.
			Eventually(func() bool {
				r := sendSAR(authorizer, authzv1.SubjectAccessReview{
					Spec: authzv1.SubjectAccessReviewSpec{
						User: "live-user",
						ResourceAttributes: &authzv1.ResourceAttributes{
							Verb: "get", Resource: "pods", Group: "",
						},
					},
				})
				return r.Status.Allowed
			}, 5*time.Second, 50*time.Millisecond).Should(BeFalse())
		})
	})

	Describe("Wildcard Matching", func() {
		BeforeEach(func() {
			wa := &authzv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-wildcard"},
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{
						{User: "admin"},
					},
					ResourceRules: []authzv1.ResourceRule{
						{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
					},
				},
			}
			Expect(envClient.Create(ctx, wa)).To(Succeed())
			waitForCachedWA(ctx, wa.Name)
			DeferCleanup(func() {
				_ = envClient.Delete(ctx, wa)
			})
		})

		It("wildcard rule matches any resource request", func() {
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "admin",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "delete", Resource: "deployments", Group: "apps",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeTrue())
		})
	})

	Describe("No WebhookAuthorizers", func() {
		It("denies when no authorizers exist", func() {
			// Ensure no authorizers by using a fresh context.
			// Note: Other tests use DeferCleanup so this may run with zero authorizers.
			resp := sendSAR(authorizer, authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User: "anyone",
					ResourceAttributes: &authzv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Group: "",
					},
				},
			})
			Expect(resp.Status.Allowed).To(BeFalse())
			Expect(resp.Status.Reason).To(ContainSubstring("no matching rules"))
		})
	})
})
