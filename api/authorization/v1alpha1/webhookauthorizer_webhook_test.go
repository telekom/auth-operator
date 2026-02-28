/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("WebhookAuthorizer CEL Validation", func() {

	validResourceRules := []authzv1.ResourceRule{
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
	}

	validAllowedPrincipals := []Principal{
		{User: "admin"},
	}

	Context("When creating WebhookAuthorizer under CEL validation", func() {

		It("Should admit a valid WebhookAuthorizer with resourceRules and allowedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules:     validResourceRules,
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("Should deny a WebhookAuthorizer without resourceRules or nonResourceRules", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-rules",
				},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one resourceRules or nonResourceRules must be specified"))
		})

		It("Should deny a WebhookAuthorizer without allowedPrincipals or deniedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-principals",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules: validResourceRules,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one allowedPrincipals or deniedPrincipals must be specified"))
		})

		It("Should deny a WebhookAuthorizer with empty resourceRules and nonResourceRules slices", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-empty-rules",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules:     []authzv1.ResourceRule{},
					NonResourceRules:  []authzv1.NonResourceRule{},
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one resourceRules or nonResourceRules must be specified"))
		})

		It("Should admit a WebhookAuthorizer with only nonResourceRules", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa-nonresource",
				},
				Spec: WebhookAuthorizerSpec{
					NonResourceRules: []authzv1.NonResourceRule{
						{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}},
					},
					DeniedPrincipals: []Principal{
						{User: "bad-actor"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("Should admit a WebhookAuthorizer with only deniedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa-denied",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules: validResourceRules,
					DeniedPrincipals: []Principal{
						{User: "blocked-user"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})
	})
})
