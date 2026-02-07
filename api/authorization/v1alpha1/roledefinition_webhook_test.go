/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("RoleDefinition Webhook", func() {

	Context("When creating RoleDefinition under Validating Webhook", func() {

		It("Should admit a valid ClusterRole RoleDefinition", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-clusterrole",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-valid-clusterrole",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should admit a valid namespaced Role RoleDefinition", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-valid-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny when targetRole is Role but targetNamespace is empty", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-role-no-ns",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-role-no-ns",
					ScopeNamespaced: true,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("targetNamespace is required when targetRole is 'Role'"))
		})

		It("Should deny when targetRole is ClusterRole but targetNamespace is set", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cr-with-ns",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-cr-with-ns",
					TargetNamespace: "default",
					ScopeNamespaced: false,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("targetNamespace must not be set when targetRole is 'ClusterRole'"))
		})

		It("Should deny duplicate targetName for the same targetRole", func() {
			rd1 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-first",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-target-name",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd1)).To(Succeed())

			// The webhook validator uses the manager's cached client for MatchingFields lookups.
			// Use DryRun to poll until the informer cache has synced rd1, avoiding side effects.
			rd2 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-second",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-target-name",
					ScopeNamespaced: false,
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("targetName shared-target-name already exists"))
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd1)).To(Succeed())
		})

		It("Should allow same targetName for different targetRoles", func() {
			rd1 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-cr",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "cross-role-target",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd1)).To(Succeed())

			// Wait for the informer cache to sync rd1 before verifying cross-role allowance.
			rd2 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "cross-role-target",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			Eventually(func(g Gomega) {
				// DryRun: Cache must have synced rd1 for this check to be meaningful.
				// The webhook should allow this since targetRoles differ.
				err := k8sClient.Create(ctx, rd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).NotTo(HaveOccurred())
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Now actually create rd2.
			Expect(k8sClient.Create(ctx, rd2)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd2)).To(Succeed())
		})
	})
})
