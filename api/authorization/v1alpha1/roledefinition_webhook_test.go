/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
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

		It("Should admit a ClusterRole with aggregationLabels", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-labels",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-labels",
					ScopeNamespaced: false,
					AggregationLabels: map[string]string{
						"custom.example.com/aggregate-to-monitoring": "true",
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny aggregationLabels on a namespaced Role", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-labels-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-agg-labels-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
					AggregationLabels: map[string]string{
						"rbac.authorization.k8s.io/aggregate-to-view": "true",
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregationLabels can only be used when targetRole is 'ClusterRole'"))
		})

		It("Should admit a ClusterRole with aggregateFrom", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-from",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-from",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny aggregateFrom on a namespaced Role", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-from-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-agg-from-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregateFrom can only be used when targetRole is 'ClusterRole'"))
		})

		It("Should deny aggregateFrom with restrictedVerbs", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-restricted",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-restricted",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
					RestrictedVerbs: []string{"delete"},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregateFrom is mutually exclusive"))
		})

		It("Should deny aggregateFrom with empty selectors", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-empty-sel",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-empty-sel",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have at least one clusterRoleSelector"))
		})

		It("Should deny aggregation labels targeting built-in ClusterRoles", func() {
			for _, target := range []string{"admin", "edit", "view", "cluster-admin"} {
				rd := &RoleDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-agg-builtin-" + target,
					},
					Spec: RoleDefinitionSpec{
						TargetRole:      DefinitionClusterRole,
						TargetName:      "test-agg-builtin-" + target,
						ScopeNamespaced: false,
						AggregationLabels: map[string]string{
							"rbac.authorization.k8s.io/aggregate-to-" + target: "true",
						},
					},
				}
				err := k8sClient.Create(ctx, rd)
				Expect(err).To(HaveOccurred(), "expected rejection for aggregate-to-%s", target)
				Expect(err.Error()).To(ContainSubstring("Forbidden"), "expected Forbidden for aggregate-to-%s", target)
				Expect(err.Error()).To(ContainSubstring("built-in ClusterRole"), "expected built-in ClusterRole in error for aggregate-to-%s", target)
			}
		})

		It("Should deny aggregateFrom with empty selector criteria", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-empty-criteria",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-empty-criteria",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{}, // empty selector — no matchLabels, no matchExpressions
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty selector would match all ClusterRoles"))
		})
	})
})
