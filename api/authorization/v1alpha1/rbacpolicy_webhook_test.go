// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const testTimeoutSeconds = 10

var _ = Describe("RBACPolicy Webhook", func() {

	Context("When creating RBACPolicy under Validating Webhook", func() {

		It("Should admit a minimal valid RBACPolicy", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-minimal",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})

		It("Should admit an RBACPolicy with valid label selectors", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-labels",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"env": "test"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})

		It("Should deny an RBACPolicy with invalid namespace label selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-nssel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						NamespaceSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{Key: "key", Operator: "InvalidOp"},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("namespaceSelector"))
		})

		It("Should deny an RBACPolicy with invalid binding limits label selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-blsel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					BindingLimits: &BindingLimits{
						ClusterRoleBindingLimits: &RoleRefLimits{
							AllowedRoleRefSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "key", Operator: "InvalidOp"},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("allowedRoleRefSelector"))
		})

		It("Should deny an RBACPolicy with invalid forbidden role ref selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-forbsel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					BindingLimits: &BindingLimits{
						RoleBindingLimits: &RoleRefLimits{
							ForbiddenRoleRefSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "key", Operator: "InvalidOp"},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("forbiddenRoleRefSelector"))
		})

		It("Should deny an RBACPolicy with invalid target namespace selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-tnssel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					BindingLimits: &BindingLimits{
						TargetNamespaceLimits: &NamespaceLimits{
							AllowedNamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "key", Operator: "InvalidOp"},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("allowedNamespaceSelector"))
		})

		It("Should deny an RBACPolicy with invalid SA namespace selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-sanssel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					SubjectLimits: &SubjectLimits{
						ServiceAccountLimits: &ServiceAccountLimits{
							AllowedNamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "key", Operator: "InvalidOp"},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("allowedNamespaceSelector"))
		})

		It("Should deny an RBACPolicy with invalid SA creation namespace selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-bad-sacsel",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					SubjectLimits: &SubjectLimits{
						ServiceAccountLimits: &ServiceAccountLimits{
							Creation: &SACreationConfig{
								AllowedCreationNamespaceSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "key", Operator: "InvalidOp"},
									},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("allowedCreationNamespaceSelector"))
		})

		It("Should admit an RBACPolicy with valid defaultAssignment", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-default-assignment-valid",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					DefaultAssignment: &DefaultPolicyAssignment{
						Groups: []string{"oidc:team-a-admins"},
						ServiceAccounts: []SARef{
							{Name: "rbac-applier", Namespace: "team-a"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})

		It("Should deny an RBACPolicy with empty defaultAssignment", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-default-assignment-empty",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					DefaultAssignment: &DefaultPolicyAssignment{},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("defaultAssignment"))
		})

		It("Should deny an RBACPolicy defaultAssignment serviceAccount without namespace", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-default-assignment-sa-missing-ns",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
					DefaultAssignment: &DefaultPolicyAssignment{
						ServiceAccounts: []SARef{{Name: "rbac-applier"}},
					},
				},
			}
			err := k8sClient.Create(ctx, pol)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("serviceAccounts[0].namespace"))
		})
	})

	Context("When updating RBACPolicy under Validating Webhook", func() {

		It("Should admit a valid update", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-update",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())

			// Update with new namespaces.
			Eventually(func(g Gomega) {
				latest := &RBACPolicy{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pol), latest)).To(Succeed())
				latest.Spec.AppliesTo.Namespaces = []string{"default", "kube-system"}
				g.Expect(k8sClient.Update(ctx, latest)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})

		It("Should deny an update with invalid label selector", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-update-bad",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RBACPolicy{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pol), latest)).To(Succeed())
				latest.Spec.AppliesTo.NamespaceSelector = &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "key", Operator: "InvalidOp"},
					},
				}
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("namespaceSelector"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})
	})

	Context("When deleting RBACPolicy under Validating Webhook", func() {

		It("Should allow deleting an unreferenced RBACPolicy", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-delete-ok",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())
			Expect(k8sClient.Delete(ctx, pol)).To(Succeed())
		})

		It("Should deny deleting an RBACPolicy referenced by RestrictedBindDefinition", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-del-ref-rbd",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())

			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-refs-policy",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: "test-rbacpol-del-ref-rbd"},
					TargetName: "test-rbd-refs-policy",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			// Use Eventually to tolerate webhook cache-sync delay for the
			// RBACPolicy that was just created above.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Use DryRun to poll until the informer cache has synced the RBD;
			// a real Delete could permanently remove the policy if the cache
			// hasn't synced the reference yet.
			Eventually(func(g Gomega) {
				err := k8sClient.Delete(ctx, pol.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("still reference this policy"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Cleanup: delete the RBD first, then the policy.
			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Delete(ctx, pol.DeepCopy())).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
		})

		It("Should deny deleting an RBACPolicy referenced by RestrictedRoleDefinition", func() {
			pol := &RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbacpol-del-ref-rrd",
				},
				Spec: RBACPolicySpec{
					AppliesTo: PolicyScope{
						Namespaces: []string{"default"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pol)).To(Succeed())

			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-refs-policy",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: "test-rbacpol-del-ref-rrd"},
					TargetName:      "test-rrd-refs-policy",
					TargetRole:      DefinitionClusterRole,
					ScopeNamespaced: false,
				},
			}
			// Use Eventually to tolerate webhook cache-sync delay for the
			// RBACPolicy that was just created above.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Use DryRun to poll until the informer cache has synced the RRD;
			// a real Delete could permanently remove the policy if the cache
			// hasn't synced the reference yet.
			Eventually(func(g Gomega) {
				err := k8sClient.Delete(ctx, pol.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("still reference this policy"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Cleanup: delete the RRD first, then the policy.
			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Delete(ctx, pol.DeepCopy())).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
		})
	})
})
