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

var _ = Describe("RestrictedBindDefinition Webhook", func() {

	var (
		policy *RBACPolicy
	)

	// Create a shared RBACPolicy for all tests.
	BeforeEach(func() {
		policy = &RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-rbd-webhook-policy",
			},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{
					Namespaces: []string{"default"},
				},
			},
		}
		// Only create if it doesn't already exist (envtest webhook suite shares state).
		err := k8sClient.Create(ctx, policy)
		if err != nil {
			// Already exists from a previous test.
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).To(Succeed())
		}

		// Wait for the informer cache to sync the RBACPolicy so webhook validators
		// using mgr.GetClient() can find it. DryRun avoids side effects.
		probe := &RestrictedBindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "cache-sync-probe-rbd"},
			Spec: RestrictedBindDefinitionSpec{
				PolicyRef:           RBACPolicyReference{Name: policy.Name},
				TargetName:          "cache-sync-probe-rbd",
				Subjects:            []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "probe"}},
				ClusterRoleBindings: &ClusterBinding{ClusterRoleRefs: []string{"probe"}},
			},
		}
		Eventually(func() error {
			return k8sClient.Create(ctx, probe.DeepCopy(), client.DryRunAll)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())
	})

	Context("When creating RestrictedBindDefinition under Validating Webhook", func() {

		It("Should admit a valid RestrictedBindDefinition", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-valid",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-valid",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})

		It("Should deny when referenced RBACPolicy does not exist", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-no-policy",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: "nonexistent-policy"},
					TargetName: "test-rbd-no-policy",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			err := k8sClient.Create(ctx, rbd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("nonexistent-policy"))
		})

		It("Should deny duplicate targetName", func() {
			rbd1 := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-dup-first",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "shared-rbd-target",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd1)).To(Succeed())

			rbd2 := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-dup-second",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "shared-rbd-target",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rbd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("spec.targetName"))
				g.Expect(err.Error()).To(ContainSubstring("shared-rbd-target"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rbd1)).To(Succeed())
		})

		It("Should deny with invalid namespace selector", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-bad-nssel",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-bad-nssel",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					RoleBindings: []NamespaceBinding{
						{
							ClusterRoleRefs: []string{"some-role"},
							NamespaceSelector: []metav1.LabelSelector{
								{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "key", Operator: "InvalidOp"},
									},
								},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rbd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("namespaceSelector"))
		})
	})

	Context("When CEL validation rejects invalid RestrictedBindDefinitions", func() {

		It("Should deny a RestrictedBindDefinition without clusterRoleBindings or roleBindings", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-cel-no-bindings",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-cel-no-bindings",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
				},
			}
			err := k8sClient.Create(ctx, rbd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one binding with a referenced role must be specified"))
		})

		It("Should deny a RestrictedBindDefinition with empty subjects", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-cel-no-subjects",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-cel-no-subjects",
					Subjects:   []rbacv1.Subject{},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"view"},
					},
				},
			}
			err := k8sClient.Create(ctx, rbd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one subject must be specified"))
		})

		It("Should deny a RestrictedBindDefinition with ServiceAccount subject missing namespace", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-cel-sa-no-ns",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-cel-sa-no-ns",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "my-sa"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"view"},
					},
				},
			}
			err := k8sClient.Create(ctx, rbd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ServiceAccount subjects must specify a namespace"))
		})
	})

	Context("When updating RestrictedBindDefinition under Validating Webhook", func() {

		It("Should deny changing targetName (immutable)", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-immut-tn",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-immut-tn",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedBindDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rbd), latest)).To(Succeed())
				latest.Spec.TargetName = testModifiedValue
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})

		It("Should deny changing policyRef (immutable)", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-immut-pr",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-immut-pr",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedBindDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rbd), latest)).To(Succeed())
				latest.Spec.PolicyRef.Name = "different-policy"
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})

		It("Should admit valid updates to mutable fields", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-mut-ok",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-mut-ok",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd)).To(Succeed())

			// Update subjects (mutable).
			Eventually(func(g Gomega) {
				latest := &RestrictedBindDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rbd), latest)).To(Succeed())
				latest.Spec.Subjects = []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "updated-group"},
				}
				g.Expect(k8sClient.Update(ctx, latest)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})
	})

	Context("When deleting RestrictedBindDefinition under Validating Webhook", func() {

		It("Should always allow delete", func() {
			rbd := &RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rbd-delete",
				},
				Spec: RestrictedBindDefinitionSpec{
					PolicyRef:  RBACPolicyReference{Name: policy.Name},
					TargetName: "test-rbd-delete",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "test-group"},
					},
					ClusterRoleBindings: &ClusterBinding{
						ClusterRoleRefs: []string{"some-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})
	})
})
