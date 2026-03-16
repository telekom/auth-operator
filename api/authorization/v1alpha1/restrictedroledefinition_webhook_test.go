// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("RestrictedRoleDefinition Webhook", func() {

	var (
		policy *RBACPolicy
	)

	BeforeEach(func() {
		policy = &RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-rrd-webhook-policy",
			},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{
					Namespaces: []string{"default"},
				},
			},
		}
		err := k8sClient.Create(ctx, policy)
		if err != nil {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).To(Succeed())
		}

		// Wait for the informer cache to sync the RBACPolicy so webhook validators
		// using mgr.GetClient() can find it. DryRun avoids side effects.
		probe := &RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "cache-sync-probe-rrd"},
			Spec: RestrictedRoleDefinitionSpec{
				PolicyRef:       RBACPolicyReference{Name: policy.Name},
				TargetRole:      DefinitionClusterRole,
				TargetName:      "cache-sync-probe-rrd",
				ScopeNamespaced: false,
			},
		}
		Eventually(func() error {
			return k8sClient.Create(ctx, probe.DeepCopy(), client.DryRunAll)
		}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())
	})

	Context("When creating RestrictedRoleDefinition under Validating Webhook", func() {

		It("Should admit a valid ClusterRole RestrictedRoleDefinition", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-valid-cr",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-valid-cr",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})

		It("Should deny when referenced RBACPolicy does not exist", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-no-policy",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: "nonexistent-policy"},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-no-policy",
					ScopeNamespaced: false,
				},
			}
			err := k8sClient.Create(ctx, rrd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("nonexistent-policy"))
		})

		It("Should deny duplicate targetName for same targetRole", func() {
			rrd1 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-dup-first",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-rrd-target",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd1)).To(Succeed())

			rrd2 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-dup-second",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-rrd-target",
					ScopeNamespaced: false,
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rrd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("targetName shared-rrd-target is already in use"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd1)).To(Succeed())
		})

		It("Should allow same targetName for different targetRole", func() {
			rrd1 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-diff-role1",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "same-target-name",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd1)).To(Succeed())

			rrd2 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-diff-role2",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "same-target-name",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			// Wait for cache to sync rrd1 before creating rrd2.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Create(ctx, rrd2.DeepCopy(), client.DryRunAll)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd1)).To(Succeed())
		})

		It("Should allow same targetName for namespaced Role targets in different namespaces", func() {
			rrd1 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-same-role-name-team-a",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "shared-rrd-role-name",
					TargetNamespace: "team-a",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rrd1)).To(Succeed())

			rrd2 := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-same-role-name-team-b",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "shared-rrd-role-name",
					TargetNamespace: "team-b",
					ScopeNamespaced: true,
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rrd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).NotTo(HaveOccurred())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Create(ctx, rrd2)).To(Succeed())

			Expect(k8sClient.Delete(ctx, rrd1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rrd2)).To(Succeed())
		})
	})

	Context("When updating RestrictedRoleDefinition under Validating Webhook", func() {

		It("Should deny changing targetName (immutable)", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-immut-tn",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-immut-tn",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedRoleDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), latest)).To(Succeed())
				latest.Spec.TargetName = "modified-name"
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})

		It("Should deny changing targetRole (immutable)", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-immut-tr",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-immut-tr",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedRoleDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), latest)).To(Succeed())
				latest.Spec.TargetRole = DefinitionNamespacedRole
				latest.Spec.TargetNamespace = "default"
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})

		It("Should deny changing policyRef (immutable)", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-immut-pr",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-immut-pr",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedRoleDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), latest)).To(Succeed())
				latest.Spec.PolicyRef.Name = "different-policy"
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})

		It("Should deny changing targetNamespace (immutable)", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-immut-tns",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-rrd-immut-tns",
					TargetNamespace: "team-a",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())

			Eventually(func(g Gomega) {
				latest := &RestrictedRoleDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), latest)).To(Succeed())
				latest.Spec.TargetNamespace = "team-b"
				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("spec.targetNamespace"))
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})

		It("Should admit valid updates to mutable fields", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-mut-ok",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-mut-ok",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())

			// Update restrictedVerbs (mutable).
			Eventually(func(g Gomega) {
				latest := &RestrictedRoleDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), latest)).To(Succeed())
				latest.Spec.RestrictedVerbs = []string{"delete"}
				g.Expect(k8sClient.Update(ctx, latest)).To(Succeed())
			}).WithTimeout(testTimeoutSeconds * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})
	})

	Context("When deleting RestrictedRoleDefinition under Validating Webhook", func() {

		It("Should always allow delete", func() {
			rrd := &RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-rrd-delete",
				},
				Spec: RestrictedRoleDefinitionSpec{
					PolicyRef:       RBACPolicyReference{Name: policy.Name},
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-rrd-delete",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
		})
	})
})
