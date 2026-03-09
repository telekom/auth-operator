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

var _ = Describe("BindDefinition Webhook", func() {

	validSubjects := []rbacv1.Subject{
		{
			Kind:     rbacv1.GroupKind,
			APIGroup: rbacv1.GroupName,
			Name:     "test-group",
		},
	}

	Context("When creating BindDefinition under Validating Webhook", func() {

		It("Should admit a valid BindDefinition with ClusterRoleBindings", func() {
			// Create the referenced ClusterRole first
			cr := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-admit-role",
				},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				},
			}
			Expect(k8sClient.Create(ctx, cr)).To(Succeed())

			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-bd",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-valid-bd",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"test-bd-admit-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, cr)).To(Succeed())
		})

		It("Should deny duplicate targetName", func() {
			bd1 := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-bd-first",
				},
				Spec: BindDefinitionSpec{
					TargetName: "shared-bd-target",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"some-clusterrole"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bd1)).To(Succeed())

			// The webhook validator uses the manager's cached client for MatchingFields lookups.
			// Use DryRun to poll until the informer cache has synced bd1, avoiding side effects.
			bd2 := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-bd-second",
				},
				Spec: BindDefinitionSpec{
					TargetName: "shared-bd-target",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"some-clusterrole"},
					},
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, bd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("targetName shared-bd-target already exists"))
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd1)).To(Succeed())
		})

		It("should admit even if referenced ClusterRole does not exist", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-missing-role",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-bd-missing-role",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"nonexistent-clusterrole"},
					},
				},
			}
			// The webhook admits with a warning when roles don't exist;
			// warning verification requires a custom round-tripper (not yet wired).
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
		})

		It("should reject when missing-role-policy is error and role does not exist", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-error-policy",
					Annotations: map[string]string{
						MissingRolePolicyAnnotation: string(MissingRolePolicyError),
					},
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-bd-error-policy",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"nonexistent-role-error"},
					},
				},
			}
			err := k8sClient.Create(ctx, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing-role-policy is 'error'"))
		})

		It("should admit when missing-role-policy is ignore and role does not exist", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-ignore-policy",
					Annotations: map[string]string{
						MissingRolePolicyAnnotation: string(MissingRolePolicyIgnore),
					},
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-bd-ignore-policy",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"nonexistent-role-ignore"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
		})

		It("should admit when missing-role-policy is error and role exists", func() {
			cr := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-error-existing-role",
				},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				},
			}
			Expect(k8sClient.Create(ctx, cr)).To(Succeed())

			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bd-error-existing",
					Annotations: map[string]string{
						MissingRolePolicyAnnotation: string(MissingRolePolicyError),
					},
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-bd-error-existing",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"test-bd-error-existing-role"},
					},
				},
			}
			// The webhook validator uses the manager's cached client.
			// Poll with DryRun until the informer cache has synced the ClusterRole.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Create(ctx, bd.DeepCopy(), client.DryRunAll)).To(Succeed())
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, cr)).To(Succeed())
		})
	})

	Context("When CEL validation rejects invalid BindDefinitions", func() {

		It("should deny a BindDefinition without clusterRoleBindings or roleBindings", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-bindings",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-cel-no-bindings",
					Subjects:   validSubjects,
				},
			}
			err := k8sClient.Create(ctx, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one binding with a referenced role must be specified"))
		})

		It("should deny a BindDefinition with empty subjects", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-subjects",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-cel-no-subjects",
					Subjects:   []rbacv1.Subject{},
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"view"},
					},
				},
			}
			err := k8sClient.Create(ctx, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one subject must be specified"))
		})

		It("should deny a BindDefinition with ServiceAccount subject missing namespace", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-sa-no-ns",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-cel-sa-no-ns",
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "my-sa"},
					},
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"view"},
					},
				},
			}
			err := k8sClient.Create(ctx, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ServiceAccount subjects must specify a namespace"))
		})
	})

	Context("Subject Kind Validation", func() {
		It("should reject a BindDefinition with unsupported subject Kind", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bad-subject-kind",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-bad-subject-kind",
					Subjects: []rbacv1.Subject{
						{Kind: "Pod", Name: "test-pod"},
					},
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"view"},
					},
				},
			}
			err := k8sClient.Create(ctx, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.subjects[0].kind"))
		})
	})

	Context("Update Immutability", func() {
		It("should deny update that changes targetName", func() {
			// Create a valid BindDefinition first
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-bd-target",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-immut-bd-target",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"test-bd-admit-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Attempt to change targetName — should be rejected
			Eventually(func(g Gomega) {
				fresh := &BindDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bd), fresh)).To(Succeed())
				fresh.Spec.TargetName = "changed-target-name"
				err := k8sClient.Update(ctx, fresh)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("spec.targetName"))
				g.Expect(err.Error()).To(ContainSubstring("immutable"))
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
		})

		It("should allow update that does not change targetName", func() {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-bd-allowed",
				},
				Spec: BindDefinitionSpec{
					TargetName: "test-immut-bd-allowed",
					Subjects:   validSubjects,
					ClusterRoleBindings: ClusterBinding{
						ClusterRoleRefs: []string{"test-bd-admit-role"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Change subjects (allowed)
			Eventually(func(g Gomega) {
				fresh := &BindDefinition{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bd), fresh)).To(Succeed())
				fresh.Spec.Subjects = []rbacv1.Subject{
					{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "new-user"},
				}
				g.Expect(k8sClient.Update(ctx, fresh)).To(Succeed())
			}, 5*time.Second, 250*time.Millisecond).Should(Succeed())

			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
		})
	})
})
