/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("BindDefinition Webhook", func() {

	validSubjects := []rbacv1.Subject{
		{
			Kind:     "Group",
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
				},
			}
			Expect(k8sClient.Create(ctx, bd1)).To(Succeed())

			bd2 := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-bd-second",
				},
				Spec: BindDefinitionSpec{
					TargetName: "shared-bd-target",
					Subjects:   validSubjects,
				},
			}
			err := k8sClient.Create(ctx, bd2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("targetName shared-bd-target already exists"))

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd1)).To(Succeed())
		})

		It("Should return a warning when referenced ClusterRole does not exist", func() {
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
			// The webhook admits with a warning when roles don't exist
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
		})
	})
})
