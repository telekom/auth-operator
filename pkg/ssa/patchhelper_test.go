// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/auth-operator/pkg/ssa"
)

var _ = Describe("PatchHelper - cache-aware SSA diff", func() {

	// -----------------------------------------------------------------------
	// ClusterRole
	// -----------------------------------------------------------------------
	Context("PatchApplyClusterRole", func() {
		It("should create a ClusterRole when it does not exist", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-create-cr",
				map[string]string{"app": "test"}, rules)

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			var cr rbacv1.ClusterRole
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-create-cr"}, &cr)).To(Succeed())
			Expect(cr.Rules).To(HaveLen(1))
		})

		It("should skip when ClusterRole already matches", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-skip-cr",
				map[string]string{"app": "test"}, rules)

			// Create first.
			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			// Apply again — should skip.
			result, err = ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should patch when ClusterRole rules change", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-patch-cr",
				map[string]string{"app": "test"}, rules)

			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Change rules.
			newRules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}},
			}
			ac2 := ssa.ClusterRoleWithLabelsAndRules("ph-patch-cr",
				map[string]string{"app": "test"}, newRules)

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac2)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			var cr rbacv1.ClusterRole
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-patch-cr"}, &cr)).To(Succeed())
			Expect(cr.Rules[0].Resources).To(ContainElements("pods", "services"))
		})

		It("should patch when labels change", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-label-cr",
				map[string]string{"version": "v1"}, rules)

			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Change labels.
			ac2 := ssa.ClusterRoleWithLabelsAndRules("ph-label-cr",
				map[string]string{"version": "v2"}, rules)

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac2)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})

		It("should reject nil ApplyConfiguration", func() {
			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have a name"))
		})

		It("should reject empty name", func() {
			ac := ssa.ClusterRoleWithLabelsAndRules("", nil, nil)
			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name must not be empty"))
		})
	})

	// -----------------------------------------------------------------------
	// Role
	// -----------------------------------------------------------------------
	Context("PatchApplyRole", func() {
		It("should create a Role when it does not exist", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			}
			ac := ssa.RoleWithLabelsAndRules("ph-create-role", "default",
				map[string]string{"tier": "backend"}, rules)

			result, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))
		})

		It("should skip when Role already matches", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			}
			ac := ssa.RoleWithLabelsAndRules("ph-skip-role", "default", nil, rules)

			_, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			result, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should patch when Role rules change", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			}
			ac := ssa.RoleWithLabelsAndRules("ph-patch-role", "default", nil, rules)

			_, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			newRules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "update"}},
			}
			ac2 := ssa.RoleWithLabelsAndRules("ph-patch-role", "default", nil, newRules)

			result, err := ssa.PatchApplyRole(testCtx, k8sClient, ac2)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})

		It("should reject empty namespace", func() {
			ac := ssa.RoleWithLabelsAndRules("test", "", nil, nil)
			_, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("namespace"))
		})
	})

	// -----------------------------------------------------------------------
	// ClusterRoleBinding
	// -----------------------------------------------------------------------
	Context("PatchApplyClusterRoleBinding", func() {
		BeforeEach(func() {
			cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "ph-binding-target"}}
			err := k8sClient.Create(testCtx, cr)
			Expect(client.IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		})

		It("should create a CRB when it does not exist", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "alice", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-create-crb", nil, subjects, roleRef)

			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))
		})

		It("should skip when CRB already matches", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "bob", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-skip-crb",
				map[string]string{"env": "test"}, subjects, roleRef)

			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should patch when subjects change", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "carol", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-patch-crb", nil, subjects, roleRef)

			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			newSubjects := []rbacv1.Subject{
				{Kind: "User", Name: "carol", APIGroup: rbacv1.GroupName},
				{Kind: "Group", Name: "admins", APIGroup: rbacv1.GroupName},
			}
			ac2 := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-patch-crb", nil, newSubjects, roleRef)

			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac2)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})

		It("should reject nil", func() {
			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, nil)
			Expect(err).To(HaveOccurred())
		})
	})

	// -----------------------------------------------------------------------
	// RoleBinding
	// -----------------------------------------------------------------------
	Context("PatchApplyRoleBinding", func() {
		BeforeEach(func() {
			r := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "ph-rb-target", Namespace: "default"}}
			err := k8sClient.Create(testCtx, r)
			Expect(client.IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		})

		It("should create a RoleBinding when it does not exist", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-create-rb", "default", nil, subjects, roleRef)

			result, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))
		})

		It("should skip when RoleBinding already matches", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa-skip", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-skip-rb", "default",
				map[string]string{"tier": "frontend"}, subjects, roleRef)

			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			result, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should patch when annotations change", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa-ann", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-ann-rb", "default", nil, subjects, roleRef)
			ac.WithAnnotations(map[string]string{"note": "v1"})

			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			ac2 := ssa.RoleBindingWithSubjectsAndRoleRef("ph-ann-rb", "default", nil, subjects, roleRef)
			ac2.WithAnnotations(map[string]string{"note": "v2"})

			result, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac2)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})

		It("should reject empty namespace", func() {
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "x"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("test", "", nil, nil, roleRef)
			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
		})
	})

	// -----------------------------------------------------------------------
	// PatchApplyResult stringer
	// -----------------------------------------------------------------------
	Context("PatchApplyResult.String", func() {
		It("should return readable labels", func() {
			Expect(ssa.PatchApplyResultSkipped.String()).To(Equal("skipped"))
			Expect(ssa.PatchApplyResultCreated.String()).To(Equal("created"))
			Expect(ssa.PatchApplyResultPatched.String()).To(Equal("patched"))
			Expect(ssa.PatchApplyResult(99).String()).To(Equal("unknown"))
		})
	})
})
