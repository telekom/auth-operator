// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
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

		It("should not skip matching ClusterRole when ForceOwnership is explicit", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-force-matching-cr",
				map[string]string{"app": "test"}, rules)

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			result, err = ssa.PatchApplyClusterRole(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})

		It("should apply when ClusterRole already matches and Always is requested", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-always-cr",
				map[string]string{"app": "test"}, rules)

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err = ssa.PatchApplyClusterRoleAlways(testCtx, countingClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
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

		It("should patch when a prunable label remains outside desired labels", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-prune-label-cr",
				map[string]string{"safe": "true", "unsafe": "true"}, rules)

			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			ac2 := ssa.ClusterRoleWithLabelsAndRules("ph-prune-label-cr",
				map[string]string{"safe": "true"}, rules)
			result, err := ssa.PatchApplyClusterRolePruningLabels(testCtx, k8sClient, ac2, func(key string) bool {
				return key == "unsafe"
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			var cr rbacv1.ClusterRole
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-prune-label-cr"}, &cr)).To(Succeed())
			Expect(cr.Labels).NotTo(HaveKey("unsafe"))

			result, err = ssa.PatchApplyClusterRolePruningLabels(testCtx, k8sClient, ac2, func(key string) bool {
				return key == "unsafe"
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should prune a protected label owned by another field manager", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-prune-foreign-label-cr",
				map[string]string{"safe": "true"}, rules)

			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			externalAC := ssa.ClusterRoleWithLabelsAndRules("ph-prune-foreign-label-cr",
				map[string]string{"safe": "true", "unsafe": "true"}, rules)
			err = k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			result, err := ssa.PatchApplyClusterRolePruningLabels(testCtx, k8sClient, ac, func(key string) bool {
				return key == "unsafe"
			}, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			var cr rbacv1.ClusterRole
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-prune-foreign-label-cr"}, &cr)).To(Succeed())
			Expect(cr.Labels).NotTo(HaveKey("unsafe"))
		})

		It("should retry apply after a prune conflict even if a stale get still matches desired fields", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ph-prune-conflict-cr",
				map[string]string{"safe": "true", "unsafe": "true"}, rules)

			_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			desiredAC := ssa.ClusterRoleWithLabelsAndRules("ph-prune-conflict-cr",
				map[string]string{"safe": "true"}, rules)
			conflictClient := &clusterRolePruneConflictClient{
				Client:      k8sClient,
				name:        "ph-prune-conflict-cr",
				staleLabels: map[string]string{"safe": "true", "unsafe": "true"},
				staleRules:  rules,
			}
			result, err := ssa.PatchApplyClusterRolePruningLabels(testCtx, conflictClient, desiredAC, func(key string) bool {
				return key == "unsafe"
			}, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(conflictClient.applyCalls).To(Equal(2))

			var cr rbacv1.ClusterRole
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-prune-conflict-cr"}, &cr)).To(Succeed())
			Expect(cr.Labels).NotTo(HaveKey("unsafe"))
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

		It("should fail on field-manager conflicts unless ForceOwnership is explicit", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			externalRules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}},
			}
			externalAC := ssa.ClusterRoleWithLabelsAndRules("ph-conflict-cr", nil, externalRules)
			err := k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac := ssa.ClusterRoleWithLabelsAndRules("ph-conflict-cr", nil, rules)
			_, err = ssa.PatchApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())

			result, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
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

		It("should apply when Role already matches and Always is requested", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			}
			ac := ssa.RoleWithLabelsAndRules("ph-always-role", "default", nil, rules)

			_, err := ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleAlways(testCtx, countingClient, ac)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
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

		It("should fail on field-manager conflicts unless ForceOwnership is explicit", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			}
			externalRules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}},
			}
			externalAC := ssa.RoleWithLabelsAndRules("ph-conflict-role", "default", nil, externalRules)
			err := k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac := ssa.RoleWithLabelsAndRules("ph-conflict-role", "default", nil, rules)
			_, err = ssa.PatchApplyRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())

			result, err := ssa.PatchApplyRole(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
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

		It("should skip an unchanged forced CRB owned by the apply manager", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "owned", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-skip-crb",
				map[string]string{"managed": "true"}, subjects, roleRef).
				WithAnnotations(map[string]string{"source": "test"})

			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(countingClient.applyCalls).To(BeZero())
		})

		It("should claim a matching CRB owned by another field manager", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "shared", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-claim-crb", nil, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, ac, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		})

		It("should re-apply when another manager takes a desired CRB label", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "owned", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-label-crb",
				map[string]string{"managed": "true"}, subjects, roleRef)
			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			foreign := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-label-crb",
				map[string]string{"managed": "false"}, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())
			foreign = ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-label-crb",
				map[string]string{"managed": "true"}, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			ac = ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-label-crb",
				map[string]string{"managed": "true"}, subjects, roleRef)
			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		})

		It("should prune a previously owned CRB label that is no longer desired", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "owned", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-prune-crb",
				map[string]string{"keep": "true", "remove": "true"}, subjects, roleRef)
			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac = ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-force-prune-crb",
				map[string]string{"keep": "true"}, subjects, roleRef)
			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))

			var binding rbacv1.ClusterRoleBinding
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-force-prune-crb"}, &binding)).To(Succeed())
			Expect(binding.Labels).To(HaveKeyWithValue("keep", "true"))
			Expect(binding.Labels).NotTo(HaveKey("remove"))
		})

		It("should apply when CRB already matches and Always is requested", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "bob", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-always-crb", nil, subjects, roleRef)

			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyClusterRoleBindingAlways(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
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

		It("should fail on field-manager conflicts unless ForceOwnership is explicit", func() {
			subjects := []rbacv1.Subject{{Kind: "User", Name: "dave", APIGroup: rbacv1.GroupName}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}

			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-conflict-crb", nil, subjects, roleRef)
			_, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			externalSubjects := []rbacv1.Subject{{Kind: "Group", Name: "external-group", APIGroup: rbacv1.GroupName}}
			externalAC := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-conflict-crb", nil, externalSubjects, roleRef)
			err = k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			desiredSubjects := []rbacv1.Subject{{Kind: "User", Name: "dave", APIGroup: rbacv1.GroupName}}
			desiredAC := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ph-conflict-crb", nil, desiredSubjects, roleRef)
			_, err = ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, desiredAC)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())

			result, err := ssa.PatchApplyClusterRoleBinding(testCtx, k8sClient, desiredAC, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
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

		It("should skip an unchanged forced RoleBinding owned by the apply manager", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "owned", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-skip-rb", "default",
				map[string]string{"managed": "true"}, subjects, roleRef).
				WithAnnotations(map[string]string{"source": "test"})

			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(countingClient.applyCalls).To(BeZero())
		})

		It("should claim a matching RoleBinding owned by another field manager", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "shared", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-claim-rb", "default", nil, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, ac, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		})

		It("should re-apply when another manager takes a desired RoleBinding label", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "owned", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-label-rb", "default",
				map[string]string{"managed": "true"}, subjects, roleRef)
			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			foreign := ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-label-rb", "default",
				map[string]string{"managed": "false"}, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())
			foreign = ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-label-rb", "default",
				map[string]string{"managed": "true"}, subjects, roleRef)
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			ac = ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-label-rb", "default",
				map[string]string{"managed": "true"}, subjects, roleRef)
			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		})

		It("should prune a previously owned RoleBinding label that is no longer desired", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "owned", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-prune-rb", "default",
				map[string]string{"keep": "true", "remove": "true"}, subjects, roleRef)
			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac = ssa.RoleBindingWithSubjectsAndRoleRef("ph-force-prune-rb", "default",
				map[string]string{"keep": "true"}, subjects, roleRef)
			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleBinding(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))

			var binding rbacv1.RoleBinding
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-force-prune-rb", Namespace: "default"}, &binding)).To(Succeed())
			Expect(binding.Labels).To(HaveKeyWithValue("keep", "true"))
			Expect(binding.Labels).NotTo(HaveKey("remove"))
		})

		It("should apply when RoleBinding already matches and Always is requested", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa-always", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-always-rb", "default", nil, subjects, roleRef)

			_, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyRoleBindingAlways(testCtx, countingClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
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

		It("should fail on field-manager conflicts unless ForceOwnership is explicit", func() {
			subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "conflict-sa", Namespace: "default"}}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "ph-rb-target"}
			externalSubjects := []rbacv1.Subject{{Kind: "Group", Name: "external-group", APIGroup: rbacv1.GroupName}}
			externalAC := ssa.RoleBindingWithSubjectsAndRoleRef("ph-conflict-rb", "default", nil, externalSubjects, roleRef)
			err := k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ph-conflict-rb", "default", nil, subjects, roleRef)
			_, err = ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())

			result, err := ssa.PatchApplyRoleBinding(testCtx, k8sClient, ac, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		})
	})

	// -----------------------------------------------------------------------
	// Binding ownership regression coverage
	// -----------------------------------------------------------------------
	DescribeTable("binding ownership safety",
		func(binding bindingPatchTestCase) {
			roleRef := rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "ph-binding-target",
			}
			subjects := []rbacv1.Subject{{Kind: "User", Name: "regression-user"}}
			annotations := map[string]string{"owned": "true"}
			ownerRefs := []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: "owner-uid"}}

			for _, field := range []string{"subjects", "roleRef", "annotation", "ownerReferences"} {
				name := "ph-regression-" + binding.label + "-" + field
				desired := newBindingPatchConfig(binding, name, subjects, roleRef, annotations, ownerRefs, true, true)
				_, err := binding.apply(testCtx, k8sClient, desired, client.ForceOwnership)
				Expect(err).NotTo(HaveOccurred(), "creating %s", name)

				external := newBindingPatchConfig(binding, name, subjects, roleRef, annotations, ownerRefs,
					field == "subjects", field == "roleRef")
				switch field {
				case "annotation":
					external = newBindingPatchConfig(binding, name, nil, roleRef, annotations, nil, false, false)
				case "ownerReferences":
					external = newBindingPatchConfig(binding, name, nil, roleRef, nil, ownerRefs, false, false)
				}
				Expect(k8sClient.Apply(testCtx, external,
					client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed(),
					"transferring %s ownership", field)

				countingClient := &applyCountingClient{Client: k8sClient}
				result, err := binding.apply(testCtx, countingClient, desired, client.ForceOwnership)
				Expect(err).NotTo(HaveOccurred(), "reclaiming %s ownership", field)
				Expect(result).To(Equal(ssa.PatchApplyResultPatched))
				Expect(countingClient.applyCalls).To(Equal(1))

				result, err = binding.apply(testCtx, countingClient, desired, client.ForceOwnership)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
				Expect(countingClient.applyCalls).To(Equal(1), "the re-apply should restore owned fields")
			}
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	DescribeTable("skip an unchanged forced binding with reordered/defaulted subjects",
		func(binding bindingPatchTestCase) {
			name := "ph-regression-order-" + binding.label
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			subjects := []rbacv1.Subject{
				{Kind: "User", Name: "alice"},
				{Kind: "Group", Name: "admins"},
			}
			initial := newBindingPatchConfig(binding, name, subjects, roleRef, nil, nil, true, true)
			_, err := binding.apply(testCtx, k8sClient, initial, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			reordered := newBindingPatchConfig(binding, name,
				[]rbacv1.Subject{subjects[1], subjects[0]}, roleRef, nil, nil, true, true)
			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := binding.apply(testCtx, countingClient, reordered, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(countingClient.applyCalls).To(BeZero())
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	DescribeTable("prune owned annotations and owner references",
		func(binding bindingPatchTestCase) {
			name := "ph-regression-prune-" + binding.label
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			subjects := []rbacv1.Subject{{Kind: "User", Name: "prune-user", APIGroup: rbacv1.GroupName}}
			ownerRefs := []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: "prune-owner-uid"}}
			initial := newBindingPatchConfig(binding, name, subjects, roleRef,
				map[string]string{"remove": "me"}, ownerRefs, true, true)
			_, err := binding.apply(testCtx, k8sClient, initial, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			desired := newBindingPatchConfig(binding, name, subjects, roleRef, nil, nil, true, true)
			result, err := binding.apply(testCtx, k8sClient, desired, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			object := binding.get(testCtx, k8sClient, name)
			Expect(object.GetAnnotations()).NotTo(HaveKey("remove"))
			Expect(object.GetOwnerReferences()).To(BeEmpty())
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	DescribeTable("preserve unrelated foreign binding fields while skipping",
		func(binding bindingPatchTestCase) {
			name := "ph-regression-foreign-" + binding.label
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			subjects := []rbacv1.Subject{{Kind: "User", Name: "foreign-user", APIGroup: rbacv1.GroupName}}
			desired := newBindingPatchConfig(binding, name, subjects, roleRef,
				map[string]string{"owned": "true"}, nil, true, true)
			_, err := binding.apply(testCtx, k8sClient, desired, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			foreign := newBindingPatchConfig(binding, name, nil, roleRef,
				map[string]string{"foreign": "preserve"}, nil, false, false)
			Expect(k8sClient.Apply(testCtx, foreign,
				client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := binding.apply(testCtx, countingClient, desired, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(countingClient.applyCalls).To(BeZero())
			Expect(binding.get(testCtx, k8sClient, name).GetAnnotations()).
				To(HaveKeyWithValue("foreign", "preserve"))
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	DescribeTable("apply when managedFields are unavailable",
		func(binding bindingPatchTestCase) {
			name := "ph-regression-no-managed-fields-" + binding.label
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			subjects := []rbacv1.Subject{{Kind: "User", Name: "managed-fields-user", APIGroup: rbacv1.GroupName}}
			desired := newBindingPatchConfig(binding, name, subjects, roleRef, nil, nil, true, true)
			_, err := binding.apply(testCtx, k8sClient, desired, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{
				Client: &managedFieldsOmittingClient{Client: k8sClient},
			}
			result, err := binding.apply(testCtx, countingClient, desired, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	DescribeTable("do not skip dry-run or stale binding preconditions",
		func(binding bindingPatchTestCase) {
			name := "ph-regression-preconditions-" + binding.label
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "ph-binding-target"}
			subjects := []rbacv1.Subject{{Kind: "User", Name: "precondition-user", APIGroup: rbacv1.GroupName}}
			desired := newBindingPatchConfig(binding, name, subjects, roleRef, nil, nil, true, true)
			_, err := binding.apply(testCtx, k8sClient, desired)
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := binding.apply(testCtx, countingClient, desired, client.DryRunAll)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))

			for _, precondition := range []string{"uid", "resourceVersion"} {
				preconditioned := newBindingPatchConfig(binding, name, subjects, roleRef, nil, nil, true, true)
				setBindingPrecondition(preconditioned, precondition)
				countingClient = &applyCountingClient{Client: k8sClient}
				_, err = binding.apply(testCtx, countingClient, preconditioned)
				Expect(err).To(HaveOccurred(), "stale %s should reach the API server", precondition)
				Expect(countingClient.applyCalls).To(Equal(1), "stale %s must not be skipped", precondition)
			}
		},
		Entry("RoleBinding", roleBindingPatchTestCase),
		Entry("ClusterRoleBinding", clusterRoleBindingPatchTestCase),
	)

	// -----------------------------------------------------------------------
	// ServiceAccount
	// -----------------------------------------------------------------------
	Context("PatchApplyServiceAccount", func() {
		It("should apply when ServiceAccount already matches and Always is requested", func() {
			ac := ssa.ServiceAccountWith("ph-always-sa", "default",
				map[string]string{"shared": "desired"}, true).
				WithAnnotations(map[string]string{"source": "desired"})

			_, err := ssa.PatchApplyServiceAccount(testCtx, k8sClient, ac, ssa.FieldOwnerFor("ph-always-bd"))
			Expect(err).NotTo(HaveOccurred())

			countingClient := &applyCountingClient{Client: k8sClient}
			result, err := ssa.PatchApplyServiceAccountAlways(testCtx, countingClient, ac, ssa.FieldOwnerFor("ph-always-bd"))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(countingClient.applyCalls).To(Equal(1))
		})

		It("should return conflict when another manager owns ServiceAccount fields", func() {
			externalAC := ssa.ServiceAccountWith("ph-conflict-sa", "default",
				map[string]string{"shared": "external"}, false).
				WithAnnotations(map[string]string{"source": "external"})
			err := k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac := ssa.ServiceAccountWith("ph-conflict-sa", "default",
				map[string]string{"shared": "desired"}, true).
				WithAnnotations(map[string]string{"source": "desired"})
			result, err := ssa.PatchApplyServiceAccount(testCtx, k8sClient, ac, ssa.FieldOwnerFor("ph-conflict-bd"))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())
			Expect(result).To(Equal(ssa.PatchApplyResult(0)))

			var sa corev1.ServiceAccount
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: "ph-conflict-sa", Namespace: "default"}, &sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("shared", "external"))
			Expect(sa.Annotations).To(HaveKeyWithValue("source", "external"))
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
		})

		It("should skip matching ServiceAccounts owned by another manager", func() {
			externalAC := ssa.ServiceAccountWith("ph-force-matching-sa", "default",
				map[string]string{"shared": "desired"}, true).
				WithAnnotations(map[string]string{"source": "desired"})
			err := k8sClient.Apply(testCtx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac := ssa.ServiceAccountWith("ph-force-matching-sa", "default",
				map[string]string{"shared": "desired"}, true).
				WithAnnotations(map[string]string{"source": "desired"})
			result, err := ssa.PatchApplyServiceAccount(testCtx, k8sClient, ac, ssa.FieldOwnerFor("ph-force-matching-bd"))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		})

		It("should return conflict when a ServiceAccount appears during create apply", func() {
			name := types.NamespacedName{Name: "ph-create-race-sa", Namespace: "default"}
			racingClient := &serviceAccountCreateRaceClient{Client: k8sClient, namespacedName: name}

			ac := ssa.ServiceAccountWith(name.Name, name.Namespace,
				map[string]string{"shared": "desired"}, true).
				WithAnnotations(map[string]string{"source": "desired"})
			result, err := ssa.PatchApplyServiceAccount(testCtx, racingClient, ac, ssa.FieldOwnerFor("ph-race-bd"))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue())
			Expect(result).To(Equal(ssa.PatchApplyResult(0)))

			var sa corev1.ServiceAccount
			Expect(k8sClient.Get(testCtx, name, &sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("shared", "external"))
			Expect(sa.Annotations).To(HaveKeyWithValue("source", "external"))
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
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

type applyCountingClient struct {
	client.Client
	applyCalls int
}

func (c *applyCountingClient) Apply(
	ctx context.Context,
	obj runtime.ApplyConfiguration,
	opts ...client.ApplyOption,
) error {
	c.applyCalls++
	return c.Client.Apply(ctx, obj, opts...)
}

type clusterRolePruneConflictClient struct {
	client.Client
	name        string
	staleLabels map[string]string
	staleRules  []rbacv1.PolicyRule
	applyCalls  int
	conflicted  bool
	returnStale bool
}

func (c *clusterRolePruneConflictClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if c.returnStale && key.Name == c.name {
		if cr, ok := obj.(*rbacv1.ClusterRole); ok {
			cr.ObjectMeta = metav1.ObjectMeta{
				Name:   c.name,
				Labels: c.staleLabels,
			}
			cr.Rules = c.staleRules
			return nil
		}
	}

	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *clusterRolePruneConflictClient) Apply(
	ctx context.Context,
	obj runtime.ApplyConfiguration,
	opts ...client.ApplyOption,
) error {
	c.applyCalls++
	if !c.conflicted {
		c.conflicted = true
		c.returnStale = true
		return apierrors.NewConflict(
			schema.GroupResource{Group: rbacv1.GroupName, Resource: "clusterroles"},
			c.name,
			errors.New("injected conflict"),
		)
	}

	return c.Client.Apply(ctx, obj, opts...)
}

type serviceAccountCreateRaceClient struct {
	client.Client
	namespacedName   types.NamespacedName
	reportNotFound   bool
	injectedConflict bool
}

func (c *serviceAccountCreateRaceClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if key == c.namespacedName && !c.reportNotFound {
		c.reportNotFound = true
		return apierrors.NewNotFound(schema.GroupResource{Resource: "serviceaccounts"}, key.Name)
	}

	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *serviceAccountCreateRaceClient) Apply(
	ctx context.Context,
	obj runtime.ApplyConfiguration,
	opts ...client.ApplyOption,
) error {
	if c.reportNotFound && !c.injectedConflict {
		c.injectedConflict = true
		externalAC := ssa.ServiceAccountWith(c.namespacedName.Name, c.namespacedName.Namespace,
			map[string]string{"shared": "external"}, false).
			WithAnnotations(map[string]string{"source": "external"})
		if err := c.Client.Apply(ctx, externalAC, client.FieldOwner("external-agent"), client.ForceOwnership); err != nil {
			return err
		}
	}

	return c.Client.Apply(ctx, obj, opts...)
}

type bindingPatchTestCase struct {
	label       string
	roleBinding bool
}

var (
	roleBindingPatchTestCase        = bindingPatchTestCase{label: "rb", roleBinding: true}
	clusterRoleBindingPatchTestCase = bindingPatchTestCase{label: "crb"}
)

func newBindingPatchConfig(
	binding bindingPatchTestCase,
	name string,
	subjects []rbacv1.Subject,
	roleRef rbacv1.RoleRef,
	annotations map[string]string,
	ownerRefs []metav1.OwnerReference,
	includeSubjects bool,
	includeRoleRef bool,
) runtime.ApplyConfiguration {
	var ac runtime.ApplyConfiguration
	if binding.roleBinding {
		roleBinding := ssa.RoleBindingWithSubjectsAndRoleRef(name, "default", nil, subjects, roleRef)
		if !includeSubjects {
			roleBinding.Subjects = nil
		}
		if !includeRoleRef {
			roleBinding.RoleRef = nil
		}
		if len(annotations) > 0 {
			roleBinding.WithAnnotations(annotations)
		}
		for i := range ownerRefs {
			ref := ownerRefs[i]
			roleBinding.WithOwnerReferences(
				metav1ac.OwnerReference().
					WithAPIVersion(ref.APIVersion).
					WithKind(ref.Kind).
					WithName(ref.Name).
					WithUID(ref.UID),
			)
		}
		ac = roleBinding
	} else {
		clusterRoleBinding := ssa.ClusterRoleBindingWithSubjectsAndRoleRef(name, nil, subjects, roleRef)
		if !includeSubjects {
			clusterRoleBinding.Subjects = nil
		}
		if !includeRoleRef {
			clusterRoleBinding.RoleRef = nil
		}
		if len(annotations) > 0 {
			clusterRoleBinding.WithAnnotations(annotations)
		}
		for i := range ownerRefs {
			ref := ownerRefs[i]
			clusterRoleBinding.WithOwnerReferences(
				metav1ac.OwnerReference().
					WithAPIVersion(ref.APIVersion).
					WithKind(ref.Kind).
					WithName(ref.Name).
					WithUID(ref.UID),
			)
		}
		ac = clusterRoleBinding
	}

	return ac
}

func (binding bindingPatchTestCase) apply(
	ctx context.Context,
	c client.Client,
	ac runtime.ApplyConfiguration,
	opts ...client.ApplyOption,
) (ssa.PatchApplyResult, error) {
	if binding.roleBinding {
		return ssa.PatchApplyRoleBinding(ctx, c, ac.(*rbacv1ac.RoleBindingApplyConfiguration), opts...)
	}
	return ssa.PatchApplyClusterRoleBinding(ctx, c, ac.(*rbacv1ac.ClusterRoleBindingApplyConfiguration), opts...)
}

func (binding bindingPatchTestCase) get(ctx context.Context, c client.Client, name string) client.Object {
	if binding.roleBinding {
		object := &rbacv1.RoleBinding{}
		Expect(c.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, object)).To(Succeed())
		return object
	}
	object := &rbacv1.ClusterRoleBinding{}
	Expect(c.Get(ctx, types.NamespacedName{Name: name}, object)).To(Succeed())
	return object
}

func setBindingPrecondition(ac runtime.ApplyConfiguration, precondition string) {
	switch binding := ac.(type) {
	case *rbacv1ac.RoleBindingApplyConfiguration:
		switch precondition {
		case "uid":
			binding.WithUID(types.UID("stale-uid"))
		case "resourceVersion":
			binding.WithResourceVersion("stale-resource-version")
		}
	case *rbacv1ac.ClusterRoleBindingApplyConfiguration:
		switch precondition {
		case "uid":
			binding.WithUID(types.UID("stale-uid"))
		case "resourceVersion":
			binding.WithResourceVersion("stale-resource-version")
		}
	}
}

type managedFieldsOmittingClient struct {
	client.Client
}

func (c *managedFieldsOmittingClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if err := c.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	obj.SetManagedFields(nil)
	return nil
}
