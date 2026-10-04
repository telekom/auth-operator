// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/auth-operator/pkg/ssa"
)

const genericTestNamespace = "default"

var genericSAFieldOwner = ssa.FieldOwnerFor("generic-applier-owner")

// descriptorCase drives one predefined Applier descriptor through its
// exported PatchApply* wrapper.
type descriptorCase struct {
	kind       string
	namespaced bool
	// build returns a fresh desired apply configuration and its metadata.
	build  func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration)
	patch  func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, opts ...client.ApplyOption) (ssa.PatchApplyResult, error)
	newObj func() client.Object
	// forwardsApplyOptions is false for ServiceAccounts, which take only a field owner.
	forwardsApplyOptions bool
}

func (tc descriptorCase) key(name string) types.NamespacedName {
	if tc.namespaced {
		return types.NamespacedName{Name: name, Namespace: genericTestNamespace}
	}
	return types.NamespacedName{Name: name}
}

var (
	genericRules   = []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
	genericRoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"}
	genericSubject = []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "generic-group"}}
)

var descriptorCases = []descriptorCase{
	{
		kind: "ClusterRole",
		build: func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration) {
			ac := ssa.ClusterRoleWithLabelsAndRules(name, labels, genericRules)
			return ac, ac.ObjectMetaApplyConfiguration
		},
		patch: func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, opts ...client.ApplyOption) (ssa.PatchApplyResult, error) {
			if always {
				return ssa.PatchApplyClusterRoleAlways(ctx, c, ac.(*rbacv1ac.ClusterRoleApplyConfiguration), opts...)
			}
			return ssa.PatchApplyClusterRole(ctx, c, ac.(*rbacv1ac.ClusterRoleApplyConfiguration), opts...)
		},
		newObj:               func() client.Object { return &rbacv1.ClusterRole{} },
		forwardsApplyOptions: true,
	},
	{
		kind:       "Role",
		namespaced: true,
		build: func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration) {
			ac := ssa.RoleWithLabelsAndRules(name, genericTestNamespace, labels, genericRules)
			return ac, ac.ObjectMetaApplyConfiguration
		},
		patch: func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, opts ...client.ApplyOption) (ssa.PatchApplyResult, error) {
			if always {
				return ssa.PatchApplyRoleAlways(ctx, c, ac.(*rbacv1ac.RoleApplyConfiguration), opts...)
			}
			return ssa.PatchApplyRole(ctx, c, ac.(*rbacv1ac.RoleApplyConfiguration), opts...)
		},
		newObj:               func() client.Object { return &rbacv1.Role{} },
		forwardsApplyOptions: true,
	},
	{
		kind: "ClusterRoleBinding",
		build: func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration) {
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef(name, labels, genericSubject, genericRoleRef)
			return ac, ac.ObjectMetaApplyConfiguration
		},
		patch: func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, opts ...client.ApplyOption) (ssa.PatchApplyResult, error) {
			if always {
				return ssa.PatchApplyClusterRoleBindingAlways(ctx, c, ac.(*rbacv1ac.ClusterRoleBindingApplyConfiguration), opts...)
			}
			return ssa.PatchApplyClusterRoleBinding(ctx, c, ac.(*rbacv1ac.ClusterRoleBindingApplyConfiguration), opts...)
		},
		newObj:               func() client.Object { return &rbacv1.ClusterRoleBinding{} },
		forwardsApplyOptions: true,
	},
	{
		kind:       "RoleBinding",
		namespaced: true,
		build: func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration) {
			ac := ssa.RoleBindingWithSubjectsAndRoleRef(name, genericTestNamespace, labels, genericSubject, genericRoleRef)
			return ac, ac.ObjectMetaApplyConfiguration
		},
		patch: func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, opts ...client.ApplyOption) (ssa.PatchApplyResult, error) {
			if always {
				return ssa.PatchApplyRoleBindingAlways(ctx, c, ac.(*rbacv1ac.RoleBindingApplyConfiguration), opts...)
			}
			return ssa.PatchApplyRoleBinding(ctx, c, ac.(*rbacv1ac.RoleBindingApplyConfiguration), opts...)
		},
		newObj:               func() client.Object { return &rbacv1.RoleBinding{} },
		forwardsApplyOptions: true,
	},
	{
		kind:       "ServiceAccount",
		namespaced: true,
		build: func(name string, labels map[string]string) (runtime.ApplyConfiguration, *metav1ac.ObjectMetaApplyConfiguration) {
			ac := ssa.ServiceAccountWith(name, genericTestNamespace, labels, false)
			return ac, ac.ObjectMetaApplyConfiguration
		},
		patch: func(ctx context.Context, c client.Client, ac runtime.ApplyConfiguration, always bool, _ ...client.ApplyOption) (ssa.PatchApplyResult, error) {
			if always {
				return ssa.PatchApplyServiceAccountAlways(ctx, c, ac.(*corev1ac.ServiceAccountApplyConfiguration), genericSAFieldOwner)
			}
			return ssa.PatchApplyServiceAccount(ctx, c, ac.(*corev1ac.ServiceAccountApplyConfiguration), genericSAFieldOwner)
		},
		newObj: func() client.Object { return &corev1.ServiceAccount{} },
	},
}

// descriptorScenario runs against a freshly created object named name.
type descriptorScenario struct {
	name string
	// requiresApplyOptions skips the scenario for descriptors without apply options.
	requiresApplyOptions bool
	run                  func(tc descriptorCase, name string)
}

var descriptorScenarios = []descriptorScenario{
	{
		name: "skips an unchanged object",
		run: func(tc descriptorCase, name string) {
			ac, _ := tc.build(name, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(counting.applyCalls).To(BeZero())
		},
	},
	{
		name: "patches drifted values",
		run: func(tc descriptorCase, name string) {
			ac, _ := tc.build(name, map[string]string{"app": "generic", "tier": "drifted"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))
			live := tc.newObj()
			Expect(k8sClient.Get(testCtx, tc.key(name), live)).To(Succeed())
			Expect(live.GetLabels()).To(HaveKeyWithValue("tier", "drifted"))
		},
	},
	{
		name: "skips matching values owned by a foreign manager without force",
		run: func(tc descriptorCase, name string) {
			foreignName := name + "-foreign"
			foreign, _ := tc.build(foreignName, map[string]string{"app": "generic"})
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			ac, _ := tc.build(foreignName, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(counting.applyCalls).To(BeZero())
		},
	},
	{
		name:                 "reclaims matching values owned by a foreign manager with force",
		requiresApplyOptions: true,
		run: func(tc descriptorCase, name string) {
			foreignName := name + "-foreign"
			foreign, _ := tc.build(foreignName, map[string]string{"app": "generic"})
			Expect(k8sClient.Apply(testCtx, foreign, client.FieldOwner("external-agent"), client.ForceOwnership)).To(Succeed())

			ac, _ := tc.build(foreignName, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))
			live := tc.newObj()
			Expect(k8sClient.Get(testCtx, tc.key(foreignName), live)).To(Succeed())
			Expect(ssa.ManagedBy(live, ssa.FieldOwner, metav1.ManagedFieldsOperationApply)).To(BeTrue())
		},
	},
	{
		name: "applies to prune a field the manager still owns",
		run: func(tc descriptorCase, name string) {
			ac, _ := tc.build(name, map[string]string{"app": "generic", "remove": "true"})
			_, err := tc.patch(testCtx, k8sClient, ac, false, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())

			ac, _ = tc.build(name, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false, client.ForceOwnership)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))
			live := tc.newObj()
			Expect(k8sClient.Get(testCtx, tc.key(name), live)).To(Succeed())
			Expect(live.GetLabels()).NotTo(HaveKey("remove"))
			Expect(live.GetLabels()).To(HaveKeyWithValue("app", "generic"))
		},
	},
	{
		name:                 "never skips a forced dry-run apply",
		requiresApplyOptions: true,
		run: func(tc descriptorCase, name string) {
			ac, _ := tc.build(name, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false, client.ForceOwnership, client.DryRunAll)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))
		},
	},
	{
		name: "forwards stale preconditions instead of skipping",
		run: func(tc descriptorCase, name string) {
			ac, meta := tc.build(name, map[string]string{"app": "generic"})
			meta.WithResourceVersion("1")
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, false)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue(), "unexpected error: %v", err)
			Expect(err.Error()).To(HavePrefix("patch " + tc.kind + " "))
			Expect(result).To(Equal(ssa.PatchApplyResult(0)))
			Expect(counting.applyCalls).To(Equal(1))
		},
	},
	{
		name: "applies an unchanged object when always is requested",
		run: func(tc descriptorCase, name string) {
			ac, _ := tc.build(name, map[string]string{"app": "generic"})
			counting := &applyCountingClient{Client: k8sClient}
			result, err := tc.patch(testCtx, counting, ac, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))
		},
	},
}

func descriptorEntries() []TableEntry {
	var entries []TableEntry
	for _, tc := range descriptorCases {
		for i, scenario := range descriptorScenarios {
			if scenario.requiresApplyOptions && !tc.forwardsApplyOptions {
				continue
			}
			entries = append(entries, Entry(tc.kind+": "+scenario.name, tc, i))
		}
	}
	return entries
}

var _ = Describe("Generic Applier", func() {
	DescribeTable("predefined descriptors",
		func(tc descriptorCase, scenarioIndex int) {
			name := fmt.Sprintf("generic-%s-%d", strings.ToLower(tc.kind), scenarioIndex)
			ac, _ := tc.build(name, map[string]string{"app": "generic"})
			result, err := tc.patch(testCtx, k8sClient, ac, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			descriptorScenarios[scenarioIndex].run(tc, name)
		},
		descriptorEntries(),
	)

	Context("with a third-party ConfigMap descriptor", func() {
		const owner = "third-party-operator"

		configMapApplier := ssa.Applier[*corev1.ConfigMap, *corev1ac.ConfigMapApplyConfiguration]{
			Kind:       "ConfigMap",
			Namespaced: true,
			New:        func() *corev1.ConfigMap { return &corev1.ConfigMap{} },
			Matches: func(existing *corev1.ConfigMap, desired *corev1ac.ConfigMapApplyConfiguration) bool {
				for key, value := range desired.Labels {
					if existing.Labels[key] != value {
						return false
					}
				}
				for key, value := range desired.Data {
					if existing.Data[key] != value {
						return false
					}
				}
				return true
			},
			Extract: corev1ac.ExtractConfigMap,
			Labels:  func(desired *corev1ac.ConfigMapApplyConfiguration) map[string]string { return desired.Labels },
		}

		desired := func(name string, data map[string]string) *corev1ac.ConfigMapApplyConfiguration {
			return corev1ac.ConfigMap(name, genericTestNamespace).
				WithLabels(map[string]string{"app": "third-party"}).
				WithData(data)
		}

		It("creates, skips, patches drift and prunes owned fields", func() {
			name := "generic-third-party-cm"
			counting := &applyCountingClient{Client: k8sClient}

			result, err := configMapApplier.PatchApply(testCtx, counting, desired(name, map[string]string{"a": "1", "b": "2"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultCreated))

			result, err = configMapApplier.PatchApply(testCtx, counting, desired(name, map[string]string{"a": "1", "b": "2"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
			Expect(counting.applyCalls).To(Equal(1))

			result, err = configMapApplier.PatchApply(testCtx, counting, desired(name, map[string]string{"a": "changed", "b": "2"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(2))

			// Values still match after dropping "b", but the manager owns it, so
			// the apply must be sent for SSA to prune it.
			result, err = configMapApplier.PatchApply(testCtx, counting, desired(name, map[string]string{"a": "changed"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(3))

			var cm corev1.ConfigMap
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: name, Namespace: genericTestNamespace}, &cm)).To(Succeed())
			Expect(cm.Data).To(Equal(map[string]string{"a": "changed"}))
			Expect(ssa.ManagedBy(&cm, owner, metav1.ManagedFieldsOperationApply)).To(BeTrue())
			Expect(ssa.ManagedBy(&cm, owner, metav1.ManagedFieldsOperationUpdate)).To(BeFalse())
			Expect(ssa.ManagedBy(&cm, "someone-else", metav1.ManagedFieldsOperationApply)).To(BeFalse())
		})

		It("prunes labels selected by ShouldPruneLabel that SSA cannot prune", func() {
			name := "generic-third-party-prune-cm"
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: genericTestNamespace,
				Labels: map[string]string{"app": "third-party", "legacy.example.com/owned": "true", "foreign": "keep"},
			}}
			Expect(k8sClient.Create(testCtx, cm)).To(Succeed())

			applier := configMapApplier
			applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
			result, err := applier.PatchApply(testCtx, k8sClient, desired(name, nil), false, client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: name, Namespace: genericTestNamespace}, cm)).To(Succeed())
			Expect(cm.Labels).To(Equal(map[string]string{"app": "third-party", "foreign": "keep"}))
		})

		It("does not persist label pruning for dry-run applies", func() {
			name := "generic-third-party-prune-dryrun-cm"
			labels := map[string]string{"app": "third-party", "legacy.example.com/owned": "true"}
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: genericTestNamespace, Labels: labels,
			}}
			Expect(k8sClient.Create(testCtx, cm)).To(Succeed())

			applier := configMapApplier
			applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
			_, err := applier.PatchApply(testCtx, k8sClient, desired(name, nil), false,
				client.FieldOwner(owner), client.DryRunAll)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: name, Namespace: genericTestNamespace}, cm)).To(Succeed())
			Expect(cm.Labels).To(Equal(labels))
		})

		It("does not treat a prune conflict as converged while owned fields still need pruning", func() {
			name := "generic-third-party-prune-conflict-cm"
			_, err := configMapApplier.PatchApply(testCtx, k8sClient, desired(name, map[string]string{"a": "1", "b": "2"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			cm := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: name, Namespace: genericTestNamespace}
			Expect(k8sClient.Get(testCtx, key, cm)).To(Succeed())
			orig := cm.DeepCopy()
			cm.Labels["legacy.example.com/owned"] = "true"
			Expect(k8sClient.Patch(testCtx, cm, client.MergeFrom(orig))).To(Succeed())

			applier := configMapApplier
			applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
			_, err = applier.PatchApply(testCtx, &applyConflictClient{Client: k8sClient}, desired(name, map[string]string{"a": "1"}), false,
				client.FieldOwner(owner))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue(), "unexpected error: %v", err)
		})

		It("preserves conflicts when alwaysApply requires an authorization check", func() {
			name := "generic-third-party-prune-always-cm"
			_, err := configMapApplier.PatchApply(testCtx, k8sClient, desired(name, map[string]string{"a": "1"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			cm := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: name, Namespace: genericTestNamespace}
			Expect(k8sClient.Get(testCtx, key, cm)).To(Succeed())
			orig := cm.DeepCopy()
			cm.Labels["legacy.example.com/owned"] = "true"
			Expect(k8sClient.Patch(testCtx, cm, client.MergeFrom(orig))).To(Succeed())

			applier := configMapApplier
			applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
			_, err = applier.PatchApply(testCtx, &applyConflictClient{Client: k8sClient}, desired(name, map[string]string{"a": "1"}), true,
				client.FieldOwner(owner))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsConflict(err)).To(BeTrue(), "unexpected error: %v", err)
		})

		DescribeTable("preserves precondition conflicts after pruning labels",
			func(precondition string) {
				name := "generic-third-party-prune-stale-" + precondition
				_, err := configMapApplier.PatchApply(testCtx, k8sClient, desired(name, map[string]string{"a": "1"}), false,
					client.FieldOwner(owner))
				Expect(err).NotTo(HaveOccurred())
				cm := &corev1.ConfigMap{}
				key := types.NamespacedName{Name: name, Namespace: genericTestNamespace}
				Expect(k8sClient.Get(testCtx, key, cm)).To(Succeed())
				orig := cm.DeepCopy()
				cm.Labels["legacy.example.com/owned"] = "true"
				Expect(k8sClient.Patch(testCtx, cm, client.MergeFrom(orig))).To(Succeed())

				ac := desired(name, map[string]string{"a": "1"})
				if precondition == "uid" {
					ac.WithUID(types.UID("stale-uid"))
				} else {
					ac.WithResourceVersion("1")
				}
				applier := configMapApplier
				applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
				c := k8sClient
				if precondition == "uid" {
					c = &applyConflictClient{Client: k8sClient}
				}
				_, err = applier.PatchApply(testCtx, c, ac, false, client.FieldOwner(owner))
				Expect(err).To(HaveOccurred())
				Expect(apierrors.IsConflict(err)).To(BeTrue(), "unexpected error: %v", err)
			},
			Entry("UID", "uid"),
			Entry("resourceVersion", "resourceversion"),
		)

		It("still applies to prune owned fields after pruning labels", func() {
			name := "generic-third-party-prune-owned-cm"
			_, err := configMapApplier.PatchApply(testCtx, k8sClient, desired(name, map[string]string{"a": "1", "b": "2"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			cm := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: name, Namespace: genericTestNamespace}
			Expect(k8sClient.Get(testCtx, key, cm)).To(Succeed())
			orig := cm.DeepCopy()
			cm.Labels["legacy.example.com/owned"] = "true"
			Expect(k8sClient.Patch(testCtx, cm, client.MergeFrom(orig))).To(Succeed())

			applier := configMapApplier
			applier.ShouldPruneLabel = func(key string) bool { return key == "legacy.example.com/owned" }
			counting := &applyCountingClient{Client: k8sClient}
			result, err := applier.PatchApply(testCtx, counting, desired(name, map[string]string{"a": "1"}), false,
				client.FieldOwner(owner))
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(counting.applyCalls).To(Equal(1))

			Expect(k8sClient.Get(testCtx, key, cm)).To(Succeed())
			Expect(cm.Labels).To(Equal(map[string]string{"app": "third-party"}))
			Expect(cm.Data).To(Equal(map[string]string{"a": "1"}))
		})

		It("validates the apply configuration and field owner", func() {
			_, err := configMapApplier.PatchApply(testCtx, k8sClient, nil, false, client.FieldOwner(owner))
			Expect(err).To(MatchError("configMap ApplyConfiguration must have a name"))

			_, err = configMapApplier.PatchApply(testCtx, k8sClient, corev1ac.ConfigMap("", genericTestNamespace), false,
				client.FieldOwner(owner))
			Expect(err).To(MatchError("configMap ApplyConfiguration name must not be empty"))

			_, err = configMapApplier.PatchApply(testCtx, k8sClient, corev1ac.ConfigMap("x", ""), false, client.FieldOwner(owner))
			Expect(err).To(MatchError("configMap ApplyConfiguration must have a namespace"))

			_, err = configMapApplier.PatchApply(testCtx, k8sClient, corev1ac.ConfigMap("x", genericTestNamespace), false)
			Expect(err).To(MatchError("fieldOwner must not be empty"))
		})
	})

	Context("StatusApplier", func() {
		namespaceStatusApplier := ssa.StatusApplier[*corev1.Namespace, *corev1ac.NamespaceApplyConfiguration]{
			Kind:       "Namespace",
			FieldOwner: "third-party-operator",
			New:        func() *corev1.Namespace { return &corev1.Namespace{} },
			Equal: func(cached, desired *corev1.Namespace) bool {
				return len(cached.Status.Conditions) == len(desired.Status.Conditions) &&
					(len(cached.Status.Conditions) == 0 ||
						cached.Status.Conditions[0].Reason == desired.Status.Conditions[0].Reason)
			},
			ApplyConfiguration: func(ns *corev1.Namespace) *corev1ac.NamespaceApplyConfiguration {
				status := corev1ac.NamespaceStatus()
				for _, condition := range ns.Status.Conditions {
					status.WithConditions(corev1ac.NamespaceCondition().
						WithType(condition.Type).
						WithStatus(condition.Status).
						WithReason(condition.Reason).
						WithLastTransitionTime(metav1.Now()))
				}
				return corev1ac.Namespace(ns.Name).WithStatus(status)
			},
		}

		It("applies changed status and skips unchanged status", func() {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "generic-status-ns"}}
			Expect(k8sClient.Create(testCtx, ns)).To(Succeed())
			ns.Status.Conditions = []corev1.NamespaceCondition{{
				Type: "example.com/Ready", Status: corev1.ConditionTrue, Reason: "Reconciled",
			}}

			result, err := namespaceStatusApplier.PatchApply(testCtx, k8sClient, ns.DeepCopy())
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))

			result, err = namespaceStatusApplier.PatchApply(testCtx, k8sClient, ns.DeepCopy())
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultSkipped))

			_, err = namespaceStatusApplier.PatchApply(testCtx, k8sClient, nil)
			Expect(err).To(MatchError("namespace must not be nil"))
		})
	})
})

// applyConflictClient fails every apply with a Conflict.
type applyConflictClient struct {
	client.Client
}

func (c *applyConflictClient) Apply(context.Context, runtime.ApplyConfiguration, ...client.ApplyOption) error {
	return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "conflict", fmt.Errorf("injected"))
}
