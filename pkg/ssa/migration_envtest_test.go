// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/auth-operator/pkg/ssa"
)

var _ = Describe("SSA wrapper migration characterization", Label("ssa-migration"), func() {
	var namespace string
	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "ssa-wrapper-"}}
		Expect(k8sClient.Create(testCtx, ns)).To(Succeed())
		namespace = ns.Name
		DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, ns)).To(Succeed()) })
	})

	DescribeTable("role wrappers forward dry-run and stale preconditions and Always never skips",
		func(clusterScoped bool) {
			name := fmt.Sprintf("ssa-options-%d", time.Now().UnixNano())
			rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
			c := &applyCountingClient{Client: k8sClient}
			var obj client.Object = &rbacv1.ClusterRole{}
			var desired runtime.ApplyConfiguration
			var apply func(context.Context, client.Client, []client.ApplyOption) (ssa.PatchApplyResult, error)
			var always func() (ssa.PatchApplyResult, error)
			if clusterScoped {
				ac := ssa.ClusterRoleWithLabelsAndRules(name, nil, rules)
				desired = ac
				apply = func(ctx context.Context, c client.Client, opts []client.ApplyOption) (ssa.PatchApplyResult, error) {
					return ssa.PatchApplyClusterRole(ctx, c, ac, opts...)
				}
				always = func() (ssa.PatchApplyResult, error) {
					return ssa.PatchApplyClusterRoleAlways(testCtx, c, ac, client.ForceOwnership)
				}
			} else {
				obj = &rbacv1.Role{}
				ac := ssa.RoleWithLabelsAndRules(name, namespace, nil, rules)
				desired = ac
				apply = func(ctx context.Context, c client.Client, opts []client.ApplyOption) (ssa.PatchApplyResult, error) {
					return ssa.PatchApplyRole(ctx, c, ac, opts...)
				}
				always = func() (ssa.PatchApplyResult, error) {
					return ssa.PatchApplyRoleAlways(testCtx, c, ac, client.ForceOwnership)
				}
			}
			_, err := apply(testCtx, c, []client.ApplyOption{client.ForceOwnership})
			Expect(err).NotTo(HaveOccurred())
			key := client.ObjectKey{Name: name}
			if !clusterScoped {
				key.Namespace = namespace
			}
			Expect(k8sClient.Get(testCtx, key, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, obj)).To(Succeed()) })
			rv := obj.GetResourceVersion()
			c.applyCalls = 0
			for _, opts := range [][]client.ApplyOption{{client.DryRunAll}, {client.DryRunAll, client.ForceOwnership}} {
				result, err := apply(testCtx, c, opts)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			}
			Expect(c.applyCalls).To(Equal(2))
			Expect(k8sClient.Get(testCtx, key, obj)).To(Succeed())
			Expect(obj.GetResourceVersion()).To(Equal(rv))
			result, err := always()
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ssa.PatchApplyResultPatched))
			Expect(c.applyCalls).To(Equal(3))
			switch ac := desired.(type) {
			case *rbacv1ac.ClusterRoleApplyConfiguration:
				ac.WithResourceVersion("1")
			case *rbacv1ac.RoleApplyConfiguration:
				ac.WithResourceVersion("1")
			}
			_, err = apply(testCtx, c, []client.ApplyOption{client.ForceOwnership})
			Expect(apierrors.IsConflict(err)).To(BeTrue())
			Expect(c.applyCalls).To(Equal(4))
			switch ac := desired.(type) {
			case *rbacv1ac.ClusterRoleApplyConfiguration:
				ac.ResourceVersion = nil
				ac.WithUID("wrong-uid")
			case *rbacv1ac.RoleApplyConfiguration:
				ac.ResourceVersion = nil
				ac.WithUID("wrong-uid")
			}
			_, err = apply(testCtx, c, []client.ApplyOption{client.ForceOwnership})
			Expect(err).To(HaveOccurred())
			Expect(c.applyCalls).To(Equal(5))
			Expect(k8sClient.Get(testCtx, key, obj)).To(Succeed())
			Expect(obj.GetUID()).NotTo(Equal(types.UID("wrong-uid")))
		},
		Entry("ClusterRole", true),
		Entry("Role", false),
	)

	It("pins the current ServiceAccount precondition skip gap while Always forwards it", func() {
		c := &applyCountingClient{Client: k8sClient}
		ac := ssa.ServiceAccountWith("preconditions", namespace, nil, true)
		_, err := ssa.PatchApplyServiceAccount(testCtx, c, ac, ssa.FieldOwner)
		Expect(err).NotTo(HaveOccurred())
		sa := &corev1.ServiceAccount{}
		key := client.ObjectKey{Name: "preconditions", Namespace: namespace}
		Expect(k8sClient.Get(testCtx, key, sa)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, sa)).To(Succeed()) })
		c.applyCalls = 0
		ac.WithResourceVersion("1")
		result, err := ssa.PatchApplyServiceAccount(testCtx, c, ac, ssa.FieldOwner)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		Expect(c.applyCalls).To(BeZero())
		_, err = ssa.PatchApplyServiceAccountAlways(testCtx, c, ac, ssa.FieldOwner)
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		Expect(c.applyCalls).To(Equal(1))
		ac.ResourceVersion = nil
		ac.WithUID("wrong-uid")
		result, err = ssa.PatchApplyServiceAccount(testCtx, c, ac, ssa.FieldOwner)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ssa.PatchApplyResultSkipped))
		Expect(c.applyCalls).To(Equal(1))
		_, err = ssa.PatchApplyServiceAccountAlways(testCtx, c, ac, ssa.FieldOwner)
		Expect(err).To(HaveOccurred())
		Expect(c.applyCalls).To(Equal(2))
		Expect(k8sClient.Get(testCtx, key, sa)).To(Succeed())
		Expect(sa.AutomountServiceAccountToken).To(HaveValue(BeTrue()))
	})

	It("pins the current label-pruning dry-run gap without changing RBAC rules", func() {
		name := fmt.Sprintf("ssa-prune-dryrun-%d", time.Now().UnixNano())
		rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
		desired := ssa.ClusterRoleWithLabelsAndRules(name, nil, rules)
		_, err := ssa.PatchApplyClusterRole(testCtx, k8sClient, desired, client.ForceOwnership)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Apply(testCtx, rbacv1ac.ClusterRole(name).WithLabels(map[string]string{"remove": "foreign"}),
			client.FieldOwner("foreign-prune"))).To(Succeed())
		role := &rbacv1.ClusterRole{}
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: name}, role)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, role)).To(Succeed()) })
		Expect(role.Labels).To(HaveKey("remove"))
		result, err := ssa.PatchApplyClusterRolePruningLabels(testCtx, k8sClient, desired,
			func(key string) bool { return key == "remove" }, client.ForceOwnership, client.DryRunAll)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ssa.PatchApplyResultPatched))
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: name}, role)).To(Succeed())
		// The SSA write is dry-run, but main's preliminary merge patch is not.
		Expect(role.Labels).NotTo(HaveKey("remove"))
		Expect(role.Rules).To(Equal(rules))
	})
})
