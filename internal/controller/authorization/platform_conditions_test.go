// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
)

type platformConditionObject interface {
	client.Object
	conditions.Setter
}

var _ = Describe("Platform condition status characterization", Label("integration", "platform"), func() {
	It("round-trips the Namespace adapter and observes API-server deletion state", func() {
		ctx := context.Background()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "platform-condition-ns-"}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, ns))).To(Succeed()) })
		wrapped := conditions.NewNamespaceWrapper(ns)
		oldTime := metav1.NewTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
		conditions.Set(wrapped, &metav1.Condition{
			Type: "PlatformBlocked", Status: metav1.ConditionTrue,
			Reason: "Blocked", Message: "pending bindings", ObservedGeneration: 42,
			LastTransitionTime: oldTime,
		})
		Expect(k8sClient.Status().Update(ctx, ns)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(ns), ns)).To(Succeed())
		actual := conditions.Get(wrapped, "PlatformBlocked")
		Expect(actual.Status).To(Equal(metav1.ConditionTrue))
		Expect(actual.LastTransitionTime.Time.Equal(oldTime.Time)).To(BeTrue())
		// NamespaceCondition has no observedGeneration field.
		Expect(actual.ObservedGeneration).To(BeZero())
		conditions.MarkFalse(wrapped, "PlatformBlocked", 0, "Unblocked", "bindings removed")
		Expect(k8sClient.Status().Update(ctx, ns)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(ns), ns)).To(Succeed())
		Expect(conditions.IsFalse(wrapped, "PlatformBlocked")).To(BeTrue())
		Expect(conditions.GetLastTransitionTime(wrapped, "PlatformBlocked").After(oldTime.Time)).To(BeTrue())
		Expect(conditions.IsNamespaceActive(ns)).To(BeTrue())
		Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(ns), ns)).To(Succeed())
		Expect(conditions.IsNamespaceTerminating(ns)).To(BeTrue())
		Expect(conditions.IsNamespaceActive(ns)).To(BeFalse())
	})

	DescribeTable("round-trips condition transitions through every CRD status subresource",
		func(kind string) {
			ctx := context.Background()
			subjects := []rbacv1.Subject{{Kind: "User", APIGroup: rbacv1.GroupName, Name: "platform-user"}}
			policyRef := authorizationv1alpha1.RBACPolicyReference{Name: "platform-policy"}
			var obj platformConditionObject
			switch kind {
			case "RoleDefinition":
				obj = &authorizationv1alpha1.RoleDefinition{Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: authorizationv1alpha1.DefinitionClusterRole, TargetName: "platform-role",
				}}
			case "BindDefinition":
				obj = &authorizationv1alpha1.BindDefinition{Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "platform-binding", Subjects: subjects,
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
				}}
			case "WebhookAuthorizer":
				obj = &authorizationv1alpha1.WebhookAuthorizer{Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
					NonResourceRules:  []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}},
					AllowedPrincipals: []authorizationv1alpha1.Principal{{User: "platform-user"}},
				}}
			case "RBACPolicy":
				obj = &authorizationv1alpha1.RBACPolicy{Spec: authorizationv1alpha1.RBACPolicySpec{
					AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"default"}},
				}}
			case "RestrictedRoleDefinition":
				obj = &authorizationv1alpha1.RestrictedRoleDefinition{Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					PolicyRef: policyRef, TargetRole: authorizationv1alpha1.DefinitionClusterRole, TargetName: "platform-restricted-role",
				}}
			case "RestrictedBindDefinition":
				obj = &authorizationv1alpha1.RestrictedBindDefinition{Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					PolicyRef: policyRef, TargetName: "platform-restricted-binding", Subjects: subjects,
					ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
				}}
			default:
				Fail(fmt.Sprintf("unsupported kind %s", kind))
			}
			obj.SetGenerateName("platform-conditions-")
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			key := client.ObjectKeyFromObject(obj)
			roundTrip := func() {
				expected := append([]metav1.Condition(nil), obj.GetConditions()...)
				Expect(k8sClient.Status().Update(ctx, obj)).To(Succeed())
				Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
				actual := append([]metav1.Condition(nil), obj.GetConditions()...)
				for i := range actual {
					Expect(actual[i].LastTransitionTime.IsZero()).To(BeFalse())
					Expect(actual[i].ObservedGeneration).To(BeNumerically(">", 0))
					actual[i].LastTransitionTime.Time = actual[i].LastTransitionTime.UTC()
					expected[i].LastTransitionTime.Time = expected[i].LastTransitionTime.UTC()
				}
				Expect(actual).To(Equal(expected))
			}

			By("persisting reconciling, stalled, and ready with abnormal-true removal")
			gen := obj.GetGeneration()
			Expect(gen).To(BeNumerically(">", 0))
			conditions.MarkReconciling(obj, gen, "Progressing", "working")
			roundTrip()
			Expect(conditions.IsReconciling(obj)).To(BeTrue())
			Expect(conditions.IsReady(obj)).To(BeFalse())
			Expect(conditions.IsStalled(obj)).To(BeFalse())
			Expect(conditions.GetObservedGeneration(obj, conditions.ReadyConditionType)).To(Equal(gen))
			conditions.MarkStalled(obj, gen, "Failed", "retry required")
			roundTrip()
			Expect(conditions.IsStalled(obj)).To(BeTrue())
			Expect(conditions.Has(obj, conditions.ReconcilingConditionType)).To(BeFalse())
			conditions.MarkReady(obj, gen, "Succeeded", "complete")
			roundTrip()
			Expect(conditions.IsReady(obj)).To(BeTrue())
			Expect(conditions.Has(obj, conditions.ReconcilingConditionType)).To(BeFalse())
			Expect(conditions.Has(obj, conditions.StalledConditionType)).To(BeFalse())

			By("preserving alphabetical ordering, not Ready-first ordering")
			conditions.MarkUnknown(obj, "APlatform", gen, "Unknown", "not discovered")
			conditions.MarkNotReady(obj, gen, "Pending", "pending")
			conditions.MarkTrue(obj, "ZPlatform", gen, "Known", "discovered")
			roundTrip()
			Expect(obj.GetConditions()[0].Type).To(Equal("APlatform"))
			Expect(obj.GetConditions()[1].Type).To(Equal("Ready"))
			Expect(obj.GetConditions()[2].Type).To(Equal("ZPlatform"))
			Expect(conditions.IsUnknown(obj, "APlatform")).To(BeTrue())
			conditions.Delete(obj, "APlatform")
			conditions.Delete(obj, "ZPlatform")

			By("advancing the actual API-server generation after a spec change")
			switch typed := obj.(type) {
			case *authorizationv1alpha1.RoleDefinition:
				typed.Spec.RestrictedVerbs = []string{"delete"}
			case *authorizationv1alpha1.BindDefinition:
				typed.Spec.Subjects[0].Name = "platform-next-user"
			case *authorizationv1alpha1.WebhookAuthorizer:
				typed.Spec.AllowedPrincipals = []authorizationv1alpha1.Principal{{User: "platform-next-user"}}
			case *authorizationv1alpha1.RBACPolicy:
				typed.Spec.AppliesTo.Namespaces = []string{"kube-system"}
			case *authorizationv1alpha1.RestrictedRoleDefinition:
				typed.Spec.RestrictedVerbs = []string{"delete"}
			case *authorizationv1alpha1.RestrictedBindDefinition:
				typed.Spec.Subjects[0].Name = "platform-next-user"
			}
			Expect(k8sClient.Update(ctx, obj)).To(Succeed())
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			Expect(obj.GetGeneration()).To(Equal(gen + 1))
			Expect(conditions.GetObservedGeneration(obj, conditions.ReadyConditionType)).To(Equal(gen))

			By("pinning transition time changes for status, reason, message, and generation independently")
			oldTime := metav1.NewTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
			base := metav1.Condition{
				Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: gen,
				Reason: "Succeeded", Message: "complete", LastTransitionTime: oldTime,
			}
			obj.SetConditions(nil)
			conditions.Set(obj, &base)
			roundTrip()
			Expect(conditions.GetLastTransitionTime(obj, conditions.ReadyConditionType).Time.Equal(oldTime.Time)).To(BeTrue())
			for _, change := range []string{"unchanged", "status", "reason", "message", "generation"} {
				obj.SetConditions([]metav1.Condition{base})
				roundTrip()
				next := base
				next.LastTransitionTime = metav1.Now()
				switch change {
				case "status":
					next.Status = metav1.ConditionFalse
				case "reason":
					next.Reason = "NewReason"
				case "message":
					next.Message = "new message"
				case "generation":
					next.ObservedGeneration = obj.GetGeneration()
				}
				conditions.Set(obj, &next)
				roundTrip()
				actual := conditions.Get(obj, conditions.ReadyConditionType)
				Expect(actual.Status).To(Equal(next.Status))
				Expect(actual.Reason).To(Equal(next.Reason))
				Expect(actual.Message).To(Equal(next.Message))
				Expect(actual.ObservedGeneration).To(Equal(next.ObservedGeneration))
				if change == "unchanged" {
					Expect(actual.LastTransitionTime.Time.Equal(oldTime.Time)).To(BeTrue())
				} else {
					Expect(actual.LastTransitionTime.After(oldTime.Time)).To(BeTrue(), change)
					Expect(actual.LastTransitionTime.Nanosecond()).To(BeZero())
				}
			}
		},
		Entry("RoleDefinition", "RoleDefinition"),
		Entry("BindDefinition", "BindDefinition"),
		Entry("WebhookAuthorizer", "WebhookAuthorizer"),
		Entry("RBACPolicy", "RBACPolicy"),
		Entry("RestrictedRoleDefinition", "RestrictedRoleDefinition"),
		Entry("RestrictedBindDefinition", "RestrictedBindDefinition"),
	)
})
