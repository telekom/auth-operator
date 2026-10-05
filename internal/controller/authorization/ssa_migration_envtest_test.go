// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	statusssa "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

func migrationObject(kind, name string) client.Object {
	meta := metav1.ObjectMeta{Name: name}
	switch kind {
	case "RoleDefinition":
		return &authorizationv1alpha1.RoleDefinition{ObjectMeta: meta, Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName: name, TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		}}
	case "BindDefinition":
		return &authorizationv1alpha1.BindDefinition{ObjectMeta: meta, Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: name, Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "migration-user", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"migration-role"}},
		}}
	case "RestrictedRoleDefinition":
		return &authorizationv1alpha1.RestrictedRoleDefinition{ObjectMeta: meta, Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "migration-absent-policy"},
			TargetName: name, TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		}}
	case "RestrictedBindDefinition":
		return &authorizationv1alpha1.RestrictedBindDefinition{ObjectMeta: meta, Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: "migration-absent-policy"},
			TargetName: name, Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "migration-user", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: &authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"migration-role"}},
		}}
	case "RBACPolicy":
		return &authorizationv1alpha1.RBACPolicy{ObjectMeta: meta, Spec: authorizationv1alpha1.RBACPolicySpec{
			AppliesTo: authorizationv1alpha1.PolicyScope{Namespaces: []string{"*"}},
		}}
	case "WebhookAuthorizer":
		return &authorizationv1alpha1.WebhookAuthorizer{ObjectMeta: meta, Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			ResourceRules:     []authzv1.ResourceRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			AllowedPrincipals: []authorizationv1alpha1.Principal{{User: "migration-user"}},
		}}
	default:
		panic("unknown migration fixture: " + kind)
	}
}

func migrationApplyStatus(ctx context.Context, c client.Client, obj client.Object) (pkgssa.PatchApplyResult, error) {
	switch obj := obj.(type) {
	case *authorizationv1alpha1.RoleDefinition:
		return statusssa.PatchApplyRoleDefinitionStatus(ctx, c, obj)
	case *authorizationv1alpha1.BindDefinition:
		return statusssa.PatchApplyBindDefinitionStatus(ctx, c, obj)
	case *authorizationv1alpha1.RestrictedRoleDefinition:
		return statusssa.PatchApplyRestrictedRoleDefinitionStatus(ctx, c, obj)
	case *authorizationv1alpha1.RestrictedBindDefinition:
		return statusssa.PatchApplyRestrictedBindDefinitionStatus(ctx, c, obj)
	case *authorizationv1alpha1.RBACPolicy:
		return statusssa.PatchApplyRBACPolicyStatus(ctx, c, obj)
	case *authorizationv1alpha1.WebhookAuthorizer:
		return statusssa.PatchApplyWebhookAuthorizerStatus(ctx, c, obj)
	default:
		panic("unknown status fixture")
	}
}

var _ = Describe("SSA migration characterization", Label("ssa-migration"), func() {
	ctx := context.Background()
	var namespace string

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "ssa-migration-"}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		namespace = ns.Name
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ns)).To(Succeed()) })
	})

	DescribeTable("status applies changes once and skips unchanged real server state",
		func(kind string) {
			obj := migrationObject(kind, fmt.Sprintf("status-%d", time.Now().UnixNano()))
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
					Expect(subresource).To(Equal("status"))
					applies++
					return c.SubResource(subresource).Apply(ctx, ac, opts...)
				},
			})
			conditions.MarkReady(obj.(conditions.Setter), obj.GetGeneration(), "Characterized", "initial")
			result, err := migrationApplyStatus(ctx, c, obj)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(pkgssa.PatchApplyResultPatched))
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			Expect(conditions.IsReady(obj.(conditions.Getter))).To(BeTrue())
			Expect(obj.GetManagedFields()).To(ContainElement(And(
				HaveField("Manager", statusssa.FieldOwner),
				HaveField("Subresource", "status"),
				HaveField("Operation", metav1.ManagedFieldsOperationApply),
			)))
			rv := obj.GetResourceVersion()
			result, err = migrationApplyStatus(ctx, c, obj)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(pkgssa.PatchApplyResultSkipped))
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			Expect(obj.GetResourceVersion()).To(Equal(rv))
			conditions.MarkReady(obj.(conditions.Setter), obj.GetGeneration(), "Characterized", "changed")
			result, err = migrationApplyStatus(ctx, c, obj)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(pkgssa.PatchApplyResultPatched))
			Expect(applies).To(Equal(2))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			Expect(conditions.Get(obj.(conditions.Getter), conditions.ReadyConditionType).Message).To(Equal("changed"))
		},
		Entry("RoleDefinition", "RoleDefinition"),
		Entry("BindDefinition", "BindDefinition"),
		Entry("RestrictedRoleDefinition", "RestrictedRoleDefinition"),
		Entry("RestrictedBindDefinition", "RestrictedBindDefinition"),
		Entry("RBACPolicy", "RBACPolicy"),
		Entry("WebhookAuthorizer", "WebhookAuthorizer"),
	)

	It("RBACPolicy controller applies counted references, skips unchanged status and persists stalled status", func() {
		policy := migrationObject("RBACPolicy", fmt.Sprintf("counted-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RBACPolicy)
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		rrd := migrationObject("RestrictedRoleDefinition", policy.Name+"-reference").(*authorizationv1alpha1.RestrictedRoleDefinition)
		rrd.Spec.PolicyRef.Name = policy.Name
		Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rrd)).To(Succeed()) })
		// The API server does not support the controller's custom field selectors;
		// use an actual informer cache with the production index functions.
		indexed, err := cache.New(cfg, cache.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
		Expect(indexed.IndexField(ctx, &authorizationv1alpha1.RestrictedBindDefinition{},
			indexer.RestrictedBindDefinitionPolicyRefField, indexer.RestrictedBindDefinitionPolicyRefFunc)).To(Succeed())
		Expect(indexed.IndexField(ctx, &authorizationv1alpha1.RestrictedRoleDefinition{},
			indexer.RestrictedRoleDefinitionPolicyRefField, indexer.RestrictedRoleDefinitionPolicyRefFunc)).To(Succeed())
		cacheCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		done := make(chan error, 1)
		go func() { done <- indexed.Start(cacheCtx) }()
		DeferCleanup(func() { cancel(); Expect(<-done).To(Succeed()) })
		Expect(indexed.WaitForCacheSync(cacheCtx)).To(BeTrue())
		applies := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			List: func(ctx context.Context, _ client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				return indexed.List(ctx, list, opts...)
			},
			SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
				applies++
				return c.SubResource(subresource).Apply(ctx, ac, opts...)
			},
		})
		r := NewRBACPolicyReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(policy)}
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, req.NamespacedName, policy)).To(Succeed())
		Expect(policy.Status.BoundResourceCount).To(Equal(int32(1)))
		Expect(conditions.IsReady(policy)).To(BeTrue())
		Expect(applies).To(Equal(1))
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(applies).To(Equal(1))
		r.markStalled(ctx, policy, fmt.Errorf("characterized failure"))
		Expect(applies).To(Equal(2))
		Expect(k8sClient.Get(ctx, req.NamespacedName, policy)).To(Succeed())
		Expect(conditions.IsStalled(policy)).To(BeTrue())
	})

	It("WebhookAuthorizer controller persists reconciling, ready and stalled status through the real subresource", func() {
		wa := migrationObject("WebhookAuthorizer", fmt.Sprintf("authorizer-%d", time.Now().UnixNano())).(*authorizationv1alpha1.WebhookAuthorizer)
		Expect(k8sClient.Create(ctx, wa)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, wa)).To(Succeed()) })
		applies := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
				applies++
				return c.SubResource(subresource).Apply(ctx, ac, opts...)
			},
		})
		r := NewWebhookAuthorizerReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(wa)}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(applies).To(Equal(2), "Reconciling and Ready are separate status writes")
		Expect(k8sClient.Get(ctx, req.NamespacedName, wa)).To(Succeed())
		Expect(wa.Status.AuthorizerConfigured).To(BeTrue())
		Expect(conditions.IsReady(wa)).To(BeTrue())
		Expect(r.markStalled(ctx, wa, fmt.Errorf("characterized failure"))).To(Succeed())
		Expect(applies).To(Equal(3))
		Expect(k8sClient.Get(ctx, req.NamespacedName, wa)).To(Succeed())
		Expect(conditions.IsStalled(wa)).To(BeTrue())
	})

	It("RestrictedBindDefinition complete reconciliations persist generated resources and Ready status", func() {
		policy := migrationObject("RBACPolicy", fmt.Sprintf("rbd-policy-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RBACPolicy)
		policy = rbdPolicyWithDefaultAllowances(policy)
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		rbd := migrationObject("RestrictedBindDefinition", policy.Name+"-binding").(*authorizationv1alpha1.RestrictedBindDefinition)
		rbd.Spec.PolicyRef.Name = policy.Name
		rbd.Spec.ClusterRoleBindings.ClusterRoleRefs = []string{"view"}
		Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rbd), rbd)).To(Succeed())
			base := rbd.DeepCopy()
			rbd.Finalizers = nil
			Expect(k8sClient.Patch(ctx, rbd, client.MergeFrom(base))).To(Succeed())
			Expect(k8sClient.Delete(ctx, rbd)).To(Succeed())
		})
		c := &bindingApplyCountingClient{Client: k8sClient}
		r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rbd)}
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.clusterRoleBindingApplies).To(Equal(1))
		crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: helpers.BuildBindingName(rbd.Spec.TargetName, "view")}}
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, crb)).To(Succeed()) })
		Expect(k8sClient.Get(ctx, req.NamespacedName, rbd)).To(Succeed())
		Expect(rbd.Status.BindReconciled).To(BeTrue())
		Expect(conditions.IsReady(rbd)).To(BeTrue())
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.clusterRoleBindingApplies).To(Equal(2))
	})

	It("clears RestrictedRoleDefinition status lists through the real status subresource", func() {
		rrd := migrationObject("RestrictedRoleDefinition", fmt.Sprintf("clear-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RestrictedRoleDefinition)
		Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rrd)).To(Succeed()) })
		rrd.Status.PolicyViolations = []string{"previous violation"}
		conditions.MarkReady(rrd, rrd.Generation, "Characterized", "initial")
		Expect(statusssa.ApplyRestrictedRoleDefinitionStatus(ctx, k8sClient, rrd)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), rrd)).To(Succeed())
		rrd.Status.PolicyViolations = nil
		rrd.SetConditions(nil)
		Expect(statusssa.ApplyRestrictedRoleDefinitionStatus(ctx, k8sClient, rrd)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), rrd)).To(Succeed())
		Expect(rrd.Status.PolicyViolations).To(BeEmpty())
		Expect(rrd.Status.Conditions).To(BeEmpty())
		result, err := statusssa.PatchApplyRestrictedRoleDefinitionStatus(ctx, k8sClient, rrd)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(pkgssa.PatchApplyResultSkipped))
	})

	DescribeTable("controller status helper entry points persist their conditions and skip repeated writes",
		func(kind, operation string) {
			obj := migrationObject(kind, fmt.Sprintf("helper-%d", time.Now().UnixNano()))
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
					applies++
					return c.SubResource(subresource).Apply(ctx, ac, opts...)
				},
			})
			recorder := events.NewFakeRecorder(100)
			run := func() {
				switch obj := obj.(type) {
				case *authorizationv1alpha1.RoleDefinition:
					r := &RoleDefinitionReconciler{client: c, recorder: recorder}
					if operation == "deletion-failed" {
						failure := fmt.Errorf("characterized failure")
						_, err := r.markDeletionFailed(ctx, obj, failure)
						Expect(err).To(MatchError(failure))
					} else {
						r.markStalled(ctx, obj, fmt.Errorf("characterized failure"))
					}
				case *authorizationv1alpha1.BindDefinition:
					r := &BindDefinitionReconciler{client: c, recorder: recorder}
					if operation == "nonfatal" {
						conditions.MarkReady(obj, obj.Generation, "Characterized", "nonfatal")
						r.applyStatusNonFatal(ctx, obj)
					} else {
						r.markStalled(ctx, obj, fmt.Errorf("characterized failure"))
					}
				case *authorizationv1alpha1.RestrictedRoleDefinition:
					r := &RestrictedRoleDefinitionReconciler{client: c, recorder: recorder}
					if operation == "apply-stalled" {
						Expect(r.rrdApplyStatusAndMarkStalled(ctx, obj, "characterized failure")).To(Succeed())
					} else {
						r.rrdMarkStalled(ctx, obj, fmt.Errorf("characterized failure"))
					}
				case *authorizationv1alpha1.RestrictedBindDefinition:
					r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, recorder)
					switch operation {
					case "apply-stalled":
						Expect(r.rbdApplyStatusAndMarkStalled(ctx, obj, "characterized failure")).To(Succeed())
					case "skipped-sa":
						obj.Status.SkippedServiceAccounts = []string{namespace + "/absent"}
						result, err := r.rbdHandleSkippedServiceAccounts(ctx, obj)
						Expect(err).NotTo(HaveOccurred())
						Expect(result.RequeueAfter).To(Equal(RoleRefRequeueInterval))
					case "missing-role":
						result, err := r.rbdHandleMissingRoleRefs(ctx, obj, []string{"absent"})
						Expect(err).NotTo(HaveOccurred())
						Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
					case "missing-namespace":
						result, err := r.rbdHandleMissingTargetNamespaces(ctx, obj, []string{"absent"})
						Expect(err).NotTo(HaveOccurred())
						Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
					default:
						r.rbdMarkStalled(ctx, obj, fmt.Errorf("characterized failure"))
					}
				}
			}
			run()
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			getter := obj.(conditions.Getter)
			switch operation {
			case "deletion-failed":
				Expect(conditions.Get(getter, authorizationv1alpha1.DeleteCondition).Status).To(Equal(metav1.ConditionFalse))
			case "nonfatal":
				Expect(conditions.IsReady(getter)).To(BeTrue())
			case "skipped-sa", "missing-role", "missing-namespace":
				Expect(conditions.IsReady(getter)).To(BeFalse())
				Expect(conditions.Get(getter, conditions.ReadyConditionType).Status).To(Equal(metav1.ConditionFalse))
			default:
				Expect(conditions.IsStalled(getter)).To(BeTrue())
			}
			rv := obj.GetResourceVersion()
			run()
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			Expect(obj.GetResourceVersion()).To(Equal(rv))
		},
		Entry("RoleDefinition stalled", "RoleDefinition", "stalled"),
		Entry("RoleDefinition deletion failed", "RoleDefinition", "deletion-failed"),
		Entry("BindDefinition stalled", "BindDefinition", "stalled"),
		Entry("BindDefinition nonfatal apply", "BindDefinition", "nonfatal"),
		Entry("RestrictedRoleDefinition stalled", "RestrictedRoleDefinition", "stalled"),
		Entry("RestrictedRoleDefinition apply stalled", "RestrictedRoleDefinition", "apply-stalled"),
		Entry("RestrictedBindDefinition stalled", "RestrictedBindDefinition", "stalled"),
		Entry("RestrictedBindDefinition apply stalled", "RestrictedBindDefinition", "apply-stalled"),
		Entry("RestrictedBindDefinition skipped ServiceAccounts", "RestrictedBindDefinition", "skipped-sa"),
		Entry("RestrictedBindDefinition missing roles", "RestrictedBindDefinition", "missing-role"),
		Entry("RestrictedBindDefinition missing namespaces", "RestrictedBindDefinition", "missing-namespace"),
	)

	DescribeTable("restricted policy evaluation persists violations through its status callback",
		func(kind string) {
			policy := migrationObject("RBACPolicy", fmt.Sprintf("denied-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RBACPolicy)
			policy.Spec.BindingLimits = &authorizationv1alpha1.BindingLimits{AllowClusterRoleBindings: false}
			policy.Spec.RoleLimits = &authorizationv1alpha1.RoleLimits{AllowClusterRoles: false}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			obj := migrationObject(kind, policy.Name+"-resource")
			switch obj := obj.(type) {
			case *authorizationv1alpha1.RestrictedBindDefinition:
				obj.Spec.PolicyRef.Name = policy.Name
			case *authorizationv1alpha1.RestrictedRoleDefinition:
				obj.Spec.PolicyRef.Name = policy.Name
			}
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
					applies++
					return c.SubResource(subresource).Apply(ctx, ac, opts...)
				},
			})
			recorder := events.NewFakeRecorder(100)
			var result ctrl.Result
			var handled bool
			var err error
			switch obj := obj.(type) {
			case *authorizationv1alpha1.RestrictedBindDefinition:
				r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, recorder)
				result, handled, err = r.rbdEvaluatePolicy(ctx, obj, policy)
			case *authorizationv1alpha1.RestrictedRoleDefinition:
				r := &RestrictedRoleDefinitionReconciler{client: c, reader: k8sClient, recorder: recorder}
				result, handled, err = r.rrdEvaluatePolicy(ctx, obj, policy)
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(handled).To(BeTrue())
			Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			Expect(conditions.Get(obj.(conditions.Getter), authorizationv1alpha1.PolicyCompliantCondition).Status).To(Equal(metav1.ConditionFalse))
			Expect(conditions.Get(obj.(conditions.Getter), conditions.ReadyConditionType).Status).To(Equal(metav1.ConditionFalse))
			switch obj := obj.(type) {
			case *authorizationv1alpha1.RestrictedBindDefinition:
				Expect(obj.Status.PolicyViolations).NotTo(BeEmpty())
			case *authorizationv1alpha1.RestrictedRoleDefinition:
				Expect(obj.Status.PolicyViolations).NotTo(BeEmpty())
			}
		},
		Entry("RestrictedBindDefinition", "RestrictedBindDefinition"),
		Entry("RestrictedRoleDefinition", "RestrictedRoleDefinition"),
	)

	DescribeTable("RestrictedRoleDefinition reconciliation persists discovery requeue and rule-budget status",
		func(startTracker bool) {
			policy := migrationObject("RBACPolicy", fmt.Sprintf("discovery-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RBACPolicy)
			limit := int32(1)
			policy.Spec.RoleLimits = &authorizationv1alpha1.RoleLimits{AllowClusterRoles: true, MaxRulesPerRole: &limit}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			rrd := migrationObject("RestrictedRoleDefinition", policy.Name+"-resource").(*authorizationv1alpha1.RestrictedRoleDefinition)
			rrd.Spec.PolicyRef.Name = policy.Name
			rrd.Finalizers = []string{authorizationv1alpha1.RestrictedRoleDefinitionFinalizer}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			DeferCleanup(func() {
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), rrd)).To(Succeed())
				base := rrd.DeepCopy()
				rrd.Finalizers = nil
				Expect(k8sClient.Patch(ctx, rrd, client.MergeFrom(base))).To(Succeed())
				Expect(k8sClient.Delete(ctx, rrd)).To(Succeed())
			})
			tracker := discovery.NewResourceTracker(scheme.Scheme, cfg)
			if startTracker {
				trackerCtx, cancel := context.WithCancel(ctx)
				trackerDone := make(chan error, 1)
				go func() {
					trackerDone <- tracker.Start(trackerCtx)
				}()
				DeferCleanup(func() {
					cancel()
					Expect(<-trackerDone).To(Succeed())
				})
				Eventually(func() error {
					_, err := tracker.GetAPIResources()
					return err
				}).Should(Succeed())
			}
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
					applies++
					return c.SubResource(subresource).Apply(ctx, ac, opts...)
				},
			})
			r := &RestrictedRoleDefinitionReconciler{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100), resourceTracker: tracker}
			result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rrd)})
			Expect(err).NotTo(HaveOccurred())
			Expect(applies).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rrd), rrd)).To(Succeed())
			if startTracker {
				Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
				Expect(rrd.Status.PolicyViolations).To(ContainElement(ContainSubstring("exceeding maximum")))
				Expect(conditions.Get(rrd, conditions.ReadyConditionType).Status).To(Equal(metav1.ConditionFalse))
			} else {
				Expect(result.RequeueAfter).To(Equal(10 * time.Second))
				Expect(conditions.IsReconciling(rrd)).To(BeTrue())
				Expect(rrd.Status.PolicyViolations).To(BeEmpty())
			}
			Expect(rrd.Status.RoleReconciled).To(BeFalse())
			role := &rbacv1.ClusterRole{}
			Expect(apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: rrd.Spec.TargetName}, role))).To(BeTrue())
		},
		Entry("discovery not started", false),
		Entry("generated rules exceed policy budget", true),
	)

	It("retries generated ServiceAccount status cleanup against fresh state after a real conflict", func() {
		bd := migrationObject("BindDefinition", fmt.Sprintf("cleanup-%d", time.Now().UnixNano())).(*authorizationv1alpha1.BindDefinition)
		Expect(k8sClient.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, bd)).To(Succeed()) })
		bd.Status.GeneratedServiceAccounts = []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "generated", Namespace: namespace}}
		conditions.MarkReady(bd, bd.Generation, "Characterized", "preserve me")
		Expect(statusssa.ApplyBindDefinitionStatus(ctx, k8sClient, bd)).To(Succeed())
		patches := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, subresource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patches++
				if patches == 1 {
					fresh := &authorizationv1alpha1.BindDefinition{}
					Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bd), fresh)).To(Succeed())
					base := fresh.DeepCopy()
					fresh.Status.ExternalServiceAccounts = []string{"foreign/account"}
					Expect(k8sClient.Status().Patch(ctx, fresh, client.MergeFrom(base))).To(Succeed())
				}
				err := c.SubResource(subresource).Patch(ctx, obj, patch, opts...)
				if patches == 1 {
					Expect(apierrors.IsConflict(err)).To(BeTrue())
				}
				return err
			},
		})
		r := &BindDefinitionReconciler{client: c, reader: k8sClient}
		Expect(r.clearGeneratedServiceAccountsStatus(ctx, bd)).To(Succeed())
		Expect(patches).To(Equal(2))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bd), bd)).To(Succeed())
		Expect(bd.Status.GeneratedServiceAccounts).To(BeEmpty())
		Expect(bd.Status.ExternalServiceAccounts).To(Equal([]string{"foreign/account"}))
		Expect(conditions.IsReady(bd)).To(BeTrue())
		Expect(r.clearGeneratedServiceAccountsStatus(ctx, bd)).To(Succeed())
		Expect(patches).To(Equal(2))
	})

	It("always applies only the terminator's Namespace condition and preserves foreign conditions", func() {
		ns := &corev1.Namespace{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: namespace}, ns)).To(Succeed())
		foreign := corev1ac.Namespace(namespace).WithStatus(corev1ac.NamespaceStatus().WithConditions(
			corev1ac.NamespaceCondition().WithType(corev1.NamespaceDeletionDiscoveryFailure).
				WithStatus(corev1.ConditionFalse).WithReason("Foreign").WithMessage("preserve")))
		Expect(k8sClient.SubResource("status").Apply(ctx, foreign, client.FieldOwner("foreign-status"))).To(Succeed())
		applies := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			SubResourceApply: func(ctx context.Context, c client.Client, subresource string, ac runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
				applies++
				return c.SubResource(subresource).Apply(ctx, ac, opts...)
			},
		})
		r := &RoleBindingTerminator{client: c}
		Expect(r.applyNamespaceTerminationStatus(ctx, ns)).To(Succeed())
		Expect(applies).To(BeZero())
		ns.Status.Conditions = []corev1.NamespaceCondition{{
			Type:   corev1.NamespaceConditionType(authorizationv1alpha1.NamespaceTerminationBlockedCondition),
			Status: corev1.ConditionTrue, Reason: "Blocked", Message: "remaining resources",
			LastTransitionTime: metav1.Now(),
		}}
		Expect(r.applyNamespaceTerminationStatus(ctx, ns)).To(Succeed())
		Expect(r.applyNamespaceTerminationStatus(ctx, ns)).To(Succeed())
		Expect(applies).To(Equal(2))
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: namespace}, ns)).To(Succeed())
		Expect(ns.Status.Conditions).To(ContainElement(HaveField("Reason", "Foreign")))
		Expect(ns.Status.Conditions).To(ContainElement(HaveField("Reason", "Blocked")))
	})

	DescribeTable("RoleDefinition call sites skip unchanged and shared ownership, repair once, and prune owned labels",
		func(clusterScoped bool) {
			rd := migrationObject("RoleDefinition", fmt.Sprintf("rd-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RoleDefinition)
			rd.Labels = map[string]string{"remove": "owned"}
			if !clusterScoped {
				rd.Spec.TargetRole = authorizationv1alpha1.DefinitionNamespacedRole
				rd.Spec.TargetNamespace = namespace
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rd)).To(Succeed()) })
			rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
			c := &roleApplyCountingClient{Client: k8sClient}
			r := &RoleDefinitionReconciler{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100)}
			ensure := func() { Expect(r.ensureRole(ctx, rd, rules)).To(Succeed()) }
			ensure()
			ensure()
			Expect(c.applies).To(Equal(1))
			var obj client.Object = &rbacv1.ClusterRole{}
			var shared, drift runtime.ApplyConfiguration
			if clusterScoped {
				shared = pkgssa.ClusterRoleWithLabelsAndRules(rd.Spec.TargetName, nil, rules)
				drift = rbacv1ac.ClusterRole(rd.Spec.TargetName).WithLabels(map[string]string{"foreign": "preserve"}).
					WithRules(rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("secrets").WithVerbs("get"))
			} else {
				obj = &rbacv1.Role{}
				shared = pkgssa.RoleWithLabelsAndRules(rd.Spec.TargetName, namespace, nil, rules)
				drift = rbacv1ac.Role(rd.Spec.TargetName, namespace).WithLabels(map[string]string{"foreign": "preserve"}).
					WithRules(rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("secrets").WithVerbs("get"))
			}
			key := client.ObjectKey{Name: rd.Spec.TargetName, Namespace: rd.Spec.TargetNamespace}
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			Expect(k8sClient.Apply(ctx, shared, client.FieldOwner("shared-role"))).To(Succeed())
			ensure()
			Expect(c.applies).To(Equal(1))
			Expect(k8sClient.Apply(ctx, drift, client.FieldOwner("shared-role"), client.ForceOwnership)).To(Succeed())
			ensure()
			ensure()
			Expect(c.applies).To(Equal(2))
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			Expect(obj.GetLabels()).To(HaveKeyWithValue("foreign", "preserve"))
			if clusterScoped {
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(Equal(rules))
			} else {
				Expect(obj.(*rbacv1.Role).Rules).To(Equal(rules))
			}
			delete(rd.Labels, "remove")
			ensure()
			ensure()
			Expect(c.applies).To(Equal(3))
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			Expect(obj.GetLabels()).NotTo(HaveKey("remove"))
			Expect(obj.GetLabels()).To(HaveKeyWithValue("foreign", "preserve"))
			if clusterScoped {
				rd.Spec.AggregateFrom = &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"aggregate": "selected"}}}}
				ensure()
				Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(BeEmpty())
				Expect(obj.(*rbacv1.ClusterRole).AggregationRule).To(Equal(rd.Spec.AggregateFrom))
				rd.Spec.AggregateFrom = nil
				ensure()
				Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
				Expect(obj.(*rbacv1.ClusterRole).AggregationRule).To(BeNil())
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(Equal(rules))
			}
			Expect(r.ensureRole(ctx, rd, nil)).To(Succeed())
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			if clusterScoped {
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(BeEmpty())
			} else {
				Expect(obj.(*rbacv1.Role).Rules).To(BeEmpty())
			}
		},
		Entry("ClusterRole", true),
		Entry("Role", false),
	)

	DescribeTable("restricted role authorization boundaries always apply, repair drift and clear rules",
		func(clusterScoped bool) {
			rrd := migrationObject("RestrictedRoleDefinition", fmt.Sprintf("rrd-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RestrictedRoleDefinition)
			if !clusterScoped {
				rrd.Spec.TargetRole = authorizationv1alpha1.DefinitionNamespacedRole
				rrd.Spec.TargetNamespace = namespace
			}
			Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rrd)).To(Succeed()) })
			rules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				Apply: func(ctx context.Context, c client.WithWatch, ac runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					applies++
					return c.Apply(ctx, ac, opts...)
				},
			})
			r := &RestrictedRoleDefinitionReconciler{client: c, reader: k8sClient, scheme: scheme.Scheme, recorder: events.NewFakeRecorder(100)}
			ensure := func(desired []rbacv1.PolicyRule) {
				Expect(r.rrdEnsureRole(ctx, rrd, desired, c)).To(Succeed())
			}
			ensure(rules)
			ensure(rules)
			Expect(applies).To(Equal(2), "restricted authorization must not be bypassed by the cache")
			var obj client.Object = &rbacv1.ClusterRole{}
			var foreign runtime.ApplyConfiguration = rbacv1ac.ClusterRole(rrd.Spec.TargetName).
				WithLabels(map[string]string{"foreign": "preserve"}).
				WithRules(rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("secrets").WithVerbs("get"))
			if !clusterScoped {
				obj = &rbacv1.Role{}
				foreign = rbacv1ac.Role(rrd.Spec.TargetName, namespace).
					WithLabels(map[string]string{"foreign": "preserve"}).
					WithRules(rbacv1ac.PolicyRule().WithAPIGroups("").WithResources("secrets").WithVerbs("get"))
			}
			key := client.ObjectKey{Name: rrd.Spec.TargetName, Namespace: rrd.Spec.TargetNamespace}
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })
			Expect(k8sClient.Apply(ctx, foreign, client.FieldOwner("foreign-role"), client.ForceOwnership)).To(Succeed())
			ensure(rules)
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			if clusterScoped {
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(Equal(rules))
				Expect(obj.GetLabels()).NotTo(HaveKey("foreign"), "restricted ClusterRoles deliberately normalize all labels")
			} else {
				Expect(obj.(*rbacv1.Role).Rules).To(Equal(rules))
				Expect(obj.GetLabels()).To(HaveKeyWithValue("foreign", "preserve"))
			}
			ensure(nil)
			Expect(k8sClient.Get(ctx, key, obj)).To(Succeed())
			if clusterScoped {
				Expect(obj.(*rbacv1.ClusterRole).Rules).To(BeEmpty())
			} else {
				Expect(obj.(*rbacv1.Role).Rules).To(BeEmpty())
			}
			ensure(nil)
			Expect(applies).To(Equal(5))
		},
		Entry("ClusterRole", true),
		Entry("Role", false),
	)

	It("restricted binding call sites always apply, repair foreign subjects and preserve foreign labels", func() {
		rbd := migrationObject("RestrictedBindDefinition", fmt.Sprintf("rbd-%d", time.Now().UnixNano())).(*authorizationv1alpha1.RestrictedBindDefinition)
		rbd.Spec.ClusterRoleBindings = &authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}}
		rbd.Spec.RoleBindings = []authorizationv1alpha1.NamespaceBinding{{Namespace: namespace, ClusterRoleRefs: []string{"view"}}}
		rbd.Spec.Subjects = []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "desired", APIGroup: rbacv1.GroupName}}
		Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rbd)).To(Succeed()) })
		c := &bindingApplyCountingClient{Client: k8sClient}
		r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
		ensure := func(subjects []rbacv1.Subject) { Expect(r.rbdReconcileBindings(ctx, rbd, subjects, c)).To(Succeed()) }
		ensure(rbd.Spec.Subjects)
		ensure(rbd.Spec.Subjects)
		Expect([]int{c.clusterRoleBindingApplies, c.roleBindingApplies}).To(Equal([]int{2, 2}))
		name := helpers.BuildBindingName(rbd.Spec.TargetName, "view")
		crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}
		rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, crb)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rb)).To(Succeed())
		})
		drift := rbacv1ac.Subject().WithKind(rbacv1.UserKind).WithAPIGroup(rbacv1.GroupName).WithName("foreign")
		Expect(k8sClient.Apply(ctx, rbacv1ac.ClusterRoleBinding(name).WithSubjects(drift).WithLabels(map[string]string{"foreign": "preserve"}),
			client.FieldOwner("foreign-binding"), client.ForceOwnership)).To(Succeed())
		Expect(k8sClient.Apply(ctx, rbacv1ac.RoleBinding(name, namespace).WithSubjects(drift).WithLabels(map[string]string{"foreign": "preserve"}),
			client.FieldOwner("foreign-binding"), client.ForceOwnership)).To(Succeed())
		ensure(rbd.Spec.Subjects)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(crb), crb)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rb), rb)).To(Succeed())
		Expect(crb.Subjects).To(Equal(rbd.Spec.Subjects))
		Expect(rb.Subjects).To(Equal(rbd.Spec.Subjects))
		Expect(crb.Labels).To(HaveKeyWithValue("foreign", "preserve"))
		Expect(rb.Labels).To(HaveKeyWithValue("foreign", "preserve"))
		ensure(nil)
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(crb), crb)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rb), rb)).To(Succeed())
		Expect(crb.Subjects).To(BeEmpty())
		Expect(rb.Subjects).To(BeEmpty())
		ensure(nil)
		Expect([]int{c.clusterRoleBindingApplies, c.roleBindingApplies}).To(Equal([]int{5, 5}))
	})

	DescribeTable("ServiceAccount controller call sites retain their distinct skip and Always contracts",
		func(restricted bool) {
			name := fmt.Sprintf("sa-owner-%d", time.Now().UnixNano())
			subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "managed", Namespace: namespace}
			applies := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				Apply: func(ctx context.Context, c client.WithWatch, ac runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
					if _, ok := ac.(*corev1ac.ServiceAccountApplyConfiguration); ok {
						applies++
					}
					return c.Apply(ctx, ac, opts...)
				},
			})
			var ensure func()
			if restricted {
				rbd := migrationObject("RestrictedBindDefinition", name).(*authorizationv1alpha1.RestrictedBindDefinition)
				rbd.Spec.Subjects = []rbacv1.Subject{subject}
				Expect(k8sClient.Create(ctx, rbd)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, rbd)).To(Succeed()) })
				r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
				ensure = func() {
					subjects, err := r.rbdEnsureServiceAccounts(ctx, rbd, c, &authorizationv1alpha1.SACreationConfig{AllowAutoCreate: true})
					Expect(err).NotTo(HaveOccurred())
					Expect(subjects).To(Equal([]rbacv1.Subject{subject}))
					Expect(rbd.Status.GeneratedServiceAccounts).To(Equal([]rbacv1.Subject{subject}))
				}
			} else {
				bd := migrationObject("BindDefinition", name).(*authorizationv1alpha1.BindDefinition)
				Expect(k8sClient.Create(ctx, bd)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, bd)).To(Succeed()) })
				r := &BindDefinitionReconciler{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100)}
				ensure = func() { Expect(r.applyServiceAccount(ctx, bd, subject, true)).To(Succeed()) }
			}
			ensure()
			ensure()
			expected := 1
			if restricted {
				expected = 2
			}
			Expect(applies).To(Equal(expected))
			sa := &corev1.ServiceAccount{}
			key := client.ObjectKey{Name: subject.Name, Namespace: namespace}
			Expect(k8sClient.Get(ctx, key, sa)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, sa)).To(Succeed()) })
			Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(subject.Name, namespace).WithLabels(map[string]string{"foreign": "preserve"}).WithAutomountServiceAccountToken(true),
				client.FieldOwner("foreign-sa"))).To(Succeed())
			ensure()
			if restricted {
				expected++
			}
			Expect(applies).To(Equal(expected))
			Expect(k8sClient.Get(ctx, key, sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("foreign", "preserve"))
			Expect(k8sClient.Apply(ctx, corev1ac.ServiceAccount(subject.Name, namespace).WithAutomountServiceAccountToken(false),
				client.FieldOwner("foreign-sa"), client.ForceOwnership)).To(Succeed())
			// ServiceAccount callers deliberately do not force ownership.
			if restricted {
				rbd := migrationObject("RestrictedBindDefinition", name).(*authorizationv1alpha1.RestrictedBindDefinition)
				Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, rbd)).To(Succeed())
				rbd.Spec.Subjects = []rbacv1.Subject{subject}
				r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
				_, err := r.rbdEnsureServiceAccounts(ctx, rbd, c, &authorizationv1alpha1.SACreationConfig{AllowAutoCreate: true})
				Expect(apierrors.IsConflict(err)).To(BeTrue())
			} else {
				bd := migrationObject("BindDefinition", name).(*authorizationv1alpha1.BindDefinition)
				Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, bd)).To(Succeed())
				r := &BindDefinitionReconciler{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100)}
				Expect(apierrors.IsConflict(r.applyServiceAccount(ctx, bd, subject, true))).To(BeTrue())
			}
			Expect(k8sClient.Get(ctx, key, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).To(HaveValue(BeFalse()))
		},
		Entry("BindDefinition", false),
		Entry("RestrictedBindDefinition", true),
	)

	DescribeTable("ServiceAccount metadata retries preserve concurrent changes and other owners",
		func(operation string) {
			bd := migrationObject("BindDefinition", fmt.Sprintf("sa-patch-%d", time.Now().UnixNano())).(*authorizationv1alpha1.BindDefinition)
			Expect(k8sClient.Create(ctx, bd)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, bd)).To(Succeed()) })
			other := migrationObject("BindDefinition", bd.Name+"-other").(*authorizationv1alpha1.BindDefinition)
			other.Spec.Subjects = []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "metadata", Namespace: namespace}}
			Expect(k8sClient.Create(ctx, other)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, other)).To(Succeed()) })
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name: "metadata", Namespace: namespace,
				Annotations: map[string]string{
					helpers.SourceKindAnnotation:  authorizationv1alpha1.BindDefinitionKind,
					helpers.SourceNamesAnnotation: helpers.MergeSourceNames(bd.Name, other.Name),
				},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: authorizationv1alpha1.BindDefinitionKind, Name: bd.Name, UID: bd.UID},
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: authorizationv1alpha1.BindDefinitionKind, Name: other.Name, UID: other.UID},
				},
			}}
			if operation == "addManagedSAReference" {
				sa.Annotations[helpers.SourceNamesAnnotation] = other.Name
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, sa)).To(Succeed()) })
			patches := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					patches++
					if patches == 1 {
						fresh := &corev1.ServiceAccount{}
						Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), fresh)).To(Succeed())
						base := fresh.DeepCopy()
						fresh.Labels = map[string]string{"foreign": "preserve"}
						fresh.Annotations["foreign"] = "preserve"
						Expect(k8sClient.Patch(ctx, fresh, client.MergeFrom(base))).To(Succeed())
					}
					err := c.Patch(ctx, obj, patch, opts...)
					if patches == 1 {
						Expect(apierrors.IsConflict(err)).To(BeTrue())
					}
					return err
				},
			})
			r := &BindDefinitionReconciler{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100)}
			run := func() {
				switch operation {
				case "addManagedSAReference":
					Expect(r.addManagedSAReference(ctx, namespace, sa.Name, bd.Name)).To(Succeed())
				case "detachServiceAccountFromBindDefinition":
					Expect(r.detachServiceAccountFromBindDefinition(ctx, sa, bd)).To(Succeed())
				case "reclassifyServiceAccountAsExternal":
					Expect(r.reclassifyServiceAccountAsExternal(ctx, namespace, sa.Name, bd, []string{"helm-controller"})).To(Succeed())
				case "deleteServiceAccount":
					result, err := r.deleteServiceAccount(ctx, bd, sa.Name, namespace)
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(deleteResultNoOwnerRef))
				}
			}
			run()
			Expect(patches).To(Equal(2))
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)).To(Succeed())
			Expect(sa.Labels).To(HaveKeyWithValue("foreign", "preserve"))
			Expect(sa.Annotations).To(HaveKeyWithValue("foreign", "preserve"))
			Expect(sa.OwnerReferences).To(ContainElement(HaveField("UID", other.UID)))
			if operation == "addManagedSAReference" {
				Expect(sa.Annotations[helpers.SourceNamesAnnotation]).To(Equal(helpers.MergeSourceNames(bd.Name, other.Name)))
			} else {
				Expect(sa.OwnerReferences).NotTo(ContainElement(HaveField("UID", bd.UID)))
				Expect(sa.Annotations[helpers.SourceNamesAnnotation]).To(Equal(other.Name))
			}
			if operation == "reclassifyServiceAccountAsExternal" {
				Expect(sa.Annotations).To(HaveKeyWithValue(authorizationv1alpha1.AnnotationKeyReferencedBy, bd.Name))
				Expect(sa.Annotations).To(HaveKeyWithValue(authorizationv1alpha1.AnnotationKeyExternalFieldManagers, "helm-controller"))
			} else {
				run()
				Expect(patches).To(Equal(2), "idempotent metadata operations must not patch")
			}
		},
		Entry("add managed source", "addManagedSAReference"),
		Entry("detach explicit external account", "detachServiceAccountFromBindDefinition"),
		Entry("reclassify foreign-owned account", "reclassifyServiceAccountAsExternal"),
		Entry("retain account referenced by another BindDefinition", "deleteServiceAccount"),
	)

	It("external ServiceAccount tracking patches preserve unrelated metadata and prune the last reference", func() {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name: "external-tracking", Namespace: namespace,
			Labels:      map[string]string{"foreign": "preserve"},
			Annotations: map[string]string{"foreign": "preserve", authorizationv1alpha1.AnnotationKeyExternalFieldManagers: "helm-controller"},
		}}
		Expect(k8sClient.Create(ctx, sa)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, sa)).To(Succeed()) })
		patches := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				patches++
				return c.Patch(ctx, obj, patch, opts...)
			},
		})
		r := &BindDefinitionReconciler{client: c, recorder: events.NewFakeRecorder(100)}
		Expect(r.addExternalSAReference(ctx, sa, "first")).To(Succeed())
		Expect(r.addExternalSAReference(ctx, sa, "first")).To(Succeed())
		Expect(patches).To(Equal(1))
		Expect(r.addExternalSAReference(ctx, sa, "second")).To(Succeed())
		Expect(r.removeExternalSAReference(ctx, namespace, sa.Name, "first")).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)).To(Succeed())
		Expect(sa.Annotations).To(HaveKeyWithValue(authorizationv1alpha1.AnnotationKeyReferencedBy, "second"))
		Expect(r.removeExternalSAReference(ctx, namespace, sa.Name, "second")).To(Succeed())
		Expect(r.removeExternalSAReference(ctx, namespace, sa.Name, "second")).To(Succeed())
		Expect(patches).To(Equal(4))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)).To(Succeed())
		Expect(sa.Annotations).NotTo(HaveKey(authorizationv1alpha1.AnnotationKeyReferencedBy))
		Expect(sa.Annotations).NotTo(HaveKey(authorizationv1alpha1.AnnotationKeyExternalFieldManagers))
		Expect(sa.Annotations).To(HaveKeyWithValue("foreign", "preserve"))
		Expect(sa.Labels).To(HaveKeyWithValue("foreign", "preserve"))
	})

	It("terminator finalizer addition and removal reject stale writes and preserve foreign finalizers", func() {
		bd := migrationObject("BindDefinition", fmt.Sprintf("terminator-%d", time.Now().UnixNano())).(*authorizationv1alpha1.BindDefinition)
		Expect(k8sClient.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, bd)).To(Succeed()) })
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "terminator", Namespace: namespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		rb.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(bd, authorizationv1alpha1.GroupVersion.WithKind(authorizationv1alpha1.BindDefinitionKind))}
		Expect(k8sClient.Create(ctx, rb)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rb), rb)).To(Succeed())
			base := rb.DeepCopy()
			rb.Finalizers = nil
			Expect(k8sClient.Patch(ctx, rb, client.MergeFrom(base))).To(Succeed())
			Expect(k8sClient.Delete(ctx, rb)).To(Succeed())
		})
		race := true
		patches := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				patches++
				if race {
					race = false
					fresh := &rbacv1.RoleBinding{}
					Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rb), fresh)).To(Succeed())
					base := fresh.DeepCopy()
					fresh.Finalizers = append(fresh.Finalizers, fmt.Sprintf("foreign.example/hold-%d", patches))
					Expect(k8sClient.Patch(ctx, fresh, client.MergeFrom(base))).To(Succeed())
					err := c.Patch(ctx, obj, patch, opts...)
					Expect(apierrors.IsConflict(err)).To(BeTrue())
					return err
				}
				return c.Patch(ctx, obj, patch, opts...)
			},
		})
		r := &RoleBindingTerminator{client: c, reader: k8sClient, recorder: events.NewFakeRecorder(100)}
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rb)}
		_, err := r.Reconcile(ctx, req)
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		_, err = r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, req.NamespacedName, rb)).To(Succeed())
		Expect(rb.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
		race = true
		removed, err := r.removeRoleBindingFinalizer(ctx, rb)
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		Expect(removed).To(BeFalse())
		Expect(k8sClient.Get(ctx, req.NamespacedName, rb)).To(Succeed())
		Expect(rb.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
		removed, err = r.removeRoleBindingFinalizer(ctx, rb)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeTrue())
		Expect(k8sClient.Get(ctx, req.NamespacedName, rb)).To(Succeed())
		Expect(rb.Finalizers).To(ContainElements("foreign.example/hold-1", "foreign.example/hold-3"))
		Expect(rb.Finalizers).NotTo(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
		removed, err = r.removeRoleBindingFinalizer(ctx, rb)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeFalse())
		Expect(patches).To(Equal(4))
	})

	// Finalizer conflicts are generated by a real concurrent metadata write,
	// not by returning synthetic Conflict errors from an interceptor.
	DescribeTable("finalizer add and remove preserve a concurrent writer across conflicts",
		func(kind, finalizer string) {
			name := fmt.Sprintf("finalizer-%d", time.Now().UnixNano())
			obj := migrationObject(kind, name)
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
			DeferCleanup(func() {
				fresh := migrationObject(kind, name)
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, fresh); err == nil {
					base := fresh.DeepCopyObject().(client.Object)
					fresh.SetFinalizers(nil)
					Expect(k8sClient.Patch(ctx, fresh, client.MergeFrom(base))).To(Succeed())
					Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, fresh))).To(Succeed())
				}
			})
			race := true
			conflicts := 0
			c := interceptor.NewClient(k8sClient, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if race && obj.GetName() == name {
						race = false
						fresh := migrationObject(kind, name)
						Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, fresh)).To(Succeed())
						base := fresh.DeepCopyObject().(client.Object)
						fresh.SetFinalizers(append(fresh.GetFinalizers(), "foreign.example/hold"))
						fresh.SetLabels(map[string]string{"foreign": "preserve", "race": fmt.Sprint(conflicts)})
						Expect(k8sClient.Patch(ctx, fresh, client.MergeFrom(base))).To(Succeed())
						err := c.Patch(ctx, obj, patch, opts...)
						Expect(apierrors.IsConflict(err)).To(BeTrue())
						conflicts++
						return err
					}
					return c.Patch(ctx, obj, patch, opts...)
				},
			})
			var add, remove func() (ctrl.Result, error)
			switch kind {
			case "RoleDefinition":
				r := &RoleDefinitionReconciler{client: c, recorder: events.NewFakeRecorder(100)}
				add = func() (ctrl.Result, error) {
					Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
					return ctrl.Result{}, r.ensureFinalizer(ctx, obj.(*authorizationv1alpha1.RoleDefinition))
				}
				remove = func() (ctrl.Result, error) {
					return r.removeRoleDefinitionFinalizer(ctx, obj.(*authorizationv1alpha1.RoleDefinition))
				}
			case "BindDefinition":
				r, err := NewBindDefinitionReconciler(c, cfg, scheme.Scheme, events.NewFakeRecorder(100), nil)
				Expect(err).NotTo(HaveOccurred())
				r.reader = k8sClient
				add = func() (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
				}
				remove = func() (ctrl.Result, error) {
					Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
					_, err := r.reconcileDelete(ctx, obj.(*authorizationv1alpha1.BindDefinition))
					return ctrl.Result{}, err
				}
			case "RestrictedBindDefinition":
				r := NewRestrictedBindDefinitionReconciler(c, scheme.Scheme, events.NewFakeRecorder(100))
				r.reader = k8sClient
				add = func() (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
				}
				remove = func() (ctrl.Result, error) {
					Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
					return ctrl.Result{}, r.reconcileDelete(ctx, obj.(*authorizationv1alpha1.RestrictedBindDefinition))
				}
			case "RestrictedRoleDefinition":
				r := &RestrictedRoleDefinitionReconciler{client: c, reader: k8sClient, scheme: scheme.Scheme, recorder: events.NewFakeRecorder(100)}
				add = func() (ctrl.Result, error) {
					return r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
				}
				remove = func() (ctrl.Result, error) {
					Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
					return ctrl.Result{}, r.rrdHandleDeletion(ctx, obj.(*authorizationv1alpha1.RestrictedRoleDefinition))
				}
			}
			result, err := add()
			if kind == "RestrictedBindDefinition" || kind == "RestrictedRoleDefinition" {
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(HaveField("Requeue", true))
			} else {
				Expect(apierrors.IsConflict(err)).To(BeTrue())
			}
			Expect(conflicts).To(Equal(1))
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
			Expect(obj.GetFinalizers()).NotTo(ContainElement(finalizer))
			_, err = add()
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
			Expect(obj.GetFinalizers()).To(ContainElement(finalizer))
			Expect(obj.GetFinalizers()).To(ContainElement("foreign.example/hold"))
			// Use a different foreign finalizer to force another resourceVersion.
			base := obj.DeepCopyObject().(client.Object)
			obj.SetFinalizers(append(obj.GetFinalizers(), "foreign.example/second"))
			Expect(k8sClient.Patch(ctx, obj, client.MergeFrom(base))).To(Succeed())
			race = true
			_, err = remove()
			Expect(apierrors.IsConflict(err)).To(BeTrue())
			Expect(conflicts).To(Equal(2))
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
			Expect(obj.GetFinalizers()).To(ContainElement(finalizer))
			_, err = remove()
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
			Expect(obj.GetFinalizers()).NotTo(ContainElement(finalizer))
			Expect(obj.GetFinalizers()).To(ContainElements("foreign.example/hold", "foreign.example/second"))
			Expect(obj.GetLabels()).To(HaveKeyWithValue("foreign", "preserve"))
		},
		Entry("RoleDefinition", "RoleDefinition", authorizationv1alpha1.RoleDefinitionFinalizer),
		Entry("BindDefinition", "BindDefinition", authorizationv1alpha1.BindDefinitionFinalizer),
		Entry("RestrictedBindDefinition", "RestrictedBindDefinition", authorizationv1alpha1.RestrictedBindDefinitionFinalizer),
		Entry("RestrictedRoleDefinition", "RestrictedRoleDefinition", authorizationv1alpha1.RestrictedRoleDefinitionFinalizer),
	)
})
