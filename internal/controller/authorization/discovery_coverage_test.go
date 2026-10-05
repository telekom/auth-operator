// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/indexer"
)

const coverageCRDFinalizer = "coverage.example.com/hold"

func releaseCoverageCRD(ctx context.Context, key client.ObjectKey) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current apiextensionsv1.CustomResourceDefinition
		if err := k8sClient.Get(ctx, key, &current); err != nil {
			return client.IgnoreNotFound(err)
		}
		if !slices.Contains(current.Finalizers, coverageCRDFinalizer) {
			return nil
		}
		current.Finalizers = slices.DeleteFunc(current.Finalizers, func(value string) bool {
			return value == coverageCRDFinalizer
		})
		return k8sClient.Update(ctx, &current)
	})
}

func discoveryCoverageCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "coveragewidgets.coverage.example.com"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "coverage.example.com", Scope: apiextensionsv1.ClusterScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "coveragewidgets", Singular: "coveragewidget", Kind: "CoverageWidget",
			},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
				},
			}},
		},
	}
}

var _ = Describe("Discovery migration characterization", func() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		crd    *apiextensionsv1.CustomResourceDefinition
		waiter *discovery.CRDWaiter
		gvk    schema.GroupVersionKind
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		crd = discoveryCoverageCRD()
		gvk = schema.GroupVersionKind{Group: crd.Spec.Group, Version: "v1", Kind: crd.Spec.Names.Kind}
		waiter = discovery.NewCRDWaiter(k8sClient, logr.Discard())
		DeferCleanup(func() {
			cancel()
			Expect(releaseCoverageCRD(context.Background(), client.ObjectKeyFromObject(crd))).To(Succeed())
			Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), crd))).To(Succeed())
			Eventually(func() bool {
				return apierrors.IsNotFound(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(crd),
					&apiextensionsv1.CustomResourceDefinition{}))
			}).WithTimeout(20 * time.Second).Should(BeTrue())
		})
	})

	It("waits for an absent CRD to be installed and established", func() {
		done := make(chan error, 1)
		go func() { done <- waiter.WaitForCRDs(ctx, []schema.GroupVersionKind{gvk}, 20*time.Second) }()
		Consistently(done).WithTimeout(100 * time.Millisecond).ShouldNot(Receive())
		Expect(k8sClient.Create(ctx, crd)).To(Succeed())
		Eventually(done).WithTimeout(20 * time.Second).Should(Receive(Succeed()))
		var established apiextensionsv1.CustomResourceDefinition
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(crd), &established)).To(Succeed())
		Expect(established.Status.Conditions).To(ContainElement(And(
			HaveField("Type", apiextensionsv1.Established),
			HaveField("Status", apiextensionsv1.ConditionTrue),
		)))
		Expect(waiter.WaitForCRDs(ctx, []schema.GroupVersionKind{gvk}, time.Second)).To(Succeed())
	})

	It("bounds missing-CRD waits and preserves caller cancellation", func() {
		err := waiter.WaitForCRDs(ctx, []schema.GroupVersionKind{gvk}, 100*time.Millisecond)
		Expect(errors.Is(err, context.DeadlineExceeded)).To(BeTrue())
		cancel()
		err = waiter.WaitForCRDs(ctx, []schema.GroupVersionKind{gvk}, time.Minute)
		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(waiter.WaitForCRDs(context.Background(), nil, time.Second)).To(Succeed())
	})

	It("discovers CRD installation and removal and automatically regenerates RBAC", func() {
		manager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme, Metrics: metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(indexer.SetupIndexes(ctx, manager)).To(Succeed())
		tracker := discovery.NewResourceTracker(scheme.Scheme, cfg)
		// Long fallback intervals ensure this test exercises watch-driven changes.
		tracker.CollectionInterval = time.Hour
		tracker.FullRescanInterval = time.Hour
		reconciler, err := NewRoleDefinitionReconciler(manager.GetClient(), scheme.Scheme, recorder, tracker)
		Expect(err).NotTo(HaveOccurred())
		Expect(reconciler.SetupWithManager(ctx, manager, 1)).To(Succeed())
		restricted, err := NewRestrictedRoleDefinitionReconciler(manager.GetClient(), scheme.Scheme, recorder, tracker)
		Expect(err).NotTo(HaveOccurred())
		Expect(restricted.SetupWithManager(manager, 1)).To(Succeed())
		Expect(manager.Add(tracker)).To(Succeed())
		managerDone := make(chan error, 1)
		go func() { managerDone <- manager.Start(ctx) }()
		DeferCleanup(func() {
			cancel()
			Eventually(managerDone).WithTimeout(20 * time.Second).Should(Receive(Succeed()))
		})
		Eventually(func() error {
			_, err := tracker.GetAPIResources()
			return err
		}).WithTimeout(20 * time.Second).Should(Succeed())

		rd := &authorizationv1alpha1.RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "discovery-coverage-"},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "discovery-coverage-role", TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}
		Expect(k8sClient.Create(ctx, rd)).To(Succeed())
		roleKey := client.ObjectKey{Name: rd.Spec.TargetName}
		policy := &authorizationv1alpha1.RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "discovery-coverage-policy-"},
			Spec: authorizationv1alpha1.RBACPolicySpec{
				AppliesTo:  authorizationv1alpha1.PolicyScope{Namespaces: []string{"*"}},
				RoleLimits: &authorizationv1alpha1.RoleLimits{AllowClusterRoles: true},
			},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "discovery-coverage-restricted-"},
			Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
				PolicyRef:  authorizationv1alpha1.RBACPolicyReference{Name: policy.Name},
				TargetName: "discovery-coverage-restricted-role", TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}
		Expect(k8sClient.Create(ctx, rrd)).To(Succeed())
		roleKeys := []client.ObjectKey{roleKey, {Name: rrd.Spec.TargetName}}
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), rd))).To(Succeed())
			Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), rrd))).To(Succeed())
			Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), policy))).To(Succeed())
			for _, key := range roleKeys {
				Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(),
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: key.Name}}))).To(Succeed())
			}
		})
		for _, key := range roleKeys {
			Eventually(func() error {
				return k8sClient.Get(ctx, key, &rbacv1.ClusterRole{})
			}).WithTimeout(20 * time.Second).Should(Succeed())
		}
		resourcePresent := func() bool {
			resources, err := tracker.GetAPIResources()
			Expect(err).NotTo(HaveOccurred())
			for _, resource := range resources[crd.Spec.Group+"/v1"] {
				if resource.Name == crd.Spec.Names.Plural {
					return true
				}
			}
			return false
		}
		rulePresent := func(key client.ObjectKey) bool {
			var role rbacv1.ClusterRole
			Expect(k8sClient.Get(ctx, key, &role)).To(Succeed())
			for _, rule := range role.Rules {
				if len(rule.APIGroups) == 1 && rule.APIGroups[0] == crd.Spec.Group {
					for _, resource := range rule.Resources {
						if resource == crd.Spec.Names.Plural {
							Expect(rule.Verbs).To(ContainElement("get"))
							return true
						}
					}
				}
			}
			return false
		}
		Expect(resourcePresent()).To(BeFalse())
		for _, key := range roleKeys {
			Expect(rulePresent(key)).To(BeFalse())
		}
		Expect(k8sClient.Create(ctx, crd)).To(Succeed())
		Expect(waiter.WaitForCRDs(ctx, []schema.GroupVersionKind{gvk}, 20*time.Second)).To(Succeed())
		Eventually(resourcePresent).WithTimeout(30 * time.Second).Should(BeTrue())
		for _, key := range roleKeys {
			Eventually(func() bool { return rulePresent(key) }).WithTimeout(30 * time.Second).Should(BeTrue())
		}

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(crd), crd)).To(Succeed())
		crd.Finalizers = append(crd.Finalizers, coverageCRDFinalizer)
		Expect(k8sClient.Update(ctx, crd)).To(Succeed())
		Expect(k8sClient.Delete(ctx, crd)).To(Succeed())
		Eventually(func() bool {
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(crd), crd)).To(Succeed())
			return crd.DeletionTimestamp != nil
		}).WithTimeout(10 * time.Second).Should(BeTrue())
		Consistently(resourcePresent).WithTimeout(500 * time.Millisecond).Should(BeTrue())
		for _, key := range roleKeys {
			Expect(rulePresent(key)).To(BeTrue(), "terminating CRDs retain their rules until deletion")
		}
		Expect(releaseCoverageCRD(ctx, client.ObjectKeyFromObject(crd))).To(Succeed())
		Eventually(resourcePresent).WithTimeout(30 * time.Second).Should(BeFalse())
		for _, key := range roleKeys {
			Eventually(func() bool { return rulePresent(key) }).WithTimeout(30 * time.Second).Should(BeFalse())
		}
	})
})
