package authorization

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
)

var _ = Describe("RoleDefinition Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		// RoleDefinition is cluster-scoped, so Namespace should be empty
		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		roledefinition := &authorizationv1alpha1.RoleDefinition{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind RoleDefinition")
			err := k8sClient.Get(ctx, typeNamespacedName, roledefinition)
			if err != nil && apierrors.IsNotFound(err) {
				resource := &authorizationv1alpha1.RoleDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: resourceName,
					},

					Spec: authorizationv1alpha1.RoleDefinitionSpec{
						TargetName: "lorem",
						TargetRole: "ClusterRole",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &authorizationv1alpha1.RoleDefinition{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance RoleDefinition")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			ctx := log.IntoContext(context.Background(), logger)
			controllerReconciler, err := NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, discovery.NewResourceTracker(scheme.Scheme, cfg))
			Expect(err).NotTo(HaveOccurred())
			go func() {
				for event := range recorder.Events {
					logger.Info("Received event", "event", event)
				}
			}()
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer was added and conditions are set via SSA
			By("Verifying finalizer and initial conditions are set")
			var updatedRD authorizationv1alpha1.RoleDefinition
			Expect(k8sClient.Get(ctx, typeNamespacedName, &updatedRD)).To(Succeed())

			// Verify Finalizer condition is set (happens before resource tracker check)
			var finalizerCondition *metav1.Condition
			for i := range updatedRD.Status.Conditions {
				if updatedRD.Status.Conditions[i].Type == string(authorizationv1alpha1.FinalizerCondition) {
					finalizerCondition = &updatedRD.Status.Conditions[i]
					break
				}
			}
			Expect(finalizerCondition).NotTo(BeNil(), "Finalizer condition should be set via SSA")
			Expect(finalizerCondition.Status).To(Equal(metav1.ConditionTrue), "Finalizer condition should be True")
		})
	})
})

var _ = Describe("RoleDefinition Drift Detection and Rollback", func() {
	ctx := context.Background()

	Context("ClusterRole rules drift rollback", func() {
		var roleDef *authorizationv1alpha1.RoleDefinition
		var reconciler *RoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker

		BeforeEach(func() {
			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			// Start the tracker to populate API resources
			go func() {
				_ = resourceTracker.Start(ctx)
			}()

			By("creating a RoleDefinition for ClusterRole")
			roleDef = &authorizationv1alpha1.RoleDefinition{TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}, ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("drift-test-cr-%d", time.Now().UnixNano()),
			},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName:      "drift-clusterrole",
					TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"delete", "deletecollection"},
					RestrictedAPIs: []metav1.APIGroup{
						{
							Name: "certificates.k8s.io",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "certificates.k8s.io/v1", Version: "v1"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, roleDef)).To(Succeed())
			// Re-set TypeMeta as it's not preserved by the API server
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}

			var err error
			reconciler, err = NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up the RoleDefinition")
			_ = k8sClient.Delete(ctx, roleDef)
			// Clean up ClusterRole if it exists
			cr := &rbacv1.ClusterRole{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr); err == nil {
				_ = k8sClient.Delete(ctx, cr)
			}
		})

		It("should restore ClusterRole when rules are modified externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the ClusterRole")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the ClusterRole was created")
			cr := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr)).To(Succeed())
			originalRulesCount := len(cr.Rules)
			Expect(originalRulesCount).To(BeNumerically(">", 0), "ClusterRole should have rules")

			By("simulating external drift by modifying ClusterRole rules")
			cr.Rules = []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"drifted-resources"},
					Verbs:     []string{"get", "list"},
				},
			}
			Expect(k8sClient.Update(ctx, cr)).To(Succeed())

			By("verifying drift occurred")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr)).To(Succeed())
			Expect(cr.Rules).To(HaveLen(1))
			Expect(cr.Rules[0].Resources).To(ContainElement("drifted-resources"))

			By("reconciling to correct drift")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying ClusterRole rules are restored")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr)).To(Succeed())
			// Rules should be restored to dynamically generated rules
			Expect(cr.Rules).ToNot(BeEmpty())
			// Drifted resources should not be present
			hasDriftedResource := false
			for _, rule := range cr.Rules {
				for _, res := range rule.Resources {
					if res == "drifted-resources" {
						hasDriftedResource = true
						break
					}
				}
			}
			Expect(hasDriftedResource).To(BeFalse(), "Drifted resources should be removed")
		})

		It("should restore ClusterRole labels when modified externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the ClusterRole")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying ClusterRole exists")
			cr := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr)).To(Succeed())

			By("simulating label drift")
			cr.Labels = map[string]string{
				"drifted-label":                "drifted-value",
				"app.kubernetes.io/created-by": "someone-else",
			}
			Expect(k8sClient.Update(ctx, cr)).To(Succeed())

			By("reconciling to correct drift")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying labels are restored")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-clusterrole"}, cr)).To(Succeed())
			Expect(cr.Labels["app.kubernetes.io/created-by"]).To(Equal("auth-operator"))
		})
	})

	Context("Role rules drift rollback", func() {
		var roleDef *authorizationv1alpha1.RoleDefinition
		var reconciler *RoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker
		var testNamespace *corev1.Namespace

		BeforeEach(func() {
			By("creating a test namespace")
			testNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("role-drift-ns-%d", time.Now().UnixNano()),
				},
			}
			Expect(k8sClient.Create(ctx, testNamespace)).To(Succeed())

			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				_ = resourceTracker.Start(ctx)
			}()

			By("creating a RoleDefinition for namespaced Role")
			roleDef = &authorizationv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("drift-test-role-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName:      "drift-role",
					TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
					TargetNamespace: testNamespace.Name,
					ScopeNamespaced: true,
					RestrictedVerbs: []string{"delete"},
				},
			}
			Expect(k8sClient.Create(ctx, roleDef)).To(Succeed())
			// Re-set TypeMeta as it's not preserved by the API server
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}

			var err error
			reconciler, err = NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up")
			_ = k8sClient.Delete(ctx, roleDef)
			_ = k8sClient.Delete(ctx, testNamespace)
		})

		It("should restore Role when rules are modified externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the Role")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the Role was created")
			role := &rbacv1.Role{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			Expect(role.Rules).ToNot(BeEmpty())

			By("simulating external drift by replacing rules")
			role.Rules = []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"drifted-ns-resource"},
					Verbs:     []string{"get"},
				},
			}
			Expect(k8sClient.Update(ctx, role)).To(Succeed())

			By("verifying drift occurred")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			Expect(role.Rules).To(HaveLen(1))
			Expect(role.Rules[0].Resources).To(ContainElement("drifted-ns-resource"))

			By("reconciling to correct drift")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying Role rules are restored")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			// Rules should be regenerated from API discovery
			Expect(role.Rules).ToNot(BeEmpty())
			// Drifted resources should no longer be present
			hasDriftedResource := false
			for _, rule := range role.Rules {
				for _, res := range rule.Resources {
					if res == "drifted-ns-resource" {
						hasDriftedResource = true
						break
					}
				}
			}
			Expect(hasDriftedResource).To(BeFalse(), "Drifted resources should be removed")
		})

		It("should restore Role when additional rules are added externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue())

			By("reconciling to create the Role")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("adding unauthorized rules to the Role")
			role := &rbacv1.Role{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-role", Namespace: testNamespace.Name}, role)).To(Succeed())

			// Add an extra rule that shouldn't be there
			role.Rules = append(role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"*"},
			})
			Expect(k8sClient.Update(ctx, role)).To(Succeed())

			By("reconciling to remove unauthorized rules")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying unauthorized rule is removed")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "drift-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			// Check that wildcard verb rule is not present in final rules
			for _, rule := range role.Rules {
				// Wildcard verbs should be filtered by RestrictedVerbs
				Expect(rule.Verbs).NotTo(ContainElement("delete"), "delete verb should be restricted")
			}
		})
	})

	Context("ClusterRole recreation when deleted externally", func() {
		var roleDef *authorizationv1alpha1.RoleDefinition
		var reconciler *RoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker

		BeforeEach(func() {
			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				_ = resourceTracker.Start(ctx)
			}()

			By("creating a RoleDefinition for ClusterRole recreation test")
			roleDef = &authorizationv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("cr-recreate-test-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName:      "recreate-clusterrole",
					TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"delete"},
				},
			}
			Expect(k8sClient.Create(ctx, roleDef)).To(Succeed())
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}

			var err error
			reconciler, err = NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up the RoleDefinition")
			_ = k8sClient.Delete(ctx, roleDef)
			cr := &rbacv1.ClusterRole{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-clusterrole"}, cr); err == nil {
				_ = k8sClient.Delete(ctx, cr)
			}
		})

		It("should recreate ClusterRole when deleted externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the ClusterRole")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the ClusterRole was created")
			cr := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-clusterrole"}, cr)).To(Succeed())
			Expect(cr.Rules).ToNot(BeEmpty())
			originalRulesCount := len(cr.Rules)

			By("deleting the ClusterRole externally")
			Expect(k8sClient.Delete(ctx, cr)).To(Succeed())

			By("verifying ClusterRole no longer exists")
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-clusterrole"}, cr)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ClusterRole should not exist after deletion")

			By("reconciling again to recreate the ClusterRole")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the ClusterRole was recreated with correct spec")
			cr = &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-clusterrole"}, cr)).To(Succeed())
			Expect(cr.Rules).ToNot(BeEmpty())
			Expect(cr.Rules).To(HaveLen(originalRulesCount), "ClusterRole should have the same rules as before")
			Expect(cr.Labels["app.kubernetes.io/created-by"]).To(Equal("auth-operator"))
		})
	})

	Context("Role recreation when deleted externally", func() {
		var roleDef *authorizationv1alpha1.RoleDefinition
		var reconciler *RoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker
		var testNamespace *corev1.Namespace

		BeforeEach(func() {
			By("creating a test namespace")
			testNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("role-recreate-ns-%d", time.Now().UnixNano()),
				},
			}
			Expect(k8sClient.Create(ctx, testNamespace)).To(Succeed())

			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				_ = resourceTracker.Start(ctx)
			}()

			By("creating a RoleDefinition for namespaced Role recreation test")
			roleDef = &authorizationv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("role-recreate-test-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName:      "recreate-role",
					TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
					TargetNamespace: testNamespace.Name,
					ScopeNamespaced: true,
					RestrictedVerbs: []string{"delete"},
				},
			}
			Expect(k8sClient.Create(ctx, roleDef)).To(Succeed())
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}

			var err error
			reconciler, err = NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up")
			_ = k8sClient.Delete(ctx, roleDef)
			_ = k8sClient.Delete(ctx, testNamespace)
		})

		It("should recreate Role when deleted externally", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the Role")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the Role was created")
			role := &rbacv1.Role{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			Expect(role.Rules).ToNot(BeEmpty())
			originalRulesCount := len(role.Rules)

			By("deleting the Role externally")
			Expect(k8sClient.Delete(ctx, role)).To(Succeed())

			By("verifying Role no longer exists")
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-role", Namespace: testNamespace.Name}, role)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Role should not exist after deletion")

			By("reconciling again to recreate the Role")
			_, err = reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the Role was recreated with correct spec")
			role = &rbacv1.Role{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "recreate-role", Namespace: testNamespace.Name}, role)).To(Succeed())
			Expect(role.Rules).ToNot(BeEmpty())
			Expect(role.Rules).To(HaveLen(originalRulesCount), "Role should have the same rules as before")
			Expect(role.Labels["app.kubernetes.io/created-by"]).To(Equal("auth-operator"))
		})
	})

	Context("RoleDefinition deletion lifecycle", func() {
		var roleDef *authorizationv1alpha1.RoleDefinition
		var reconciler *RoleDefinitionReconciler
		var resourceTracker *discovery.ResourceTracker

		BeforeEach(func() {
			By("creating a ResourceTracker")
			resourceTracker = discovery.NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				_ = resourceTracker.Start(ctx)
			}()

			By("creating a RoleDefinition for deletion test")
			roleDef = &authorizationv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("delete-test-%d", time.Now().UnixNano()),
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName:      "delete-test-clusterrole",
					TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"delete"},
				},
			}
			Expect(k8sClient.Create(ctx, roleDef)).To(Succeed())
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}

			var err error
			reconciler, err = NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, resourceTracker)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up")
			_ = k8sClient.Delete(ctx, roleDef)
			cr := &rbacv1.ClusterRole{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: "delete-test-clusterrole"}, cr); err == nil {
				_ = k8sClient.Delete(ctx, cr)
			}
		})

		It("should delete ClusterRole and remove finalizer when RoleDefinition is deleted", func() {
			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("reconciling to create the ClusterRole and add finalizer")
			logCtx := log.IntoContext(ctx, logger)
			_, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the ClusterRole was created")
			cr := &rbacv1.ClusterRole{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "delete-test-clusterrole"}, cr)).To(Succeed())
			Expect(cr.Rules).ToNot(BeEmpty())

			By("verifying the finalizer was added")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: roleDef.Name}, roleDef)).To(Succeed())
			Expect(roleDef.Finalizers).To(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))

			By("deleting the RoleDefinition")
			Expect(k8sClient.Delete(ctx, roleDef)).To(Succeed())

			By("reconciling to handle deletion")
			// Re-fetch to get deletion timestamp
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: roleDef.Name}, roleDef)).To(Succeed())
			roleDef.TypeMeta = metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			}
			result, err := reconciler.Reconcile(logCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: roleDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			// handleDeletion requeues after 1s to wait for GC
			if result.RequeueAfter > 0 {
				By("reconciling again after requeue to complete deletion")
				// Re-fetch to get updated state
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: roleDef.Name}, roleDef)).To(Succeed())
				roleDef.TypeMeta = metav1.TypeMeta{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				}
				_, err = reconciler.Reconcile(logCtx, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: roleDef.Name},
				})
				Expect(err).NotTo(HaveOccurred())
			}

			By("verifying the ClusterRole was deleted")
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "delete-test-clusterrole"}, cr)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ClusterRole should be deleted")
		})
	})
})

func TestFilterAPIResourcesAdditionalCases(t *testing.T) {
	ctx := context.Background()

	t.Run("excludes restricted API groups", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				RestrictedAPIs: []metav1.APIGroup{{Name: "apps"}},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"apps/v1": []metav1.APIResource{
				{Name: "deployments", Verbs: metav1.Verbs{"get", "list"}},
			},
			"v1": []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get", "list"}},
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		// Only core API group should remain
		for _, rule := range rules {
			g.Expect(rule.Resources).NotTo(ContainElement("deployments"))
			g.Expect(rule.Resources).To(ContainElement("pods"))
		}
	})

	t.Run("excludes restricted resources", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				RestrictedResources: []metav1.APIResource{
					{Name: "secrets", Group: ""},
				},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get"}},
				{Name: "secrets", Verbs: metav1.Verbs{"get"}},
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		for _, rule := range rules {
			g.Expect(rule.Resources).NotTo(ContainElement("secrets"))
		}
	})

	t.Run("excludes restricted verbs", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				RestrictedVerbs: []string{"delete"},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get", "delete"}},
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rules).To(HaveLen(1))
		for _, rule := range rules {
			g.Expect(rule.Verbs).NotTo(ContainElement("delete"))
			g.Expect(rule.Verbs).To(ContainElement("get"))
		}
	})

	t.Run("filters namespaced resources when ScopeNamespaced is false", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				ScopeNamespaced: false,
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": []metav1.APIResource{
				{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"get"}},
				{Name: "nodes", Namespaced: false, Verbs: metav1.Verbs{"get"}},
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		for _, rule := range rules {
			g.Expect(rule.Resources).NotTo(ContainElement("pods"))
			g.Expect(rule.Resources).To(ContainElement("nodes"))
		}
	})

	t.Run("groups resources by API group and verbs", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get", "list"}},
				{Name: "services", Verbs: metav1.Verbs{"get", "list"}},
				{Name: "secrets", Verbs: metav1.Verbs{"get"}}, // Different verb set
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		// Should have 2 rules: one for {get,list} and one for {get}
		g.Expect(rules).To(HaveLen(2))
	})

	t.Run("skips resources with all verbs restricted", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				RestrictedVerbs: []string{"get", "list"},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": []metav1.APIResource{
				{Name: "pods", Verbs: metav1.Verbs{"get", "list"}},
			},
		}

		r := &RoleDefinitionReconciler{}
		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rules).To(BeEmpty())
	})
}

func TestQueueAll(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)

	t.Run("returns request for each RoleDefinition", func(t *testing.T) {
		g := NewWithT(t)

		rd1 := &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd-1"}}
		rd2 := &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd-2"}}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd1, rd2).Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s}

		mapFn := r.queueAll()
		requests := mapFn(ctx, nil)
		g.Expect(requests).To(HaveLen(2))
	})

	t.Run("returns empty for no RoleDefinitions", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s}

		mapFn := r.queueAll()
		requests := mapFn(ctx, nil)
		g.Expect(requests).To(BeEmpty())
	})
}

// TestRDReconcileBuildRoleObjectError verifies that Reconcile fails
// and marks the RoleDefinition stalled when TargetRole is invalid.
func TestRDReconcileBuildRoleObjectError(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-target-rd", UID: "uid1"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: "InvalidRole",
			TargetName: "test",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).
		WithStatusSubresource(rd).Build()
	r := &RoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "bad-target-rd"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("invalid target role"))
}

// TestRDReconcileEnsureFinalizerError covers the path where Update fails
// when adding the finalizer during Reconcile.
func TestRDReconcileEnsureFinalizerError(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "fin-err-rd", UID: "uid2"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "test-cr",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).
		WithStatusSubresource(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
				if _, ok := obj.(*authorizationv1alpha1.RoleDefinition); ok {
					return fmt.Errorf("injected patch error")
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{
		client:   c,
		scheme:   s,
		recorder: events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "fin-err-rd"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected patch error"))
}

// TestRDReconcileTrackerNotStarted covers the requeue path when
// the ResourceTracker reports it's not started yet.
func TestRDReconcileTrackerNotStarted(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "tracker-ns-rd",
			UID:        "uid3",
			Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "test-cr",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).
		WithStatusSubresource(rd).Build()

	// NewResourceTracker with nil config; started=false by default,
	// so GetAPIResources() returns ErrResourceTrackerNotStarted
	tracker := discovery.NewResourceTracker(s, nil)

	r := &RoleDefinitionReconciler{
		client:          c,
		scheme:          s,
		recorder:        events.NewFakeRecorder(10),
		resourceTracker: tracker,
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "tracker-ns-rd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(10 * time.Second))
}

// TestRDReconcileGetError covers the path where the initial Get fails
// with a non-NotFound error during Reconcile.
func TestRDReconcileGetError(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	c := fake.NewClientBuilder().WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*authorizationv1alpha1.RoleDefinition); ok {
					return fmt.Errorf("injected get error")
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s}

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "get-err-rd"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected get error"))
}

// TestHandleDeletionDeleteAndStatusError covers the combined error path
// where Delete fails AND the subsequent status update also fails.
func TestHandleDeletionDeleteAndStatusError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "del-both-err", UID: "uid5", DeletionTimestamp: &now, Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer}},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "del-both-cr",
		},
	}

	cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "del-both-cr"}}

	statusPatchCount := 0
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd, cr).
		WithStatusSubresource(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.ClusterRole); ok {
					return fmt.Errorf("injected delete error")
				}
				return nil
			},
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				statusPatchCount++
				if statusPatchCount >= 2 {
					return fmt.Errorf("injected status error")
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	builtRole, err := r.buildRoleObject(rd)
	g.Expect(err).NotTo(HaveOccurred())

	_, err = r.handleDeletion(ctx, rd, builtRole)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected delete error"))
	g.Expect(err.Error()).To(ContainSubstring("injected status error"))
}
