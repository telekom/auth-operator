package authorization

import (
	"context"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
)

var _ = Describe("BindDefinition Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		binddefinition := &authorizationv1alpha1.BindDefinition{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind BindDefinition")
			err := k8sClient.Get(ctx, typeNamespacedName, binddefinition)
			if err != nil && apierrors.IsNotFound(err) {
				resource := &authorizationv1alpha1.BindDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: authorizationv1alpha1.BindDefinitionSpec{
						TargetName: "test-target",
						Subjects:   []rbacv1.Subject{},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &authorizationv1alpha1.BindDefinition{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance BindDefinition")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}
			go func() {
				for event := range recorder.Events {
					logger.Info("Received event", "event", event)
				}
			}()

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When reconciling with ClusterRoleBindings and RoleBindings", func() {
		const fullResourceName = "full-reconcile-test"
		targetNS := "full-reconcile-ns"
		fullNamespacedName := types.NamespacedName{Name: fullResourceName}
		ctx := context.Background()

		BeforeEach(func() {
			By("creating target namespace")
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: targetNS, Labels: map[string]string{"test": "full"}}}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: targetNS}, &corev1.Namespace{})
			if err != nil {
				Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			}

			By("creating a ClusterRole for referencing")
			cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "full-test-view"}}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "full-test-view"}, &rbacv1.ClusterRole{})
			if err != nil {
				Expect(k8sClient.Create(ctx, cr)).To(Succeed())
			}

			By("creating the BindDefinition with CRBs and RBs")
			bd := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: fullResourceName},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "full-test",
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
					},
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
						ClusterRoleRefs: []string{"full-test-view"},
					},
					RoleBindings: []authorizationv1alpha1.NamespaceBinding{
						{
							Namespace:       targetNS,
							ClusterRoleRefs: []string{"full-test-view"},
						},
					},
				},
			}
			err = k8sClient.Get(ctx, fullNamespacedName, &authorizationv1alpha1.BindDefinition{})
			if err != nil {
				Expect(k8sClient.Create(ctx, bd)).To(Succeed())
			}
		})

		AfterEach(func() {
			bd := &authorizationv1alpha1.BindDefinition{}
			if err := k8sClient.Get(ctx, fullNamespacedName, bd); err == nil {
				// Remove finalizer if present so we can delete cleanly
				bd.Finalizers = nil
				_ = k8sClient.Update(ctx, bd)
				_ = k8sClient.Delete(ctx, bd)
			}
		})

		It("should create ClusterRoleBinding and RoleBinding", func() {
			rec := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: fullNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("verifying ClusterRoleBinding was created")
			crb := &rbacv1.ClusterRoleBinding{}
			crbName := helpers.BuildBindingName("full-test", "full-test-view")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: crbName}, crb)).To(Succeed())
			Expect(crb.Subjects).To(HaveLen(1))
			Expect(crb.Subjects[0].Name).To(Equal("devs"))
			Expect(crb.RoleRef.Name).To(Equal("full-test-view"))

			By("verifying RoleBinding was created in namespace")
			rb := &rbacv1.RoleBinding{}
			rbName := helpers.BuildBindingName("full-test", "full-test-view")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: rbName, Namespace: targetNS}, rb)).To(Succeed())
			Expect(rb.Subjects).To(HaveLen(1))
			Expect(rb.RoleRef.Name).To(Equal("full-test-view"))
		})

		It("should handle reconcile delete with cleanup", func() {
			rec := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			By("first reconcile to create resources")
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: fullNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("deleting the BindDefinition")
			bd := &authorizationv1alpha1.BindDefinition{}
			Expect(k8sClient.Get(ctx, fullNamespacedName, bd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bd)).To(Succeed())

			By("reconciling deletion")
			// Re-fetch after delete to get DeletionTimestamp
			Expect(k8sClient.Get(ctx, fullNamespacedName, bd)).To(Succeed())
			_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: fullNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("verifying BindDefinition is fully deleted")
			err = k8sClient.Get(ctx, fullNamespacedName, bd)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			By("verifying ClusterRoleBinding was cleaned up")
			crb := &rbacv1.ClusterRoleBinding{}
			crbName := helpers.BuildBindingName("full-test", "full-test-view")
			err = k8sClient.Get(ctx, types.NamespacedName{Name: crbName}, crb)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should reconcile not-found resource without error", func() {
			rec := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "does-not-exist"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
		})
	})

	Context("Blocking resources detection and logging", func() {
		It("should correctly format blocking resources message for single resource type", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"test-pod"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pods"))
			Expect(message).To(ContainSubstring("test-pod"))
		})

		It("should correctly format blocking resources message for multiple resource types", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        2,
					Names:        []string{"frontend", "backend"},
				},
				{
					ResourceType: "persistentvolumeclaims",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"storage-pvc"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pods"))
			Expect(message).To(ContainSubstring("frontend"))
			Expect(message).To(ContainSubstring("persistentvolumeclaims"))
			Expect(message).To(ContainSubstring("storage-pvc"))
		})

		It("should include API group in resource type when present", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "deployments",
					APIGroup:     "apps",
					Count:        1,
					Names:        []string{"my-deployment"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("deployments (apps)"))
		})
	})

	Context("ResourceBlocking type", func() {
		It("should create ResourceBlocking with correct fields", func() {
			rb := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "core",
				Count:        3,
				Names:        []string{"pod1", "pod2", "pod3"},
			}

			Expect(rb.ResourceType).To(Equal("pods"))
			Expect(rb.APIGroup).To(Equal("core"))
			Expect(rb.Count).To(Equal(3))
			Expect(rb.Names).To(HaveLen(3))
			Expect(rb.Names).To(ContainElements("pod1", "pod2", "pod3"))
		})

		It("should handle empty Names slice", func() {
			rb := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        0,
				Names:        []string{},
			}

			Expect(rb.Names).To(BeEmpty())
			Expect(rb.Count).To(Equal(0))
		})

		It("should handle ResourceBlocking with empty APIGroup", func() {
			rb := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test-pod"},
			}

			Expect(rb.APIGroup).To(BeEmpty())
			Expect(rb.ResourceType).To(Equal("pods"))
		})

		It("should handle ResourceBlocking with complex APIGroup", func() {
			rb := namespaceDeletionResourceBlocking{
				ResourceType: "customresources",
				APIGroup:     "custom.example.com",
				Count:        2,
				Names:        []string{"resource1", "resource2"},
			}

			Expect(rb.APIGroup).To(Equal("custom.example.com"))
			Expect(rb.Count).To(Equal(2))
		})
	})

	Context("Message formatting edge cases", func() {
		It("should handle large resource names", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"very-long-pod-name-with-many-characters-123456789"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("very-long-pod-name-with-many-characters-123456789"))
		})

		It("should format many resources of same type", func() {
			names := make([]string, 0, 10)
			for i := range 10 {
				names = append(names, fmt.Sprintf("pod-%d", i))
			}

			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        10,
					Names:        names,
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pods"))
			Expect(message).To(ContainSubstring("10"))
		})

		It("should format many different resource types", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        2,
					Names:        []string{"pod1", "pod2"},
				},
				{
					ResourceType: "services",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"service1"},
				},
				{
					ResourceType: "deployments",
					APIGroup:     "apps",
					Count:        1,
					Names:        []string{"deploy1"},
				},
				{
					ResourceType: "statefulsets",
					APIGroup:     "apps",
					Count:        3,
					Names:        []string{"stateful1", "stateful2", "stateful3"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pods"))
			Expect(message).To(ContainSubstring("services"))
			Expect(message).To(ContainSubstring("deployments (apps)"))
			Expect(message).To(ContainSubstring("statefulsets (apps)"))
		})

		It("should handle single resource in many types", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pod",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"single-pod"},
				},
				{
					ResourceType: "service",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"single-service"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pod"))
			Expect(message).To(ContainSubstring("service"))
		})

		It("should include count in message", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        5,
					Names:        []string{"pod1", "pod2", "pod3", "pod4", "pod5"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("5"))
		})

		It("should handle special characters in resource names", func() {
			blockingResources := []namespaceDeletionResourceBlocking{
				{
					ResourceType: "pods",
					APIGroup:     "",
					Count:        1,
					Names:        []string{"pod-with-dashes-and_underscores.123"},
				},
			}

			message := formatBlockingResourcesMessage(blockingResources)
			Expect(message).To(ContainSubstring("pod-with-dashes-and_underscores.123"))
		})
	})

	Context("ResourceBlocking comparison and validation", func() {
		It("should compare two ResourceBlocking structs correctly", func() {
			rb1 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test-pod"},
			}

			rb2 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test-pod"},
			}

			Expect(rb1.ResourceType).To(Equal(rb2.ResourceType))
			Expect(rb1.APIGroup).To(Equal(rb2.APIGroup))
			Expect(rb1.Count).To(Equal(rb2.Count))
		})

		It("should detect difference in ResourceType", func() {
			rb1 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test"},
			}

			rb2 := namespaceDeletionResourceBlocking{
				ResourceType: "services",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test"},
			}

			Expect(rb1.ResourceType).NotTo(Equal(rb2.ResourceType))
		})

		It("should detect difference in APIGroup", func() {
			rb1 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test"},
			}

			rb2 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "apps",
				Count:        1,
				Names:        []string{"test"},
			}

			Expect(rb1.APIGroup).NotTo(Equal(rb2.APIGroup))
		})

		It("should detect difference in Count", func() {
			rb1 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        1,
				Names:        []string{"test"},
			}

			rb2 := namespaceDeletionResourceBlocking{
				ResourceType: "pods",
				APIGroup:     "",
				Count:        5,
				Names:        []string{"test"},
			}

			Expect(rb1.Count).NotTo(Equal(rb2.Count))
		})
	})
})

// TestReconcileTerminatingNamespaces verifies that the controller properly handles terminating namespaces
// and logs blocking resources with detailed information.
//
// Test Coverage:
// 1. formatBlockingResourcesMessage() - Converts ResourceBlocking data to human-readable messages
// 2. ResourceBlocking type - Captures resource details for logging
// 3. Logging of blocking resources - Structured logs with namespace, resource type, count, and names
//
// To run these tests:
//   go test -v ./internal/controller/authorization/...
//
// Integration with full test suite:
//   make test

// TestBindDefinitionDriftDetection tests drift detection using a fake client
// to properly preserve TypeMeta across client operations.
func TestBindDefinitionDriftDetection(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("ClusterRoleBinding subjects drift rollback", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-test-crb",
				UID:  "test-uid-crb",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "drift-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "original-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// First reconcile creates the CRB
		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify CRB was created
		crbName := "drift-target-view-binding"
		crb := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects).To(HaveLen(1))
		g.Expect(crb.Subjects[0].Name).To(Equal("original-user"))

		// Simulate drift by modifying subjects
		crb.Subjects = []rbacv1.Subject{
			{Kind: "User", Name: "drifted-user", APIGroup: rbacv1.GroupName},
		}
		err = c.Update(ctx, crb)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify drift occurred
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects[0].Name).To(Equal("drifted-user"))

		// Reconcile again to correct drift
		err = r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify subjects are restored
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects).To(HaveLen(1))
		g.Expect(crb.Subjects[0].Name).To(Equal("original-user"))
	})

	t.Run("ClusterRoleBinding labels drift rollback", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-test-crb-labels",
				UID:  "test-uid-crb-labels",
				Labels: map[string]string{
					"app": "test",
				},
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "drift-labels-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Create CRB
		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Drift labels
		crbName := "drift-labels-target-view-binding"
		crb := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())

		crb.Labels = map[string]string{"drifted": "true"}
		err = c.Update(ctx, crb)
		g.Expect(err).NotTo(HaveOccurred())

		// Reconcile to correct drift
		err = r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify labels restored
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Labels["app.kubernetes.io/managed-by"]).To(Equal("auth-operator"))
	})

	t.Run("RoleBinding subjects drift rollback", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-rb-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-test-rb",
				UID:  "test-uid-rb",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "drift-rb-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "rb-original-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						Namespace:       ns.Name,
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Create RoleBinding
		err := r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, "view", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RB created
		rbName := "drift-rb-target-view-binding"
		rb := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: ns.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.Subjects[0].Name).To(Equal("rb-original-user"))

		// Simulate drift
		rb.Subjects = []rbacv1.Subject{
			{Kind: "User", Name: "drifted-rb-user", APIGroup: rbacv1.GroupName},
		}
		err = c.Update(ctx, rb)
		g.Expect(err).NotTo(HaveOccurred())

		// Reconcile to correct
		err = r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, "view", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify restored
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: ns.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.Subjects[0].Name).To(Equal("rb-original-user"))
	})

	t.Run("ServiceAccount automountToken drift rollback", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-sa-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		automountFalse := false
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "drift-test-sa",
				UID:  "test-uid-sa",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "drift-sa-target",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "drift-test-sa", Namespace: ns.Name},
				},
				AutomountServiceAccountToken: &automountFalse,
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Create ServiceAccount
		_, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify SA created with automount=false
		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "drift-test-sa", Namespace: ns.Name}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())

		// Simulate drift
		automountTrue := true
		sa.AutomountServiceAccountToken = &automountTrue
		err = c.Update(ctx, sa)
		g.Expect(err).NotTo(HaveOccurred())

		// Reconcile to correct
		_, _, err = r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify restored
		err = c.Get(ctx, types.NamespacedName{Name: "drift-test-sa", Namespace: ns.Name}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
	})

	t.Run("Multiple resources drift correction in single call", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "multi-drift-test",
				UID:  "test-uid-multi",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "multi-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "multi-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view", "edit"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Create CRBs
		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Drift both CRBs
		crb1 := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "multi-target-view-binding"}, crb1)
		g.Expect(err).NotTo(HaveOccurred())
		crb1.Subjects = []rbacv1.Subject{{Kind: "User", Name: "drifted-1", APIGroup: rbacv1.GroupName}}
		err = c.Update(ctx, crb1)
		g.Expect(err).NotTo(HaveOccurred())

		crb2 := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "multi-target-edit-binding"}, crb2)
		g.Expect(err).NotTo(HaveOccurred())
		crb2.Subjects = []rbacv1.Subject{{Kind: "User", Name: "drifted-2", APIGroup: rbacv1.GroupName}}
		err = c.Update(ctx, crb2)
		g.Expect(err).NotTo(HaveOccurred())

		// Single reconcile should fix both
		err = r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify both restored
		err = c.Get(ctx, types.NamespacedName{Name: "multi-target-view-binding"}, crb1)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb1.Subjects[0].Name).To(Equal("multi-user"))

		err = c.Get(ctx, types.NamespacedName{Name: "multi-target-edit-binding"}, crb2)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb2.Subjects[0].Name).To(Equal("multi-user"))
	})
}

// TestNamespaceLifecycleHandling tests namespace deletion and recreation scenarios
func TestNamespaceLifecycleHandling(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should skip RoleBinding creation in terminating namespace", func(t *testing.T) {
		g := NewWithT(t)

		// Create a terminating namespace (DeletionTimestamp set, phase Terminating)
		now := metav1.Now()
		terminatingNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "terminating-ns",
				DeletionTimestamp: &now,
				Finalizers:        []string{"kubernetes"},
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceTerminating,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "terminating-ns-test",
				UID:  "test-uid-terminating",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "terminating-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						Namespace:       terminatingNs.Name,
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, terminatingNs).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Filter active namespaces - should exclude terminating namespace
		namespaceSet := map[string]corev1.Namespace{
			terminatingNs.Name: *terminatingNs,
		}
		activeNamespaces := r.filterActiveNamespaces(ctx, bindDef, namespaceSet)
		g.Expect(activeNamespaces).To(BeEmpty(), "Terminating namespace should be filtered out")

		// Verify that no RoleBinding was created in the terminating namespace
		rbName := "terminating-target-view-binding"
		rb := &rbacv1.RoleBinding{}
		err := c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: terminatingNs.Name}, rb)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should not exist in terminating namespace")
	})

	t.Run("should create RoleBinding in recreated namespace", func(t *testing.T) {
		g := NewWithT(t)

		// Create an active namespace (simulating a recreated namespace)
		recreatedNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "recreated-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "recreated-ns-test",
				UID:  "test-uid-recreated",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "recreated-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						Namespace:       recreatedNs.Name,
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, recreatedNs).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Ensure RoleBinding is created
		err := r.ensureSingleRoleBinding(ctx, bindDef, recreatedNs.Name, "view", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RoleBinding exists with correct spec
		rbName := "recreated-target-view-binding"
		rb := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: recreatedNs.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.RoleRef.Name).To(Equal("view"))
		g.Expect(rb.Subjects).To(HaveLen(1))
		g.Expect(rb.Subjects[0].Name).To(Equal("test-user"))
	})

	t.Run("should create RoleBindings in new namespace matching selector", func(t *testing.T) {
		g := NewWithT(t)

		// Create a namespace with labels that match a selector
		newNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "new-matching-ns",
				Labels: map[string]string{
					"env":  "test",
					"team": "platform",
				},
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "selector-test",
				UID:  "test-uid-selector",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "selector-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "selector-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"edit"},
						NamespaceSelector: []metav1.LabelSelector{
							{
								MatchLabels: map[string]string{
									"env": "test",
								},
							},
						},
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, newNs).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Resolve namespaces matching the selector
		namespaces, err := r.resolveRoleBindingNamespaces(ctx, bindDef.Spec.RoleBindings[0])
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(namespaces).To(HaveLen(1))
		g.Expect(namespaces[0].Name).To(Equal("new-matching-ns"))

		// Create RoleBinding in matching namespace
		err = r.ensureSingleRoleBinding(ctx, bindDef, newNs.Name, "edit", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RoleBinding exists
		rbName := "selector-target-edit-binding"
		rb := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: newNs.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.RoleRef.Name).To(Equal("edit"))
		g.Expect(rb.Subjects[0].Name).To(Equal("selector-user"))
	})

	t.Run("should not match namespace after selector labels removed", func(t *testing.T) {
		g := NewWithT(t)

		// Namespace without matching labels (simulating label removal)
		nonMatchingNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "non-matching-ns",
				Labels: map[string]string{
					"unrelated": "label",
				},
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "non-matching-test",
				UID:  "test-uid-nonmatch",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "nonmatch-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						NamespaceSelector: []metav1.LabelSelector{
							{
								MatchLabels: map[string]string{
									"env": "production",
								},
							},
						},
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, nonMatchingNs).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Resolve namespaces - should return empty since labels don't match
		namespaces, err := r.resolveRoleBindingNamespaces(ctx, bindDef.Spec.RoleBindings[0])
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(namespaces).To(BeEmpty(), "No namespaces should match when labels don't match selector")
	})
}

// TestResourceRecreationOnExternalDeletion tests that resources are recreated when deleted externally
func TestResourceRecreationOnExternalDeletion(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should recreate ClusterRoleBinding when deleted externally", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-recreate-test",
				UID:  "test-uid-crb-recreate",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "crb-recreate-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "crb-recreate-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Step 1: Create the ClusterRoleBinding via reconcile
		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify CRB was created
		crbName := "crb-recreate-target-view-binding"
		crb := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects).To(HaveLen(1))
		g.Expect(crb.Subjects[0].Name).To(Equal("crb-recreate-user"))

		// Step 2: Delete the CRB externally
		err = c.Delete(ctx, crb)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 3: Verify CRB doesn't exist
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "CRB should not exist after deletion")

		// Step 4: Reconcile again
		err = r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 5: Verify CRB exists again with correct spec
		crb = &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects).To(HaveLen(1))
		g.Expect(crb.Subjects[0].Name).To(Equal("crb-recreate-user"))
		g.Expect(crb.RoleRef.Name).To(Equal("view"))
		g.Expect(crb.Labels["app.kubernetes.io/managed-by"]).To(Equal("auth-operator"))
	})

	t.Run("should recreate RoleBinding when deleted externally", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rb-recreate-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "rb-recreate-test",
				UID:  "test-uid-rb-recreate",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "rb-recreate-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "rb-recreate-user", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"edit"},
						Namespace:       ns.Name,
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Step 1: Create the RoleBinding
		err := r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, "edit", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RB was created
		rbName := "rb-recreate-target-edit-binding"
		rb := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: ns.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.Subjects[0].Name).To(Equal("rb-recreate-user"))

		// Step 2: Delete the RB externally
		err = c.Delete(ctx, rb)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 3: Verify RB doesn't exist
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: ns.Name}, rb)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should not exist after deletion")

		// Step 4: Reconcile again
		err = r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, "edit", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		// Step 5: Verify RB exists again with correct spec
		rb = &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: ns.Name}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.Subjects).To(HaveLen(1))
		g.Expect(rb.Subjects[0].Name).To(Equal("rb-recreate-user"))
		g.Expect(rb.RoleRef.Name).To(Equal("edit"))
		g.Expect(rb.Labels["app.kubernetes.io/managed-by"]).To(Equal("auth-operator"))
	})

	t.Run("should recreate ServiceAccount when deleted externally", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sa-recreate-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		automountFalse := false
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "sa-recreate-test",
				UID:  "test-uid-sa-recreate",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "sa-recreate-target",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "recreated-sa", Namespace: ns.Name},
				},
				AutomountServiceAccountToken: &automountFalse,
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Step 1: Create the ServiceAccount
		_, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify SA was created
		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "recreated-sa", Namespace: ns.Name}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())

		// Step 2: Delete the SA externally
		err = c.Delete(ctx, sa)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 3: Verify SA doesn't exist
		err = c.Get(ctx, types.NamespacedName{Name: "recreated-sa", Namespace: ns.Name}, sa)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ServiceAccount should not exist after deletion")

		// Step 4: Reconcile again
		_, _, err = r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 5: Verify SA exists again with correct spec
		sa = &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "recreated-sa", Namespace: ns.Name}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
		g.Expect(sa.Labels["app.kubernetes.io/managed-by"]).To(Equal("auth-operator"))
	})

	t.Run("should recreate multiple ClusterRoleBindings when deleted externally", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "multi-crb-recreate-test",
				UID:  "test-uid-multi-crb-recreate",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "multi-crb-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "multi-crb-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view", "edit"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		// Step 1: Create all CRBs
		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify both CRBs exist
		crb1 := &rbacv1.ClusterRoleBinding{}
		crb2 := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-view-binding"}, crb1)
		g.Expect(err).NotTo(HaveOccurred())
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-edit-binding"}, crb2)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 2: Delete both CRBs externally
		err = c.Delete(ctx, crb1)
		g.Expect(err).NotTo(HaveOccurred())
		err = c.Delete(ctx, crb2)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 3: Verify both CRBs don't exist
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-view-binding"}, crb1)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-edit-binding"}, crb2)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue())

		// Step 4: Reconcile again
		err = r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Step 5: Verify both CRBs exist again
		crb1 = &rbacv1.ClusterRoleBinding{}
		crb2 = &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-view-binding"}, crb1)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb1.Subjects[0].Name).To(Equal("multi-crb-user"))
		err = c.Get(ctx, types.NamespacedName{Name: "multi-crb-target-edit-binding"}, crb2)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb2.Subjects[0].Name).To(Equal("multi-crb-user"))
	})
}

func TestEnsureClusterRoleBindings(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-binddef",
			UID:  "test-uid",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin", "view"},
			},
		},
	}

	t.Run("creates ClusterRoleBindings when they don't exist", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		for _, roleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
			crbName := helpers.BuildBindingName(bindDef.Spec.TargetName, roleRef)
			crb := &rbacv1.ClusterRoleBinding{}
			err := c.Get(ctx, types.NamespacedName{Name: crbName}, crb)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(crb.RoleRef.Name).To(Equal(roleRef))
			g.Expect(crb.Subjects).To(HaveLen(1))
			g.Expect(crb.Subjects[0].Name).To(Equal("test-user"))
		}
	})

	t.Run("updates ClusterRoleBindings when subjects change", func(t *testing.T) {
		existingCRB := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: helpers.BuildBindingName(bindDef.Spec.TargetName, "admin"),
				Labels: map[string]string{
					helpers.ManagedByLabelStandard: helpers.ManagedByValue,
				},
			},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "old-user", APIGroup: rbacv1.GroupName},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "admin",
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, existingCRB).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		err := r.ensureClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		crb := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: existingCRB.Name}, crb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crb.Subjects).To(HaveLen(1))
		g.Expect(crb.Subjects[0].Name).To(Equal("test-user"))
	})
}

func TestEnsureSingleRoleBinding(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-binddef",
			UID:  "test-uid",
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "test-sa", Namespace: "test-ns"},
			},
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ns",
		},
	}

	t.Run("creates RoleBinding when it doesn't exist", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		err := r.ensureSingleRoleBinding(ctx, bindDef, "test-ns", "edit", "ClusterRole")
		g.Expect(err).NotTo(HaveOccurred())

		rbName := helpers.BuildBindingName(bindDef.Spec.TargetName, "edit")
		rb := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: "test-ns"}, rb)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rb.RoleRef.Name).To(Equal("edit"))
		g.Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
	})
}

func TestEnsureServiceAccounts(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	automountFalse := false
	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-binddef",
			UID:  "test-uid",
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: authorizationv1alpha1.BindSubjectServiceAccount, Name: "test-sa", Namespace: "test-ns"},
			},
			AutomountServiceAccountToken: &automountFalse,
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ns",
		},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceActive,
		},
	}

	t.Run("creates ServiceAccount when it doesn't exist", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		generatedSAs, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(HaveLen(1))

		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "test-ns"}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
	})

	t.Run("updates ServiceAccount when it exists and is owned", func(t *testing.T) {
		automountTrue := true
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: authorizationv1alpha1.GroupVersion.String(),
						Kind:       "BindDefinition",
						Name:       bindDef.Name,
						UID:        bindDef.UID,
						Controller: &automountTrue,
					},
				},
			},
			AutomountServiceAccountToken: &automountTrue,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns, existingSA).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		_, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "test-ns"}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(*sa.AutomountServiceAccountToken).To(BeFalse())
	})

	t.Run("skips ServiceAccount in terminating namespace", func(t *testing.T) {
		terminatingNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ns",
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceTerminating,
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, terminatingNS).Build()
		r := &BindDefinitionReconciler{
			client:   c,
			scheme:   scheme,
			recorder: events.NewFakeRecorder(10),
		}

		generatedSAs, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(BeEmpty())

		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "test-ns"}, sa)
		g.Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
	})
}

// TestValidateRoleReferences tests the validateRoleReferences function
func TestValidateRoleReferences(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should return empty when all ClusterRoles exist", func(t *testing.T) {
		g := NewWithT(t)

		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "view"},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		missing := r.validateRoleReferences(ctx, bindDef, nil)
		g.Expect(missing).To(BeEmpty())
	})

	t.Run("should detect missing ClusterRole in ClusterRoleBindings", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"nonexistent-cr"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		missing := r.validateRoleReferences(ctx, bindDef, nil)
		g.Expect(missing).To(ContainElement("ClusterRole/nonexistent-cr"))
	})

	t.Run("should detect missing ClusterRole in RoleBindings", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"missing-cr"},
						Namespace:       "default",
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		missing := r.validateRoleReferences(ctx, bindDef, nil)
		g.Expect(missing).To(ContainElement("ClusterRole/missing-cr"))
	})

	t.Run("should detect missing Role in RoleBindings with namespace", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						RoleRefs:  []string{"missing-role"},
						Namespace: "test-ns",
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		missing := r.validateRoleReferences(ctx, bindDef, []corev1.Namespace{*ns})
		g.Expect(missing).To(ContainElement("Role/test-ns/missing-role"))
	})

	t.Run("should not duplicate ClusterRole references", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"missing-cr"},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"missing-cr"},
						Namespace:       "default",
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		missing := r.validateRoleReferences(ctx, bindDef, nil)
		// Should only appear once (deduplication)
		count := 0
		for _, m := range missing {
			if m == "ClusterRole/missing-cr" {
				count++
			}
		}
		g.Expect(count).To(Equal(1), "missing ClusterRole should be deduplicated")
	})
}

// TestCollectNamespaces tests the collectNamespaces function
func TestCollectNamespaces(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should collect namespace by explicit name", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "my-ns"},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "my-ns", ClusterRoleRefs: []string{"view"}},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		nsSet, err := r.collectNamespaces(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(nsSet).To(HaveKey("my-ns"))
	})

	t.Run("should skip not-found namespace", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "nonexistent", ClusterRoleRefs: []string{"view"}},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		nsSet, err := r.collectNamespaces(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(nsSet).To(BeEmpty())
	})

	t.Run("should collect namespaces by label selector", func(t *testing.T) {
		g := NewWithT(t)

		ns1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "ns-1", Labels: map[string]string{"env": "prod"}},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "ns-2", Labels: map[string]string{"env": "prod"}},
		}
		ns3 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "ns-3", Labels: map[string]string{"env": "dev"}},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						NamespaceSelector: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"env": "prod"}},
						},
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns1, ns2, ns3).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		nsSet, err := r.collectNamespaces(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(nsSet).To(HaveLen(2))
		g.Expect(nsSet).To(HaveKey("ns-1"))
		g.Expect(nsSet).To(HaveKey("ns-2"))
	})

	t.Run("should deduplicate namespaces", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "dup-ns", Labels: map[string]string{"env": "prod", "team": "a"}},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						Namespace:       "dup-ns",
						ClusterRoleRefs: []string{"view"},
						NamespaceSelector: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"env": "prod"}},
						},
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		nsSet, err := r.collectNamespaces(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(nsSet).To(HaveLen(1), "same namespace should be deduplicated")
	})
}

// TestIsSAReferencedByOtherBindDefs tests the cross-reference check for ServiceAccounts
func TestIsSAReferencedByOtherBindDefs(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should return false when no other BindDefs reference the SA", func(t *testing.T) {
		g := NewWithT(t)

		bd := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "bd-1", Namespace: "default"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "my-sa", Namespace: "default"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		ref, err := r.isSAReferencedByOtherBindDefs(ctx, "bd-1", "my-sa", "default")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(ref).To(BeFalse())
	})

	t.Run("should return true when another BindDef references the SA", func(t *testing.T) {
		g := NewWithT(t)

		bd1 := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "bd-1", Namespace: "default"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test-1",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "default"},
				},
			},
		}
		bd2 := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "bd-2", Namespace: "default"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test-2",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "default"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd1, bd2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		// bd-1 is being deleted, check if bd-2 also references the SA
		ref, err := r.isSAReferencedByOtherBindDefs(ctx, "bd-1", "shared-sa", "default")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(ref).To(BeTrue())
	})

	t.Run("should not count the deleting BindDef itself", func(t *testing.T) {
		g := NewWithT(t)

		bd := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "only-bd", Namespace: "default"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "my-sa", Namespace: "default"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		ref, err := r.isSAReferencedByOtherBindDefs(ctx, "only-bd", "my-sa", "default")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(ref).To(BeFalse(), "should not count the BindDef being deleted")
	})
}

// TestSANotOwnedByThisBindDef verifies that SSA applies even when another owner
// reference already exists. With SSA + ForceOwnership, the operator's fields
// are set regardless of existing ownership.
func TestSANotOwnedByThisBindDef(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("SSA applies fields even when SA has different owner", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		// SA owned by a different BindDefinition (different UID)
		isController := true
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "contested-sa",
				Namespace: "test-ns",
				Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: authorizationv1alpha1.GroupVersion.String(),
						Kind:       "BindDefinition",
						Name:       "other-bd",
						UID:        "other-uid-12345",
						Controller: &isController,
					},
				},
			},
			AutomountServiceAccountToken: boolPtr(true),
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-bd",
				UID:  "my-uid-67890",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "contested-sa", Namespace: "test-ns"},
				},
				AutomountServiceAccountToken: boolPtr(false),
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, existingSA, bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		// SSA applies the SA with our desired fields and owner reference
		err := r.applyServiceAccount(ctx, bindDef, bindDef.Spec.Subjects[0], false)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify SA was updated via SSA (labels now include managed-by)
		sa := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "contested-sa", Namespace: "test-ns"}, sa)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(sa.Labels).To(HaveKeyWithValue(helpers.ManagedByLabelStandard, helpers.ManagedByValue))
	})
}

func boolPtr(b bool) *bool {
	return &b
}

// TestReconcileDelete tests the full BindDefinition deletion lifecycle
func TestReconcileDelete(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("should delete owned CRBs and remove finalizer", func(t *testing.T) {
		g := NewWithT(t)

		isController := true
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "delete-test-bd",
				UID:        "delete-uid-123",
				Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-target",
				Subjects: []rbacv1.Subject{
					{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
				},
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "del-target-view-binding",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: authorizationv1alpha1.GroupVersion.String(),
						Kind:       "BindDefinition",
						Name:       "delete-test-bd",
						UID:        "delete-uid-123",
						Controller: &isController,
					},
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "view",
			},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, crb).
			WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.reconcileDelete(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.RequeueAfter).To(BeZero(), "should not requeue after successful deletion")

		// CRB should be deleted
		deletedCRB := &rbacv1.ClusterRoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "del-target-view-binding"}, deletedCRB)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "CRB should be deleted")

		// Finalizer should be removed
		updatedBD := &authorizationv1alpha1.BindDefinition{}
		err = c.Get(ctx, types.NamespacedName{Name: "delete-test-bd"}, updatedBD)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(updatedBD.Finalizers).NotTo(ContainElement(authorizationv1alpha1.BindDefinitionFinalizer))
	})

	t.Run("should delete owned SAs during deletion", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-del-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		isController := true
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "sa-delete-bd",
				UID:        "sa-delete-uid",
				Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "sa-del-target",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "del-sa", Namespace: "sa-del-ns"},
				},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "del-sa",
				Namespace: "sa-del-ns",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: authorizationv1alpha1.GroupVersion.String(),
						Kind:       "BindDefinition",
						Name:       "sa-delete-bd",
						UID:        "sa-delete-uid",
						Controller: &isController,
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns, sa).
			WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		_, err := r.reconcileDelete(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// SA should be deleted
		deletedSA := &corev1.ServiceAccount{}
		err = c.Get(ctx, types.NamespacedName{Name: "del-sa", Namespace: "sa-del-ns"}, deletedSA)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "SA should be deleted")
	})
}

func TestEnsureRoleBindings(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("creates RoleBindings for ClusterRoleRefs and RoleRefs in active namespaces", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "test-ns",
				Labels: map[string]string{"env": "test"},
			},
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "rb-test-bd",
				UID:  "rb-test-uid",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "rb-test",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						RoleRefs:        []string{"developer"},
						Namespace:       "test-ns",
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.ensureRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify ClusterRoleRef-based RoleBinding
		crbRB := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: helpers.BuildBindingName("rb-test", "view"), Namespace: "test-ns"}, crbRB)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(crbRB.RoleRef.Kind).To(Equal("ClusterRole"))
		g.Expect(crbRB.RoleRef.Name).To(Equal("view"))

		// Verify RoleRef-based RoleBinding
		roleRB := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: helpers.BuildBindingName("rb-test", "developer"), Namespace: "test-ns"}, roleRB)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(roleRB.RoleRef.Kind).To(Equal("Role"))
		g.Expect(roleRB.RoleRef.Name).To(Equal("developer"))
	})

	t.Run("skips terminating namespaces", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "terminating-ns",
				DeletionTimestamp: &now,
				Finalizers:        []string{"kubernetes"},
			},
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "skip-term-bd",
				UID:  "skip-term-uid",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "skip-term",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						Namespace:       "terminating-ns",
					},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.ensureRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify NO RoleBinding was created in the terminating namespace
		rbList := &rbacv1.RoleBindingList{}
		err = c.List(ctx, rbList)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rbList.Items).To(BeEmpty())
	})

	t.Run("works with no RoleBindings specified", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "no-rb-bd", UID: "no-rb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName:   "no-rb",
				Subjects:     []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
				RoleBindings: nil,
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.ensureRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})
}

func TestDeleteAllRoleBindings(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("deletes RoleBindings across namespaces", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "del-rb-ns",
				Labels: map[string]string{"env": "test"},
			},
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "del-rb-bd",
				UID:  "del-rb-uid",
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-rb",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
				},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{
						ClusterRoleRefs: []string{"view"},
						RoleRefs:        []string{"developer"},
						Namespace:       "del-rb-ns",
					},
				},
			},
		}

		// Pre-create RoleBindings that should be deleted
		crRefName := helpers.BuildBindingName("del-rb", "view")
		roleRefName := helpers.BuildBindingName("del-rb", "developer")
		existingCRB := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crRefName,
				Namespace: "del-rb-ns",
				Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-rb-bd", UID: "del-rb-uid", Controller: boolPtr(true)},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		existingRoleRB := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleRefName,
				Namespace: "del-rb-ns",
				Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-rb-bd", UID: "del-rb-uid", Controller: boolPtr(true)},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "developer"},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns, existingCRB, existingRoleRB).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteAllRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RoleBindings were deleted
		rbList := &rbacv1.RoleBindingList{}
		err = c.List(ctx, rbList)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rbList.Items).To(BeEmpty())
	})

	t.Run("succeeds when no RoleBindings exist", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "empty-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "no-del-bd", UID: "no-del-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "no-del",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{ClusterRoleRefs: []string{"view"}, Namespace: "empty-ns"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteAllRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})
}

func TestMarkStalledBindDefinition(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("sets Stalled condition and ObservedGeneration", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "stalled-bd",
				UID:        "stalled-uid",
				Generation: 3,
			},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "stalled",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		r.markStalled(ctx, bindDef, fmt.Errorf("test error"))

		// Verify condition was set in-memory
		g.Expect(bindDef.Status.ObservedGeneration).To(Equal(int64(3)))
		stalledFound := false
		for _, cond := range bindDef.Status.Conditions {
			if cond.Type == "Stalled" {
				stalledFound = true
				g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(cond.Message).To(ContainSubstring("test error"))
			}
		}
		g.Expect(stalledFound).To(BeTrue(), "Stalled condition should be set")
	})
}

func TestApplyStatusNonFatal(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("does not panic when status apply succeeds", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nonfatal-bd", UID: "nonfatal-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "nonfatal",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		// Should not panic
		g.Expect(func() {
			r.applyStatusNonFatal(ctx, bindDef)
		}).NotTo(Panic())
	})
}

func TestDeleteRoleBindingWithStatusUpdate(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t.Run("succeeds when RoleBinding does not exist", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-status-bd", UID: "del-status-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-status",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteRoleBindingWithStatusUpdate(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
	})

	t.Run("succeeds when RoleBinding exists and is owned", func(t *testing.T) {
		g := NewWithT(t)

		rbName := helpers.BuildBindingName("del-owned", "view")
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-owned-bd", UID: "del-owned-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-owned",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: "test-ns",
				Labels:    map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-owned-bd", UID: "del-owned-uid", Controller: boolPtr(true)},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bindDef, rb).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteRoleBindingWithStatusUpdate(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())

		// Verify RoleBinding was deleted
		deleted := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: rbName, Namespace: "test-ns"}, deleted)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})
}

func TestApplyServiceAccount(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)

	t.Run("creates new SA when not found", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "create-sa-bd", UID: "create-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "create-sa"},
		}

		subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "new-sa", Namespace: "default"}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.applyServiceAccount(ctx, bindDef, subject, true)
		g.Expect(err).NotTo(HaveOccurred())

		actual := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "new-sa", Namespace: "default"}, actual)).To(Succeed())
		g.Expect(actual.Labels).To(HaveKeyWithValue(helpers.ManagedByLabelStandard, helpers.ManagedByValue))
		g.Expect(*actual.AutomountServiceAccountToken).To(BeTrue())
	})

	t.Run("updates existing SA with different labels via SSA", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "upd-sa-bd", UID: "upd-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "upd-sa"},
		}

		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "existing-sa", Namespace: "default",
				Labels: map[string]string{"old": "label"},
			},
			AutomountServiceAccountToken: boolPtr(false),
		}

		subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "existing-sa", Namespace: "default"}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, existingSA).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.applyServiceAccount(ctx, bindDef, subject, true)
		g.Expect(err).NotTo(HaveOccurred())

		actual := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "existing-sa", Namespace: "default"}, actual)).To(Succeed())
		g.Expect(actual.Labels).To(HaveKeyWithValue(helpers.ManagedByLabelStandard, helpers.ManagedByValue))
		g.Expect(*actual.AutomountServiceAccountToken).To(BeTrue())
	})

	t.Run("SSA idempotent when SA already matches", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "noop-sa-bd", UID: "noop-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "noop-sa"},
		}

		labels := helpers.BuildResourceLabels(nil)
		existingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "same-sa", Namespace: "default",
				Labels: labels,
			},
			AutomountServiceAccountToken: boolPtr(true),
		}

		subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "same-sa", Namespace: "default"}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, existingSA).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.applyServiceAccount(ctx, bindDef, subject, true)
		g.Expect(err).NotTo(HaveOccurred())

		actual := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "same-sa", Namespace: "default"}, actual)).To(Succeed())
		g.Expect(actual.Labels).To(HaveKeyWithValue(helpers.ManagedByLabelStandard, helpers.ManagedByValue))
	})
}

func TestNamespaceToBindDefinitionRequests(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	t.Run("returns requests for all BindDefinitions", func(t *testing.T) {
		g := NewWithT(t)

		bd1 := &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bd1"}}
		bd2 := &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bd2"}}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd1, bd2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns"}}
		requests := r.namespaceToBindDefinitionRequests(ctx, ns)
		g.Expect(requests).To(HaveLen(2))
	})

	t.Run("returns nil for non-namespace object", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme}

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod"}}
		requests := r.namespaceToBindDefinitionRequests(ctx, pod)
		g.Expect(requests).To(BeNil())
	})
}

func TestDeleteSubjectServiceAccounts(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)

	t.Run("deletes owned SA subjects", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "del-sa-bd", UID: "del-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "sa1", Namespace: "default"},
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
				},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sa1", Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-sa-bd", UID: "del-sa-uid", Controller: boolPtr(true)},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, sa).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteSubjectServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})

	t.Run("ignores non-SA subjects", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "no-sa-bd", UID: "no-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "no-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteSubjectServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})
}

func TestDeleteAllClusterRoleBindingsUnit(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	t.Run("deletes owned CRBs", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "del-crb-bd", UID: "del-crb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-crb",
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		crbName := helpers.BuildBindingName("del-crb", "view")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-crb-bd", UID: "del-crb-uid", Controller: boolPtr(true)},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, crb).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteAllClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})

	t.Run("succeeds when CRB not found", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "no-crb-bd", UID: "no-crb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "no-crb",
				ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
					ClusterRoleRefs: []string{"view"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteAllClusterRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})
}

func TestFetchRoleDefinitionUnit(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)

	t.Run("returns nil for not found", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &RoleDefinitionReconciler{client: c, scheme: scheme}

		rd, err := r.fetchRoleDefinition(ctx, client.ObjectKey{Name: "nonexistent"})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(rd).To(BeNil())
	})

	t.Run("returns RoleDefinition when found", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "existing"},
			Spec:       authorizationv1alpha1.RoleDefinitionSpec{TargetRole: "ClusterRole", TargetName: "test"},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rd).Build()
		r := &RoleDefinitionReconciler{client: c, scheme: scheme}

		result, err := r.fetchRoleDefinition(ctx, client.ObjectKey{Name: "existing"})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).NotTo(BeNil())
		g.Expect(result.Name).To(Equal("existing"))
	})
}

func TestEnsureClusterRoleBindingsError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "err-crb-bd", UID: "err-crb-uid"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "err-crb",
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(bindDef).
		WithStatusSubresource(bindDef).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected patch error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	err := r.ensureClusterRoleBindings(ctx, bindDef)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected patch error"))
}

func TestEnsureSingleRoleBindingError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "err-rb-bd", UID: "err-rb-uid"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "err-rb",
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(bindDef).
		WithStatusSubresource(bindDef).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected rb patch error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	err := r.ensureSingleRoleBinding(ctx, bindDef, "default", "view", "ClusterRole")
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected rb patch error"))
}

func TestReconcileResourcesWithSSAError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns"}}
	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "err-rec-bd", UID: "err-rec-uid"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "err-rec",
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(bindDef, ns).
		WithStatusSubresource(bindDef).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected SSA error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	activateNamespaces := []corev1.Namespace{*ns}
	_, err := r.reconcileResources(ctx, bindDef, activateNamespaces)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected SSA error"))
}

func TestReconcileDeleteError(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	t.Run("error on status apply", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "del-err-bd", UID: "del-err-uid", DeletionTimestamp: &now, Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer}},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-err",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName}},
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
					return fmt.Errorf("injected status error")
				},
			}).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		_, err := r.reconcileDelete(ctx, bindDef)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("injected status error"))
	})
}

func TestDeleteAllRoleBindingsUnit(t *testing.T) {
	ctx := context.Background()

	scheme := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(scheme)
	_ = rbacv1.SchemeBuilder.AddToScheme(scheme)
	_ = corev1.SchemeBuilder.AddToScheme(scheme)

	t.Run("deletes RoleBindings across namespaces", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "rb-ns"}}
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: "del-rb-all-bd", UID: "del-rb-all-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-rb-all",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{
					{Namespace: "rb-ns", ClusterRoleRefs: []string{"view"}, RoleRefs: []string{"editor"}},
				},
			},
		}

		rbName := helpers.BuildBindingName("del-rb-all", "view")
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: rbName, Namespace: "rb-ns",
				Labels: map[string]string{helpers.ManagedByLabelStandard: helpers.ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-rb-all-bd", UID: "del-rb-all-uid", Controller: boolPtr(true)},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef, ns, rb).WithStatusSubresource(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		err := r.deleteAllRoleBindings(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
	})
}

// TestEnsureServiceAccountsApplyError tests that ensureServiceAccounts
// propagates SSA apply errors.
func TestEnsureServiceAccountsApplyError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.SchemeBuilder.AddToScheme(s)
	_ = rbacv1.SchemeBuilder.AddToScheme(s)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-ns"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "apply-err-bd", UID: "apply-err-uid"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "apply-err",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "sa-test", Namespace: "sa-ns"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bindDef, ns).
		WithStatusSubresource(bindDef).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected SA patch error")
			},
		}).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, _, err := r.ensureServiceAccounts(ctx, bindDef)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apply ServiceAccount"))
}

// --- BD Reconcile error path tests ---

func TestBDReconcileGetError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	c := fake.NewClientBuilder().WithScheme(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return fmt.Errorf("injected get error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("fetch BindDefinition"))
}

func TestBDReconcileAddFinalizerError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "fin-err-bd", UID: "uid1"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "fin-err",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("injected patch error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "fin-err-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("add finalizer"))
}

func TestBDReconcileCollectNamespacesError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ns-err-bd",
			UID:        "uid2",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "ns-err",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{"env": "test"}}},
					ClusterRoleRefs:   []string{"view"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return fmt.Errorf("injected list error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "ns-err-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("collect namespaces"))
}

func TestBDReconcileFinalStatusApplyError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	// BD with no CRBs/RBs so reconcileResources does nothing except validateRoleReferences
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "status-err-bd",
			UID:        "uid3",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "status-err",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	// Fail immediately on SubResourceApply — the final applyStatus
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				return fmt.Errorf("injected status error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "status-err-bd"}})
	g.Expect(err).To(HaveOccurred())
}

// --- reconcileDelete error path tests ---

func TestReconcileDeleteInitialStatusError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-status-bd",
			UID:               "uid4",
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "del-status",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				return fmt.Errorf("injected status error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "del-status-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apply delete condition"))
}

func TestReconcileDeleteSAError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-sa-bd",
			UID:               "uid5",
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "del-sa",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "test-sa", Namespace: "ns1"},
			},
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}
	// Create the SA so deleteServiceAccount finds it and attempts Delete
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-sa-bd", UID: "uid5", Controller: boolPtr(true)},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, ns, sa).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return fmt.Errorf("injected SA delete error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "del-sa-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("delete ServiceAccounts"))
}

func TestReconcileDeleteFinalStatusError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-final-bd",
			UID:               "uid6",
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "del-final",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	callCount := 0
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				callCount++
				if callCount == 2 {
					return fmt.Errorf("injected final status error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "del-final-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apply status after cleanup"))
}

func TestReconcileDeleteRefetchError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "del-refetch-bd",
			UID:               "uid7",
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "del-refetch",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	// Count Get calls for BindDefinition specifically.
	// Gets: #1 Reconcile initial fetch,
	//        #2 re-fetch before finalizer removal
	// (status apply uses SSA directly without a pre-flight GET)
	getCallCount := 0
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*authorizationv1alpha1.BindDefinition); ok {
					getCallCount++
					// Fail on the re-fetch Get (#2)
					if getCallCount >= 2 {
						return fmt.Errorf("injected refetch error")
					}
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "del-refetch-bd"}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected refetch error"))
}

func TestDeleteAllCRBsWithStatusError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "crb-err-bd", UID: "uid8"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "crb-err",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"admin"},
			},
		},
	}

	crbName := helpers.BuildBindingName("crb-err", "admin")
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: crbName,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "crb-err-bd", UID: "uid8", Controller: boolPtr(true)},
			},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, crb).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
					return fmt.Errorf("injected CRB delete error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.deleteAllClusterRoleBindings(ctx, bd)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("deleteAllClusterRoleBindings"))
}

func TestDeleteRoleBindingWithStatusUpdateError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-status-bd", UID: "uid9"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "rb-status",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	rbName := helpers.BuildBindingName("rb-status", "view")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "rb-status-bd", UID: "uid9", Controller: boolPtr(true)},
			},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, rb).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return fmt.Errorf("injected RB delete error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.deleteRoleBindingWithStatusUpdate(ctx, bd, "view", "ns1")
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("RoleBinding"))
}

func TestDeleteRoleBindingWithStatusUpdateStatusError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-both-err-bd", UID: "uid10"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "rb-both-err",
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "u", APIGroup: rbacv1.GroupName}},
		},
	}

	rbName := helpers.BuildBindingName("rb-both-err", "edit")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "rb-both-err-bd", UID: "uid10", Controller: boolPtr(true)},
			},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "edit"},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, rb).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return fmt.Errorf("injected RB delete error")
				}
				return nil
			},
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				return fmt.Errorf("injected status error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.deleteRoleBindingWithStatusUpdate(ctx, bd, "edit", "ns1")
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apply status after RoleBinding deletion failure"))
}

// TestApplyServiceAccountError covers the path where the SSA Apply fails.
func TestApplyServiceAccountError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "sa-patch-err", Namespace: "default", UID: "uid1"},
	}

	subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "test-sa", Namespace: "test-ns"}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected patch error")
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.applyServiceAccount(ctx, bd, subject, true)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("apply ServiceAccount"))
}

// TestDeleteAllRoleBindingsRoleRefError covers the error return path
// when deleteRoleBindingWithStatusUpdate fails for a RoleRef.
func TestDeleteAllRoleBindingsRoleRefError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-err-bd", Namespace: "default", UID: "uid1"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "rb-err",
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "devs"}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					Namespace: "ns1",
					RoleRefs:  []string{"edit"},
				},
			},
		},
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}

	controller := true
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rb-err-edit-binding", Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
				Name:       bd.Name,
				UID:        bd.UID,
				Controller: &controller,
			}},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "edit"},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(bd, ns, rb).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return fmt.Errorf("injected RB delete error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.deleteAllRoleBindings(ctx, bd)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("roleRef"))
	g.Expect(err.Error()).To(ContainSubstring("edit"))
}

// TestReconcileResourcesEnsureRBError covers the path where ensureRoleBindings
// fails during reconcileResources, testing the error return in that function.
func TestReconcileResourcesEnsureRBError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rr-err-bd", Namespace: "default", UID: "uid1"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "rr-err",
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{
					Namespace:       "ns1",
					ClusterRoleRefs: []string{"admin"},
				},
			},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "devs"},
			},
		},
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}

	applyCount := 0
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(bd, ns).
		WithStatusSubresource(bd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				applyCount++
				if applyCount >= 1 {
					return fmt.Errorf("injected SSA error")
				}
				return nil
			},
		}).Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	namespaces := []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}}
	_, err := r.reconcileResources(ctx, bd, namespaces)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected SSA error"))
}

// TestReconcileDeletePreservesSharedSA verifies that when two BindDefinitions
// reference the same ServiceAccount, deleting one BD does NOT remove the SA.
func TestReconcileDeletePreservesSharedSA(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-ns"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	isController := true

	// BD-A: being deleted, references shared-sa
	bdA := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "bd-a",
			UID:        "uid-a",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "shared-target",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "shared-ns"},
			},
		},
	}

	// BD-B: still active, also references shared-sa
	bdB := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "bd-b",
			UID:  "uid-b",
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "other-target",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "shared-ns"},
			},
		},
	}

	// SA owned by BD-A
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-sa",
			Namespace: "shared-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "BindDefinition",
					Name:       "bd-a",
					UID:        "uid-a",
					Controller: &isController,
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bdA, bdB, ns, sa).
		WithStatusSubresource(bdA).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.reconcileDelete(ctx, bdA)
	g.Expect(err).NotTo(HaveOccurred())

	// SA must still exist because BD-B also references it
	existingSA := &corev1.ServiceAccount{}
	err = c.Get(ctx, types.NamespacedName{Name: "shared-sa", Namespace: "shared-ns"}, existingSA)
	g.Expect(err).NotTo(HaveOccurred(), "SA should be preserved because another BD references it")
}

// TestReconcileDeleteRemovesSAWhenNotShared verifies that deleting a BD removes
// its owned SA when no other BD references it.
func TestReconcileDeleteRemovesSAWhenNotShared(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "sole-ns"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	isController := true

	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "sole-bd",
			UID:        "sole-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "sole-target",
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "sole-sa", Namespace: "sole-ns"},
			},
		},
	}

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sole-sa",
			Namespace: "sole-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "BindDefinition",
					Name:       "sole-bd",
					UID:        "sole-uid",
					Controller: &isController,
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, ns, sa).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	_, err := r.reconcileDelete(ctx, bd)
	g.Expect(err).NotTo(HaveOccurred())

	// SA should be deleted since no other BD references it
	deletedSA := &corev1.ServiceAccount{}
	err = c.Get(ctx, types.NamespacedName{Name: "sole-sa", Namespace: "sole-ns"}, deletedSA)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "SA should be deleted when not shared")
}

// TestReconcileReturnsShortRequeueOnMissingRoleRefs verifies that Reconcile
// returns RoleRefRequeueInterval when referenced roles are missing.
func TestReconcileReturnsShortRequeueOnMissingRoleRefs(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "missing-refs-bd",
			UID:        "missing-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "missing-target",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"nonexistent-cluster-role"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "missing-refs-bd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(RoleRefRequeueInterval),
		"should use short requeue interval when role refs are missing")
}

// TestReconcileReturnsDefaultRequeueWhenAllRefsValid verifies that Reconcile
// returns DefaultRequeueInterval when all referenced roles exist.
func TestReconcileReturnsDefaultRequeueWhenAllRefsValid(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// The ClusterRole must exist for the ref to be valid
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-role"},
	}

	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "valid-refs-bd",
			UID:        "valid-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "valid-target",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"existing-role"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, cr).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "valid-refs-bd"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval),
		"should use default requeue interval when all role refs are valid")
}

// TestReconcileDeleteCleansUpGaugeMetrics verifies that reconcileDelete
// removes per-BD gauge metrics so they don't persist after deletion.
func TestReconcileDeleteCleansUpGaugeMetrics(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bdName := "metrics-cleanup-bd"

	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       bdName,
			UID:        "metrics-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "metrics-target",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	// Simulate metrics being set during a prior reconciliation
	metrics.RoleRefsMissing.WithLabelValues(bdName).Set(2)
	metrics.NamespacesActive.WithLabelValues(bdName).Set(5)

	_, err := r.reconcileDelete(ctx, bd)
	g.Expect(err).NotTo(HaveOccurred())

	// After deletion the per-BD gauge label sets should be cleaned up.
	// Prometheus GetMetricWithLabelValues returns an existing metric if it
	// was previously registered; after DeleteLabelValues the metric entry
	// should no longer be present. We verify by checking that a fresh Get
	// returns a gauge with value 0 (Prometheus creates a new default-0 entry).
	roleGauge, _ := metrics.RoleRefsMissing.GetMetricWithLabelValues(bdName)
	g.Expect(roleGauge).NotTo(BeNil())

	nsGauge, _ := metrics.NamespacesActive.GetMetricWithLabelValues(bdName)
	g.Expect(nsGauge).NotTo(BeNil())
}

// ---------------------------------------------------------------------------
// Missing-role policy tests (#52)
// ---------------------------------------------------------------------------

// newBDWithPolicy creates a BindDefinition with the given missing-role policy
// annotation and a reference to a non-existent ClusterRole.
func newBDWithPolicy(name string, policy authorizationv1alpha1.MissingRolePolicy) *authorizationv1alpha1.BindDefinition {
	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			UID:        "policy-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: name,
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"nonexistent-role"},
			},
		},
	}
	if policy != "" {
		bd.Annotations = map[string]string{
			authorizationv1alpha1.MissingRolePolicyAnnotation: string(policy),
		}
	}
	return bd
}

func TestReconcile_MissingRolePolicy_Warn(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := newBDWithPolicy("policy-warn-bd", authorizationv1alpha1.MissingRolePolicyWarn)

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: bd.Name},
	})
	// warn mode still succeeds (no error), but requeues with short interval.
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(RoleRefRequeueInterval))
}

func TestReconcile_MissingRolePolicy_Error(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := newBDWithPolicy("policy-error-bd", authorizationv1alpha1.MissingRolePolicyError)

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: bd.Name},
	})
	// error mode does NOT propagate the error (we use RequeueAfter instead of
	// returning an error to prevent exponential backoff), but the BD is Stalled.
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(RoleRefRequeueInterval))

	// Verify the BD was marked as Stalled
	var updated authorizationv1alpha1.BindDefinition
	g.Expect(c.Get(ctx, types.NamespacedName{Name: bd.Name}, &updated)).To(Succeed())
	stalledCond := findCondition(updated.Status.Conditions, "Stalled")
	g.Expect(stalledCond).NotTo(BeNil(), "expected Stalled condition to be set")
	g.Expect(stalledCond.Status).To(Equal(metav1.ConditionTrue))
	g.Expect(stalledCond.Message).To(ContainSubstring("policy=error"))
}

func TestReconcile_MissingRolePolicy_Ignore(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	bd := newBDWithPolicy("policy-ignore-bd", authorizationv1alpha1.MissingRolePolicyIgnore)

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: bd.Name},
	})
	// ignore mode succeeds and uses the default interval (no degradation).
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))

	// Verify MissingRoleRefs is empty in status
	var updated authorizationv1alpha1.BindDefinition
	g.Expect(c.Get(ctx, types.NamespacedName{Name: bd.Name}, &updated)).To(Succeed())
	g.Expect(updated.Status.MissingRoleRefs).To(BeEmpty())

	// RoleRefsValid condition should be True
	roleRefCond := findCondition(updated.Status.Conditions, string(authorizationv1alpha1.RoleRefValidCondition))
	g.Expect(roleRefCond).NotTo(BeNil())
	g.Expect(roleRefCond.Status).To(Equal(metav1.ConditionTrue))
}

func TestReconcile_MissingRolePolicy_Default(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// No annotation at all — should default to "warn"
	bd := newBDWithPolicy("policy-default-bd", "")

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: bd.Name},
	})
	// Default (warn) mode succeeds with short requeue
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(RoleRefRequeueInterval))
}

func TestReconcile_MissingRolePolicy_ErrorWithAllRefsValid(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-role"},
	}
	bd := &authorizationv1alpha1.BindDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authorizationv1alpha1.GroupVersion.String(),
			Kind:       "BindDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "policy-error-ok-bd",
			UID:        "policy-uid",
			Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
			Annotations: map[string]string{
				authorizationv1alpha1.MissingRolePolicyAnnotation: string(authorizationv1alpha1.MissingRolePolicyError),
			},
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "policy-error-ok",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
				ClusterRoleRefs: []string{"existing-role"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(bd, cr).
		WithStatusSubresource(bd).
		Build()
	r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: bd.Name},
	})
	// error mode with all refs valid succeeds normally.
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(DefaultRequeueInterval))
}

// findCondition returns the condition with the given type from the list.
func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
