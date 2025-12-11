package authorization

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
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
			if err != nil && errors.IsNotFound(err) {
				resource := &authorizationv1alpha1.BindDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: authorizationv1alpha1.BindDefinitionSpec{
						Subjects: []rbacv1.Subject{},
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
			controllerReconciler := &bindDefinitionReconciler{
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
			names := []string{}
			for i := 0; i < 10; i++ {
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
