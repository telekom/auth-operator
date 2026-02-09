/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

func TestResourceTracker(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ResourceTracker Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		ErrorIfCRDPathMissing: false,
	}

	// Only set BinaryAssetsDirectory if KUBEBUILDER_ASSETS is not set
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue(), "failed to determine caller information")
		repoRoot, absErr := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
		Expect(absErr).NotTo(HaveOccurred(), "failed to resolve absolute path for repo root")
		testEnv.BinaryAssetsDirectory = filepath.Join(repoRoot, "bin", "k8s",
			"1.34.1-"+runtime.GOOS+"-"+runtime.GOARCH)
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = apiextensionsv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	if err := testEnv.Stop(); err != nil {
		logf.Log.Error(err, "failed to stop test environment (best-effort cleanup)")
	}
})

var _ = Describe("ResourceTracker CRD Deletion Handling", func() {
	var (
		ctx             context.Context
		cancel          context.CancelFunc
		resourceTracker *ResourceTracker
		testCRD         *apiextensionsv1.CustomResourceDefinition
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		// Create a test CRD
		testCRD = &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testresources.test.example.com",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "test.example.com",
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Plural:   "testresources",
					Singular: "testresource",
					Kind:     "TestResource",
					ListKind: "TestResourceList",
				},
				Scope: apiextensionsv1.NamespaceScoped,
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
					{
						Name:    "v1",
						Served:  true,
						Storage: true,
						Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "object",
								Properties: map[string]apiextensionsv1.JSONSchemaProps{
									"spec": {
										Type: "object",
									},
								},
							},
						},
					},
				},
			},
		}
	})

	AfterEach(func() {
		cancel()

		// Clean up test CRD if it exists
		if testCRD != nil {
			_ = k8sClient.Delete(context.Background(), testCRD)
			// Wait for CRD to be fully deleted
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(testCRD), &apiextensionsv1.CustomResourceDefinition{})
				return apierrors.IsNotFound(err)
			}, "30s", "1s").Should(BeTrue(), "CRD should be deleted")
		}
	})

	Context("when a CRD is created and then deleted", func() {
		It("should include CRD resources in discovery while CRD exists", func() {
			By("creating the test CRD")
			Expect(k8sClient.Create(ctx, testCRD)).To(Succeed())

			By("waiting for CRD to be established")
			Eventually(func() bool {
				crd := &apiextensionsv1.CustomResourceDefinition{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(testCRD), crd); err != nil {
					return false
				}
				for _, cond := range crd.Status.Conditions {
					if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
						return true
					}
				}
				return false
			}, "30s", "1s").Should(BeTrue(), "CRD should be established")

			By("creating and starting the ResourceTracker")
			resourceTracker = NewResourceTracker(scheme.Scheme, cfg)
			go func() {
				defer GinkgoRecover()
				_ = resourceTracker.Start(ctx)
			}()

			By("waiting for ResourceTracker to be ready")
			Eventually(func() bool {
				_, err := resourceTracker.GetAPIResources()
				return err == nil
			}, "30s", "1s").Should(BeTrue(), "ResourceTracker should be ready")

			By("verifying the test CRD resources are in the cache")
			Eventually(func() bool {
				resources, err := resourceTracker.GetAPIResources()
				if err != nil {
					return false
				}
				// Check if test.example.com/v1 group version exists
				_, exists := resources["test.example.com/v1"]
				return exists
			}, "60s", "1s").Should(BeTrue(), "test CRD resources should be discovered")

			By("deleting the test CRD")
			Expect(k8sClient.Delete(ctx, testCRD)).To(Succeed())

			By("waiting for CRD to be fully deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKeyFromObject(testCRD), &apiextensionsv1.CustomResourceDefinition{})
				return apierrors.IsNotFound(err)
			}, "30s", "1s").Should(BeTrue(), "CRD should be fully deleted")

			By("verifying resources are removed from cache after CRD deletion")
			Eventually(func() bool {
				resources, err := resourceTracker.GetAPIResources()
				if err != nil {
					return false
				}
				// Check if test.example.com/v1 group version no longer exists
				_, exists := resources["test.example.com/v1"]
				return !exists
			}, "60s", "1s").Should(BeTrue(), "test CRD resources should be removed after deletion")
		})
	})
})

var _ = Describe("ResourceTracker Watch Event Handling", func() {
	Context("shouldSkipCollectionForTerminatingCRD logic", func() {
		// These are unit tests for the deletion timestamp skip logic

		It("should skip collection when CRD has deletionTimestamp and event is MODIFIED", func() {
			now := metav1.Now()
			crd := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test.example.com",
					DeletionTimestamp: &now,
				},
			}

			// Use the extracted helper function
			Expect(shouldSkipTerminatingCRD(crd, watch.Modified)).To(BeTrue(),
				"should skip collection for terminating CRD on MODIFIED event")
		})

		It("should NOT skip collection when CRD has deletionTimestamp and event is DELETED", func() {
			now := metav1.Now()
			crd := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test.example.com",
					DeletionTimestamp: &now,
				},
			}

			// Use the extracted helper function
			Expect(shouldSkipTerminatingCRD(crd, watch.Deleted)).To(BeFalse(),
				"should NOT skip collection for terminating CRD on DELETED event")
		})

		It("should NOT skip collection when CRD has NO deletionTimestamp", func() {
			crd := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test.example.com",
					// No DeletionTimestamp
				},
			}

			// Use the extracted helper function
			Expect(shouldSkipTerminatingCRD(crd, watch.Modified)).To(BeFalse(),
				"should NOT skip collection for non-terminating CRD")
		})

		It("should skip collection on ADDED event for terminating CRDs", func() {
			now := metav1.Now()
			crd := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test.example.com",
					DeletionTimestamp: &now,
				},
			}

			// Use the extracted helper function
			// ADDED events for terminating CRDs are also skipped to avoid unnecessary collection
			Expect(shouldSkipTerminatingCRD(crd, watch.Added)).To(BeTrue(),
				"ADDED events for terminating CRDs are skipped to avoid unnecessary collection")
		})
	})
})

var _ = Describe("ResourceTracker APIResourcesByGroupVersion", func() {
	Context("Equals comparison", func() {
		It("should return true for identical maps", func() {
			a := APIResourcesByGroupVersion{
				"v1": []metav1.APIResource{
					{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: []string{"get", "list"}},
				},
			}
			b := APIResourcesByGroupVersion{
				"v1": []metav1.APIResource{
					{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: []string{"get", "list"}},
				},
			}
			Expect(a.Equals(b)).To(BeTrue())
		})

		It("should return true when verbs are in different order", func() {
			a := APIResourcesByGroupVersion{
				"v1": []metav1.APIResource{
					{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: []string{"get", "list", "watch"}},
				},
			}
			b := APIResourcesByGroupVersion{
				"v1": []metav1.APIResource{
					{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: []string{"watch", "get", "list"}},
				},
			}
			Expect(a.Equals(b)).To(BeTrue())
		})

		It("should return false when group version is missing", func() {
			a := APIResourcesByGroupVersion{
				"v1":                  []metav1.APIResource{{Name: "pods"}},
				"test.example.com/v1": []metav1.APIResource{{Name: "testresources"}},
			}
			b := APIResourcesByGroupVersion{
				"v1": []metav1.APIResource{{Name: "pods"}},
				// test.example.com/v1 is missing - simulates CRD deletion
			}
			Expect(a.Equals(b)).To(BeFalse(), "should detect missing group version after CRD deletion")
		})

		It("should return false when resource is removed from a group version", func() {
			a := APIResourcesByGroupVersion{
				"test.example.com/v1": []metav1.APIResource{
					{Name: "testresources", Namespaced: true, Kind: "TestResource"},
					{Name: "testresources/status", Namespaced: true, Kind: "TestResource"},
				},
			}
			b := APIResourcesByGroupVersion{
				"test.example.com/v1": []metav1.APIResource{
					{Name: "testresources", Namespaced: true, Kind: "TestResource"},
					// status subresource removed
				},
			}
			Expect(a.Equals(b)).To(BeFalse())
		})
	})
})

var _ = Describe("ResourceTracker Integration - CRD Lifecycle", Ordered, func() {
	var (
		ctx             context.Context
		cancel          context.CancelFunc
		resourceTracker *ResourceTracker
		lifecycleCRD    *apiextensionsv1.CustomResourceDefinition
		signalReceived  chan struct{}
	)

	BeforeAll(func() {
		ctx, cancel = context.WithCancel(context.Background())
		signalReceived = make(chan struct{}, 10)

		// Create a unique CRD for this test
		lifecycleCRD = &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "lifecycletests.lifecycle.example.com",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "lifecycle.example.com",
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Plural:   "lifecycletests",
					Singular: "lifecycletest",
					Kind:     "LifecycleTest",
					ListKind: "LifecycleTestList",
				},
				Scope: apiextensionsv1.ClusterScoped,
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
					{
						Name:    "v1",
						Served:  true,
						Storage: true,
						Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "object",
							},
						},
					},
				},
			},
		}

		By("creating the lifecycle test CRD")
		Expect(k8sClient.Create(ctx, lifecycleCRD)).To(Succeed())

		By("waiting for CRD to be established")
		Eventually(func() bool {
			crd := &apiextensionsv1.CustomResourceDefinition{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(lifecycleCRD), crd); err != nil {
				return false
			}
			for _, cond := range crd.Status.Conditions {
				if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
					return true
				}
			}
			return false
		}, "30s", "1s").Should(BeTrue())

		By("creating the ResourceTracker with signal function")
		resourceTracker = NewResourceTracker(scheme.Scheme, cfg)
		resourceTracker.AddSignalFunc(func() error {
			select {
			case signalReceived <- struct{}{}:
			default:
			}
			return nil
		})

		go func() {
			defer GinkgoRecover()
			_ = resourceTracker.Start(ctx)
		}()

		By("waiting for ResourceTracker to be ready")
		Eventually(func() bool {
			_, err := resourceTracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())
	})

	AfterAll(func() {
		cancel()

		// Best-effort cleanup: remove test finalizer and delete CRD
		// so the suite doesn't leave resources behind if an earlier assertion fails.
		cleanupCtx := context.Background()
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := k8sClient.Get(cleanupCtx, client.ObjectKeyFromObject(lifecycleCRD), crd); err == nil {
			// Remove test finalizer if present
			updatedFinalizers := make([]string, 0, len(crd.Finalizers))
			for _, f := range crd.Finalizers {
				if f != "test.example.com/lifecycle-test" {
					updatedFinalizers = append(updatedFinalizers, f)
				}
			}
			if len(updatedFinalizers) != len(crd.Finalizers) {
				crd.Finalizers = updatedFinalizers
				_ = k8sClient.Update(cleanupCtx, crd) //nolint:errcheck // best-effort
			}
			_ = k8sClient.Delete(cleanupCtx, lifecycleCRD) //nolint:errcheck // best-effort
		}
	})

	It("should have lifecycle CRD resources in cache after creation", func() {
		Eventually(func() bool {
			resources, err := resourceTracker.GetAPIResources()
			if err != nil {
				return false
			}
			_, exists := resources["lifecycle.example.com/v1"]
			return exists
		}, "60s", "2s").Should(BeTrue(), "lifecycle CRD resources should be in cache")
	})

	It("should add finalizer to hold CRD in terminating state", func() {
		By("adding a finalizer to the lifecycle CRD")
		crd := &apiextensionsv1.CustomResourceDefinition{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(lifecycleCRD), crd)).To(Succeed())
		crd.Finalizers = append(crd.Finalizers, "test.example.com/lifecycle-test")
		Expect(k8sClient.Update(ctx, crd)).To(Succeed())
	})

	It("should retain resources while CRD is terminating", func() {
		By("deleting the lifecycle CRD (will enter terminating state due to finalizer)")
		Expect(k8sClient.Delete(ctx, lifecycleCRD)).To(Succeed())

		By("verifying CRD is in terminating state (has deletionTimestamp)")
		Eventually(func() bool {
			crd := &apiextensionsv1.CustomResourceDefinition{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(lifecycleCRD), crd); err != nil {
				return false
			}
			return crd.DeletionTimestamp != nil
		}, "30s", "1s").Should(BeTrue(), "CRD should be in terminating state")

		By("verifying resources are STILL in cache while CRD is terminating")
		// Note: 10s is sufficient because the watch handler (which is the only path that
		// skips collection for terminating CRDs) processes events within seconds.
		// periodicCollection (30s) and periodicFullRescan (15m) call collectAPIResources
		// which queries the API server directly — the API server still serves resources
		// for terminating CRDs, so they won't be dropped from the cache.
		Consistently(func() bool {
			resources, err := resourceTracker.GetAPIResources()
			if err != nil {
				return false
			}
			_, exists := resources["lifecycle.example.com/v1"]
			return exists
		}, "10s", "1s").Should(BeTrue(), "lifecycle CRD resources should remain in cache while terminating")
	})

	It("should remove lifecycle CRD resources from cache after full deletion", func() {
		By("removing the finalizer to allow full deletion")
		crd := &apiextensionsv1.CustomResourceDefinition{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(lifecycleCRD), crd)).To(Succeed())
		// Only remove the test finalizer, preserving any Kubernetes-managed finalizers
		updatedFinalizers := make([]string, 0, len(crd.Finalizers))
		for _, f := range crd.Finalizers {
			if f != "test.example.com/lifecycle-test" {
				updatedFinalizers = append(updatedFinalizers, f)
			}
		}
		crd.Finalizers = updatedFinalizers
		Expect(k8sClient.Update(ctx, crd)).To(Succeed())

		By("waiting for CRD to be fully deleted")
		Eventually(func() bool {
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(lifecycleCRD), &apiextensionsv1.CustomResourceDefinition{})
			return apierrors.IsNotFound(err)
		}, "30s", "1s").Should(BeTrue(), "CRD should be fully deleted")

		By("verifying resources are removed from cache after full deletion")
		Eventually(func() bool {
			resources, err := resourceTracker.GetAPIResources()
			if err != nil {
				return false
			}
			_, exists := resources["lifecycle.example.com/v1"]
			return !exists
		}, "60s", "2s").Should(BeTrue(), "lifecycle CRD resources should be removed after full deletion")

		By("verifying signal was received for resource change after deletion")
		Eventually(signalReceived).Should(Receive(), "signal should be received after CRD deletion")
	})
})

var _ = Describe("ResourceTracker GetAPIResources", func() {
	It("should return ErrResourceTrackerNotStarted before Start is called", func() {
		tracker := NewResourceTracker(scheme.Scheme, cfg)
		_, err := tracker.GetAPIResources()
		Expect(err).To(Equal(ErrResourceTrackerNotStarted))
	})

	It("should return a deep copy of the cache", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tracker := NewResourceTracker(scheme.Scheme, cfg)
		go func() {
			defer GinkgoRecover()
			_ = tracker.Start(ctx)
		}()

		Eventually(func() bool {
			_, err := tracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())

		resources1, err := tracker.GetAPIResources()
		Expect(err).NotTo(HaveOccurred())

		resources2, err := tracker.GetAPIResources()
		Expect(err).NotTo(HaveOccurred())

		// Modify resources1 and verify resources2 is not affected
		if len(resources1["v1"]) > 0 {
			resources1["v1"][0].Name = "modified"
			Expect(resources2["v1"][0].Name).NotTo(Equal("modified"), "GetAPIResources should return deep copies")
		}
	})
})

var _ = Describe("ResourceTracker RefreshUUIDMap", func() {
	var (
		ctx             context.Context
		cancel          context.CancelFunc
		resourceTracker *ResourceTracker
		testCRD         *apiextensionsv1.CustomResourceDefinition
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		// Create a test CRD for UUID tracking tests
		testCRD = &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "uuidtestresources.uuid.example.com",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "uuid.example.com",
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Kind:     "UUIDTestResource",
					ListKind: "UUIDTestResourceList",
					Plural:   "uuidtestresources",
					Singular: "uuidtestresource",
				},
				Scope: apiextensionsv1.NamespaceScoped,
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
					{
						Name:    "v1",
						Served:  true,
						Storage: true,
						Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "object",
							},
						},
					},
				},
			},
		}

		resourceTracker = NewResourceTracker(scheme.Scheme, cfg)
	})

	AfterEach(func() {
		cancel()
		// Clean up CRD if it exists
		_ = k8sClient.Delete(context.Background(), testCRD)
	})

	It("should refresh UUID map with current CRDs", func() {
		By("starting the tracker")
		go func() {
			defer GinkgoRecover()
			_ = resourceTracker.Start(ctx)
		}()

		Eventually(func() bool {
			_, err := resourceTracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())

		initialUUIDCount := resourceTracker.crdUUIDCount()

		By("creating a new CRD")
		Expect(k8sClient.Create(ctx, testCRD)).To(Succeed())
		Eventually(func() bool {
			var crd apiextensionsv1.CustomResourceDefinition
			err := k8sClient.Get(ctx, client.ObjectKey{Name: testCRD.Name}, &crd)
			return err == nil && crd.UID != ""
		}, "30s", "1s").Should(BeTrue())

		By("calling refreshUUIDMap")
		err := resourceTracker.refreshUUIDMap(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("verifying the UUID map includes the new CRD")
		// The map should include the new CRD
		var crd apiextensionsv1.CustomResourceDefinition
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: testCRD.Name}, &crd)).To(Succeed())
		Expect(resourceTracker.hasCRDUUID(string(crd.UID))).To(BeTrue(), "refreshUUIDMap should include the new CRD's UUID")
		Expect(resourceTracker.crdUUIDCount()).To(BeNumerically(">=", initialUUIDCount), "UUID map should not shrink unexpectedly")
	})

	It("should remove stale UUIDs from the map on refresh", func() {
		By("starting the tracker")
		go func() {
			defer GinkgoRecover()
			_ = resourceTracker.Start(ctx)
		}()

		Eventually(func() bool {
			_, err := resourceTracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())

		By("adding a fake UUID to simulate a deleted CRD that was missed")
		fakeUID := "fake-uid-that-doesnt-exist"
		resourceTracker.addCRDUUID(fakeUID)
		Expect(resourceTracker.hasCRDUUID(fakeUID)).To(BeTrue())

		By("calling refreshUUIDMap")
		err := resourceTracker.refreshUUIDMap(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("verifying the fake UUID is removed")
		Expect(resourceTracker.hasCRDUUID(fakeUID)).To(BeFalse(), "refreshUUIDMap should remove stale UUIDs")
	})
})
