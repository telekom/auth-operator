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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

			By("waiting for CRD to enter terminating state")
			Eventually(func() bool {
				crd := &apiextensionsv1.CustomResourceDefinition{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(testCRD), crd); err != nil {
					return false
				}
				return crd.DeletionTimestamp != nil
			}, "30s", "1s").Should(BeTrue(), "CRD should enter terminating state")

			By("releasing envtest CRD finalizers")
			Eventually(func() bool {
				crd := &apiextensionsv1.CustomResourceDefinition{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(testCRD), crd); err != nil {
					return apierrors.IsNotFound(err)
				}
				if crd.DeletionTimestamp == nil {
					return false
				}
				if len(crd.Finalizers) == 0 {
					return true
				}
				crd.Finalizers = nil
				return k8sClient.Update(ctx, crd) == nil
			}, "30s", "1s").Should(BeTrue(), "CRD finalizers should be released after deletion starts")

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

var _ = Describe("ResourceTracker CRD Watch Handling", func() {
	It("stops collection when the context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resourceTracker := NewResourceTracker(scheme.Scheme, cfg)

		done := make(chan struct {
			Changed bool
			Err     error
		}, 1)
		go func() {
			defer GinkgoRecover()
			changed, err := resourceTracker.collectAPIResources(ctx)
			done <- struct {
				Changed bool
				Err     error
			}{Changed: changed, Err: err}
		}()

		cancel()
		Eventually(done, "1s", "10ms").Should(Receive(And(
			HaveField("Changed", BeFalse()),
			HaveField("Err", MatchError(context.Canceled)),
		)))
	})

	It("discovers CRDs created after startup without waiting for periodic refresh", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		watchCRD := &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "watchstartupresources.watchstartup.example.com",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "watchstartup.example.com",
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Plural:   "watchstartupresources",
					Singular: "watchstartupresource",
					Kind:     "WatchStartupResource",
					ListKind: "WatchStartupResourceList",
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
		defer func() {
			_ = k8sClient.Delete(context.Background(), watchCRD)
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(watchCRD), &apiextensionsv1.CustomResourceDefinition{})
				return apierrors.IsNotFound(err)
			}, "30s", "1s").Should(BeTrue(), "watch startup CRD should be deleted")
		}()

		resourceTracker := NewResourceTracker(scheme.Scheme, cfg)
		resourceTracker.CollectionInterval = time.Hour
		resourceTracker.FullRescanInterval = time.Hour
		signalReceived := make(chan struct{}, 1)
		resourceTracker.AddSignalFunc(func() error {
			select {
			case signalReceived <- struct{}{}:
			default:
			}
			return nil
		})

		started := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			started <- resourceTracker.Start(ctx)
		}()

		By("waiting for ResourceTracker to be ready")
		Eventually(func() bool {
			_, err := resourceTracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())
		DeferCleanup(func() {
			cancel()
			Eventually(started, "10s", "10ms").Should(Receive(BeNil()))
		})
		for {
			select {
			case <-signalReceived:
			default:
				goto startupSignalsDrained
			}
		}
	startupSignalsDrained:

		By("creating a CRD after ResourceTracker startup")
		Expect(k8sClient.Create(ctx, watchCRD)).To(Succeed())
		Eventually(func() bool {
			crd := &apiextensionsv1.CustomResourceDefinition{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(watchCRD), crd); err != nil {
				return false
			}
			for _, cond := range crd.Status.Conditions {
				if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
					return true
				}
			}
			return false
		}, "30s", "1s").Should(BeTrue(), "watch startup CRD should be established")

		By("verifying the watch-driven cache update and signal")
		Eventually(func() bool {
			resources, err := resourceTracker.GetAPIResources()
			if err != nil {
				return false
			}
			_, exists := resources["watchstartup.example.com/v1"]
			return exists
		}, "60s", "1s").Should(BeTrue(), "watch startup CRD should be discovered without periodic refresh")
		Eventually(signalReceived, "10s", "1s").Should(Receive())
	})
})

var _ = Describe("ResourceTracker explicit RBAC verbs", func() {
	It("adds bind and escalate for clusterroles", func() {
		resource := withExplicitRBACVerbs(rbacv1.GroupName, "v1", metav1.APIResource{
			Name:       rbacResourceClusterRoles,
			Namespaced: false,
			Kind:       "ClusterRole",
			Verbs:      metav1.Verbs{verbGet, verbList},
		})

		Expect(resource.Verbs).To(ConsistOf(verbGet, verbList, verbBind, verbEscalate))
	})

	It("adds bind and escalate for roles", func() {
		resource := withExplicitRBACVerbs(rbacv1.GroupName, "v1", metav1.APIResource{
			Name:       rbacResourceRoles,
			Namespaced: true,
			Kind:       "Role",
			Verbs:      metav1.Verbs{verbGet, verbList},
		})

		Expect(resource.Verbs).To(ConsistOf(verbGet, verbList, verbBind, verbEscalate))
	})

	It("does not duplicate existing explicit verbs", func() {
		resource := withExplicitRBACVerbs(rbacv1.GroupName, "v1", metav1.APIResource{
			Name:       rbacResourceClusterRoles,
			Namespaced: false,
			Kind:       "ClusterRole",
			Verbs:      metav1.Verbs{verbGet, verbBind, verbEscalate},
		})

		Expect(resource.Verbs).To(Equal(metav1.Verbs{verbGet, verbBind, verbEscalate}))
	})

	It("does not add bind to rolebindings", func() {
		resource := withExplicitRBACVerbs(rbacv1.GroupName, "v1", metav1.APIResource{
			Name:       "rolebindings",
			Namespaced: true,
			Kind:       "RoleBinding",
			Verbs:      metav1.Verbs{verbGet, verbList},
		})

		Expect(resource.Verbs).To(ConsistOf(verbGet, verbList))
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

		started := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			started <- resourceTracker.Start(ctx)
		}()

		By("waiting for ResourceTracker to be ready")
		Eventually(func() bool {
			_, err := resourceTracker.GetAPIResources()
			return err == nil
		}, "30s", "1s").Should(BeTrue())
		DeferCleanup(func() {
			cancel()
			Eventually(started, "10s", "10ms").Should(Receive(BeNil()))
		})
		for {
			select {
			case <-signalReceived:
			default:
				goto lifecycleStartupSignalsDrained
			}
		}
	lifecycleStartupSignalsDrained:
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
				_ = k8sClient.Update(cleanupCtx, crd)
			}
			_ = k8sClient.Delete(cleanupCtx, lifecycleCRD)
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
		for {
			select {
			case <-signalReceived:
			default:
				goto beforeLifecycleDeletion
			}
		}
	beforeLifecycleDeletion:
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
