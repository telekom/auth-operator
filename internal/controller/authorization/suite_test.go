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

package authorization

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.WithWatch
var discoveryClient discovery.DiscoveryInterface
var recorder *events.FakeRecorder
var logger logr.Logger
var testEnv *envtest.Environment

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logger = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	logf.SetLogger(logger)

	// Use buffered recorder to prevent deadlock when events are not consumed.
	recorder = events.NewFakeRecorder(100)
	discoveryClient = fake.NewClientset().Discovery()

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Only set BinaryAssetsDirectory if KUBEBUILDER_ASSETS is not set.
	// This allows CI to use setup-envtest while still supporting local "go test".
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Get the directory of this test file to build an absolute path
		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue(), "failed to determine caller information for BinaryAssetsDirectory")
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
		// Ensure we have an absolute path (runtime.Caller may return relative paths in some build modes)
		absRepoRoot, absErr := filepath.Abs(repoRoot)
		Expect(absErr).NotTo(HaveOccurred(), "failed to determine absolute repo root for BinaryAssetsDirectory")
		testEnv.BinaryAssetsDirectory = filepath.Join(absRepoRoot, "bin", "k8s",
			fmt.Sprintf("1.34.1-%s-%s", runtime.GOOS, runtime.GOARCH))
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = authorizationv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.NewWithWatch(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	// Best-effort stop: log but don't fail if the kube-apiserver is slow to shut down,
	// since all specs have already passed by this point.
	if testEnv != nil {
		err := testEnv.Stop()
		if err != nil {
			// Log but don't fail — all specs already passed; this is only cleanup.
			_, _ = fmt.Fprintf(GinkgoWriter, "warning: testEnv.Stop() returned error: %v\n", err)
		}
	}
})
