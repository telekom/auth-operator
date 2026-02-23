/*
Copyright © 2026 Deutsche Telekom AG.
*/

package webhooks_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// envtest globals shared by Ginkgo integration tests in this package.
// Standard testing.T tests (e.g. webhook_authorizer_test.go) do not use these.
var (
	envCfg     *rest.Config
	envClient  client.Client
	envTestEnv *envtest.Environment
)

func TestWebhookIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Webhook Authorization Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping envtest environment for webhook integration tests")
	envTestEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue(), "failed to determine caller information")
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
		absRepoRoot, absErr := filepath.Abs(repoRoot)
		Expect(absErr).NotTo(HaveOccurred())
		envTestEnv.BinaryAssetsDirectory = filepath.Join(absRepoRoot, "bin", "k8s",
			fmt.Sprintf("1.34.1-%s-%s", runtime.GOOS, runtime.GOARCH))
	}

	var err error
	envCfg, err = envTestEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(envCfg).NotTo(BeNil())

	err = authorizationv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	envClient, err = client.New(envCfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(envClient).NotTo(BeNil())
})

var _ = AfterSuite(func() {
	By("tearing down envtest environment")
	if envTestEnv != nil {
		err := envTestEnv.Stop()
		if err != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "warning: envTestEnv.Stop() returned error: %v\n", err)
		}
	}
})
