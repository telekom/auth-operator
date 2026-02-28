/*
Copyright © 2026 Deutsche Telekom AG.
*/

package webhooks_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
	// +kubebuilder:scaffold:imports
)

// envtest globals shared by Ginkgo integration tests in this package.
// Standard testing.T tests (e.g. webhook_authorizer_test.go) do not use these.
var (
	envCfg     *rest.Config
	envClient  client.Client
	envTestEnv *envtest.Environment
	envCache   cache.Cache
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

	// Build a cache-backed client with field indexes so that MatchingFields
	// queries in the webhook handler work correctly during integration tests.
	envCache, err = cache.New(envCfg, cache.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())

	// Register the WebhookAuthorizer hasNamespaceSelector field index on the cache.
	ctx := context.Background()
	err = envCache.IndexField(ctx,
		&authorizationv1alpha1.WebhookAuthorizer{},
		indexer.WebhookAuthorizerHasNamespaceSelectorField,
		indexer.WebhookAuthorizerHasNamespaceSelectorFunc,
	)
	Expect(err).NotTo(HaveOccurred())

	// Start the cache in the background so it syncs with the API server.
	cacheCtx, cacheCancel := context.WithCancel(ctx)
	go func() {
		defer GinkgoRecover()
		Expect(envCache.Start(cacheCtx)).To(Succeed())
	}()
	DeferCleanup(func() { cacheCancel() })

	// Wait for the cache to sync before running tests.
	// Use a bounded timeout to prevent indefinite hangs in CI if the
	// API server or CRDs fail to initialize.
	syncCtx, syncCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer syncCancel()
	Expect(envCache.WaitForCacheSync(syncCtx)).To(BeTrue())

	// Create a delegating client: reads go through the indexed cache,
	// writes go directly to the API server.
	envClient, err = client.New(envCfg, client.Options{
		Scheme: scheme.Scheme,
		Cache: &client.CacheOptions{
			Reader: envCache,
		},
	})
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

// waitForCachedWA polls the cache-backed client until the WebhookAuthorizer
// with the given name is visible, ensuring cache propagation before
// assertions. This prevents flaky failures caused by watch event latency.
func waitForCachedWA(ctx context.Context, name string) {
	GinkgoHelper()
	Eventually(func() error {
		return envClient.Get(ctx, client.ObjectKey{Name: name}, &authorizationv1alpha1.WebhookAuthorizer{})
	}, 5*time.Second, 50*time.Millisecond).Should(Succeed(), "WebhookAuthorizer %q did not appear in cache", name)
}
