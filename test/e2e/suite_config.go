//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"strings"
)

// InstallMethod represents the operator installation method.
type InstallMethod string

// Supported install methods.
const (
	InstallMethodHelm      InstallMethod = "helm"
	InstallMethodKustomize InstallMethod = "kustomize"
	InstallMethodDev       InstallMethod = "dev"
)

// TestSuiteConfig defines configuration for an e2e test suite
// Each suite MUST use its own dedicated cluster to ensure isolation
type TestSuiteConfig struct {
	// SuiteName is the unique identifier for this test suite
	SuiteName string

	// ClusterName is the dedicated Kind cluster name for this suite
	// Format: auth-operator-e2e-{suite} (auto-generated if empty)
	ClusterName string

	// InstallMethod determines how the operator is installed
	InstallMethod InstallMethod

	// Namespace is the operator deployment namespace
	Namespace string

	// TestNamespaces are additional namespaces created for testing
	TestNamespaces []string

	// MultiNode indicates if a multi-node cluster is required (for HA tests)
	MultiNode bool

	// Labels are Ginkgo labels for test filtering
	Labels []string

	// Timeouts
	DeployTimeout    string
	ReconcileTimeout string
	PollingInterval  string

	// Debug settings
	DebugLevel       int
	CollectArtifacts bool
}

// ClusterMapping defines which test suite uses which cluster
// This ensures complete isolation between install methods
var ClusterMapping = map[string]TestSuiteConfig{
	"base": {
		SuiteName:        "base",
		ClusterName:      "auth-operator-e2e",
		InstallMethod:    InstallMethodDev,
		Namespace:        "auth-operator-system",
		Labels:           []string{"setup", "api", "debug"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "2m",
		PollingInterval:  "5s",
	},
	"helm": {
		SuiteName:        "helm",
		ClusterName:      "auth-operator-e2e-helm",
		InstallMethod:    InstallMethodHelm,
		Namespace:        "auth-operator-helm",
		TestNamespaces:   []string{"e2e-helm-test-ns"},
		Labels:           []string{"helm"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "3m",
		PollingInterval:  "5s",
	},
	"dev": {
		SuiteName:        "dev",
		ClusterName:      "auth-operator-e2e-dev",
		InstallMethod:    InstallMethodKustomize,
		Namespace:        "auth-operator-system",
		TestNamespaces:   []string{"dev-e2e-test-ns"},
		Labels:           []string{"dev"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "2m",
		PollingInterval:  "5s",
	},
	"complex": {
		SuiteName:        "complex",
		ClusterName:      "auth-operator-e2e-complex",
		InstallMethod:    InstallMethodHelm,
		Namespace:        "auth-operator-complex-test",
		TestNamespaces:   []string{"complex-e2e-test-ns", "complex-e2e-ns-team-a", "complex-e2e-ns-team-b"},
		Labels:           []string{"complex"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "3m",
		PollingInterval:  "5s",
	},
	"integration": {
		SuiteName:        "integration",
		ClusterName:      "auth-operator-e2e-integration",
		InstallMethod:    InstallMethodHelm,
		Namespace:        "auth-operator-integration-test",
		TestNamespaces:   []string{"integration-ns-alpha", "integration-ns-beta", "integration-ns-gamma"},
		Labels:           []string{"integration"},
		DeployTimeout:    "3m",
		ReconcileTimeout: "2m",
		PollingInterval:  "3s",
	},
	"golden": {
		SuiteName:        "golden",
		ClusterName:      "auth-operator-e2e-golden",
		InstallMethod:    InstallMethodHelm,
		Namespace:        "auth-operator-golden-test",
		Labels:           []string{"golden"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "2m",
		PollingInterval:  "5s",
	},
	"ha": {
		SuiteName:        "ha",
		ClusterName:      "auth-operator-e2e-ha-multi",
		InstallMethod:    InstallMethodHelm,
		Namespace:        "auth-operator-ha",
		TestNamespaces:   []string{"e2e-ha-test-ns"},
		MultiNode:        true,
		Labels:           []string{"ha", "leader-election"},
		DeployTimeout:    "5m",
		ReconcileTimeout: "3m",
		PollingInterval:  "5s",
	},
	"kustomize": {
		SuiteName:        "kustomize",
		ClusterName:      "", // No cluster needed - build-only tests
		InstallMethod:    InstallMethodKustomize,
		Labels:           []string{"kustomize"},
		DeployTimeout:    "1m",
		ReconcileTimeout: "1m",
		PollingInterval:  "5s",
	},
}

// GetSuiteConfig returns the configuration for a test suite
func GetSuiteConfig(suiteName string) (TestSuiteConfig, error) {
	config, ok := ClusterMapping[suiteName]
	if !ok {
		return TestSuiteConfig{}, fmt.Errorf("unknown test suite: %s", suiteName)
	}
	return config, nil
}

// GetSuiteForLabels determines which suite config to use based on active labels
func GetSuiteForLabels(labels []string) (TestSuiteConfig, error) {
	for _, label := range labels {
		for name, config := range ClusterMapping {
			for _, configLabel := range config.Labels {
				if label == configLabel {
					return ClusterMapping[name], nil
				}
			}
		}
	}
	return ClusterMapping["base"], nil
}

// ValidateClusterIsolation checks that the current cluster matches the expected suite
func ValidateClusterIsolation(config TestSuiteConfig) error {
	currentCluster := os.Getenv("KIND_CLUSTER")
	if currentCluster == "" {
		currentCluster = "auth-operator-e2e"
	}

	// Skip validation for kustomize tests (no cluster needed)
	if config.ClusterName == "" {
		return nil
	}

	// For base suite, the cluster is auth-operator-e2e which doesn't contain "base"
	// So we check against ClusterName directly
	if currentCluster != config.ClusterName {
		return fmt.Errorf(
			"cluster isolation violation: suite '%s' should run in cluster '%s' but running in '%s'",
			config.SuiteName, config.ClusterName, currentCluster,
		)
	}

	return nil
}

// PrintSuiteConfig prints the current test suite configuration
func PrintSuiteConfig(config TestSuiteConfig) {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                         TEST SUITE CONFIGURATION                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Suite:          %-60s ║
║ Cluster:        %-60s ║
║ Install Method: %-60s ║
║ Namespace:      %-60s ║
║ Multi-Node:     %-60v ║
║ Labels:         %-60s ║
╚══════════════════════════════════════════════════════════════════════════════╝
`,
		config.SuiteName,
		config.ClusterName,
		config.InstallMethod,
		config.Namespace,
		config.MultiNode,
		strings.Join(config.Labels, ", "),
	)
}

// GetAllClusterNames returns all cluster names for cleanup
func GetAllClusterNames() []string {
	clusters := make([]string, 0, len(ClusterMapping))
	seen := make(map[string]bool)
	for _, config := range ClusterMapping {
		if config.ClusterName != "" && !seen[config.ClusterName] {
			clusters = append(clusters, config.ClusterName)
			seen[config.ClusterName] = true
		}
	}
	return clusters
}

// InstallMethodDocs provides documentation for each install method
var InstallMethodDocs = map[InstallMethod]string{
	InstallMethodHelm: `
Helm Installation:
  - Uses chart/auth-operator Helm chart
  - Supports configurable values
  - Good for testing chart correctness
  - Command: helm install auth-operator chart/auth-operator -n <namespace>`,

	InstallMethodKustomize: `
Kustomize Installation:
  - Uses config/overlays/dev or config/overlays/production
  - Standard Kubernetes manifests
  - Good for testing raw manifests
  - Command: make deploy OVERLAY=dev`,

	InstallMethodDev: `
Dev Installation:
  - Uses make install && make deploy
  - Quick iteration during development
  - Debug logging enabled by default
  - Command: make install && make deploy OVERLAY=dev`,
}
