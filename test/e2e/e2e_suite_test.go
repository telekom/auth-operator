//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var (
	// skipClusterSetup allows skipping cluster setup when running against an existing cluster
	skipClusterSetup = os.Getenv("SKIP_CLUSTER_SETUP") == "true"
	// kindClusterName is the name of the kind cluster to use
	kindClusterName = getEnvOrDefault("KIND_CLUSTER", "auth-operator-e2e")
	// projectImage is the operator image to test
	projectImage = getEnvOrDefault("IMG", "auth-operator:e2e-test")
	// debugOnFailure controls whether to collect debug info on test failures
	debugOnFailure = os.Getenv("E2E_DEBUG_ON_FAILURE") != "false"
)

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func setSuiteOutputDir(suite string) {
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		runID = time.Now().UTC().Format("20060102T150405Z")
	}
	outputDir := filepath.Join("test/e2e/output", runID, suite)
	_ = os.MkdirAll(outputDir, 0o755)
	_ = os.Setenv("E2E_OUTPUT_DIR", outputDir)
}

func sanitizeSpecName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		" ", "_",
		":", "_",
		"|", "_",
		"\t", "_",
		"\n", "_",
		"\r", "_",
	)
	value = replacer.Replace(value)
	if len(value) > 120 {
		value = value[:120]
	}
	return value
}

func specOutputDir(report SpecReport) string {
	base := utils.GetE2EOutputDir()
	name := report.LeafNodeText
	if name == "" {
		name = report.FullText()
	}
	stamp := report.StartTime.UTC().Format("20060102-150405")
	folder := fmt.Sprintf("%s-%s", stamp, sanitizeSpecName(name))
	return filepath.Join(base, "specs", sanitizeSpecName(report.State.String()), folder)
}

// Run e2e tests using the Ginkgo runner.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "=== Starting auth-operator e2e suite ===\n")
	_, _ = fmt.Fprintf(GinkgoWriter, "  Kind cluster: %s\n", kindClusterName)
	_, _ = fmt.Fprintf(GinkgoWriter, "  Project image: %s\n", projectImage)
	_, _ = fmt.Fprintf(GinkgoWriter, "  Skip cluster setup: %v\n", skipClusterSetup)
	_, _ = fmt.Fprintf(GinkgoWriter, "  Debug on failure: %v\n", debugOnFailure)
	_, _ = fmt.Fprintf(GinkgoWriter, "  E2E_DEBUG_LEVEL: %d\n", utils.DebugLevel)
	_, _ = fmt.Fprintf(GinkgoWriter, "  Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(GinkgoWriter, "======================================\n\n")
	RunSpecs(t, "Auth Operator E2E Suite")
}

var _ = BeforeSuite(func() {
	By("Printing environment info")
	printEnvironmentInfo()

	By("Waiting for cluster to be fully ready")
	Eventually(func() error {
		cmd := exec.CommandContext(context.Background(), "kubectl", "cluster-info")
		_, err := utils.Run(cmd)
		return err
	}, 2*time.Minute, 5*time.Second).Should(Succeed(), "Kubernetes cluster not available")

	By("Waiting for API server to be ready")
	Eventually(func() error {
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "nodes", "-o", "name")
		_, err := utils.Run(cmd)
		return err
	}, 2*time.Minute, 5*time.Second).Should(Succeed(), "Cannot connect to API server")

	By("Cleaning up any pre-existing auth-operator installations")
	cleanupPreExistingInstallations()

	By("Printing initial cluster state")
	printClusterState()

	// Note: cert-manager is NOT required - the webhook uses the cert-controller/pkg/rotator
	// to self-sign and rotate certificates automatically.

	By("Suite setup complete")
})

var _ = AfterSuite(func() {
	By("Collecting final debug info")
	if debugOnFailure {
		utils.CollectAndSaveAllDebugInfo("AfterSuite")
	}

	By("Cleaning up webhooks that might interfere with other tests")
	utils.CleanupAllAuthOperatorWebhooks()
})

// AfterEach records a per-spec summary and collects full artifacts on failure (or when forced).
var _ = AfterEach(func() {
	report := CurrentSpecReport()
	context := fmt.Sprintf("Spec: %s", report.FullText())
	outputDir := specOutputDir(report)

	// Generate structured debug report
	debugReport := GenerateDebugReport(report, detectInstallMethod())

	// Always save summary
	summary := fmt.Sprintf("# Spec Summary\n\n- Name: %s\n- State: %s\n- Start: %s\n- End: %s\n- Run Time: %s\n",
		report.FullText(), report.State, report.StartTime.UTC().Format(time.RFC3339), report.EndTime.UTC().Format(time.RFC3339), report.RunTime)
	_ = utils.SaveDebugInfoToFile(outputDir, "summary.md", summary)

	forceAll := os.Getenv("E2E_COLLECT_ALL_SPECS") == "true"
	if report.Failed() || forceAll {
		prevOutputDir := os.Getenv("E2E_OUTPUT_DIR")
		_ = os.Setenv("E2E_OUTPUT_DIR", outputDir)
		defer func() {
			_ = os.Setenv("E2E_OUTPUT_DIR", prevOutputDir)
		}()

		// Save structured JSON debug report
		_ = SaveDebugReport(debugReport, outputDir)

		utils.CollectAndSaveAllDebugInfo(context)
	}
})

// ReportAfterEach collects debug info when a test fails
var _ = ReportAfterEach(func(report SpecReport) {
	if report.Failed() && debugOnFailure {
		// Generate and print concise summary
		debugReport := GenerateDebugReport(report, detectInstallMethod())
		PrintConciseSummary(debugReport)

		_, _ = fmt.Fprintf(GinkgoWriter, "\n")
		_, _ = fmt.Fprintf(GinkgoWriter, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
		_, _ = fmt.Fprintf(GinkgoWriter, "!!! TEST FAILED: %s\n", report.FullText())
		_, _ = fmt.Fprintf(GinkgoWriter, "!!! Failure: %s\n", report.Failure.Message)
		_, _ = fmt.Fprintf(GinkgoWriter, "!!! Location: %s\n", report.Failure.Location.String())
		_, _ = fmt.Fprintf(GinkgoWriter, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n")

		// Collect comprehensive debug info
		utils.CollectClusterDebugInfo(report.FullText())

		// Collect operator logs from known namespaces
		operatorNamespaces := []string{
			"auth-operator-system",
			"auth-operator-helm",
			"auth-operator-ha",
			"auth-operator-integration-test",
		}
		for _, ns := range operatorNamespaces {
			utils.CollectOperatorLogs(ns, 100)
		}

		// Collect CRD debug info
		utils.CollectCRDDebugInfo()
	}
})

// detectInstallMethod attempts to detect the install method based on current labels/context
func detectInstallMethod() string {
	cluster := os.Getenv("KIND_CLUSTER")
	if cluster == "" {
		cluster = kindClusterName
	}
	switch {
	case strings.Contains(cluster, "helm"):
		return "helm"
	case strings.Contains(cluster, "dev"):
		return "kustomize"
	case strings.Contains(cluster, "ha"):
		return "helm-ha"
	default:
		return "dev"
	}
}

// printEnvironmentInfo prints useful environment information for debugging
func printEnvironmentInfo() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Environment Info ===\n")

	// Print relevant environment variables
	envVars := []string{
		"KIND_CLUSTER",
		"IMG",
		"SKIP_CLUSTER_SETUP",
		"E2E_DEBUG_LEVEL",
		"E2E_DEBUG_ON_FAILURE",
		"KUBECONFIG",
		"HOME",
		"USER",
	}
	for _, env := range envVars {
		val := os.Getenv(env)
		if val != "" {
			_, _ = fmt.Fprintf(GinkgoWriter, "  %s=%s\n", env, val)
		}
	}

	// Print Go version
	cmd := exec.CommandContext(context.Background(), "go", "version")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "  Go: %s", string(output))
	}

	// Print kubectl version
	cmd = exec.CommandContext(context.Background(), "kubectl", "version", "--client", "--short")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "  kubectl: %s", string(output))
	}

	// Print kind version
	cmd = exec.CommandContext(context.Background(), "kind", "version")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "  kind: %s", string(output))
	}

	// Print docker version
	cmd = exec.CommandContext(context.Background(), "docker", "version", "--format", "{{.Server.Version}}")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "  docker: %s\n", string(output))
	}

	_, _ = fmt.Fprintf(GinkgoWriter, "========================\n\n")
}

// printClusterState prints the current cluster state for debugging
func printClusterState() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Initial Cluster State ===\n")

	// Nodes
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "nodes", "-o", "wide")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Nodes:\n%s\n", string(output))
	}

	// Namespaces
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "namespaces")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Namespaces:\n%s\n", string(output))
	}

	// CRDs
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "crds")
	if output, err := cmd.CombinedOutput(); err == nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "CRDs:\n%s\n", string(output))
	}

	_, _ = fmt.Fprintf(GinkgoWriter, "==============================\n\n")
}

// cleanupPreExistingInstallations removes any pre-existing auth-operator installations
// that might interfere with tests. This ensures a clean slate for each test run.
func cleanupPreExistingInstallations() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Cleaning up pre-existing installations ===\n")

	// First, delete all webhooks to prevent namespace deletion failures
	_, _ = fmt.Fprintf(GinkgoWriter, "Removing all auth-operator webhooks...\n")
	utils.CleanupAllAuthOperatorWebhooks()

	// Check for helm releases
	cmd := exec.CommandContext(context.Background(), "helm", "list", "-A", "-o", "json")
	if output, err := cmd.CombinedOutput(); err == nil {
		outputStr := string(output)
		// Simple check for auth-operator releases
		if strings.Contains(outputStr, "auth-operator") {
			_, _ = fmt.Fprintf(GinkgoWriter, "Found auth-operator helm releases, uninstalling...\n")

			// Try common release names and namespaces
			releases := []struct{ name, ns string }{
				{"auth-operator", "auth-operator-system"},
				{"auth-operator-int", "auth-operator-integration-test"},
				{"auth-operator-helm", "auth-operator-helm"},
				{"auth-operator-ha", "auth-operator-ha"},
			}
			for _, r := range releases {
				uninstallCmd := exec.CommandContext(context.Background(), "helm", "uninstall", r.name, "-n", r.ns)
				_, _ = uninstallCmd.CombinedOutput() // Ignore errors
			}
		}
	}

	// Clean up known test namespaces
	testNamespaces := []string{
		"auth-operator-system",
		"auth-operator-integration-test",
		"auth-operator-helm",
		"auth-operator-ha",
		"auth-operator-golden-test",
		"auth-operator-complex-test",
		"integration-ns-alpha",
		"integration-ns-beta",
		"integration-ns-gamma",
		"e2e-test-ns",
		"e2e-helm-test-ns",
		"e2e-ha-test-ns",
		"dev-e2e-test-ns",
		"complex-team-alpha",
		"complex-team-beta",
	}
	for _, ns := range testNamespaces {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found=true", "--wait=false")
		_, _ = cmd.CombinedOutput()
	}

	// Wait a moment for deletions to propagate
	time.Sleep(2 * time.Second)
	_, _ = fmt.Fprintf(GinkgoWriter, "Pre-existing installations cleanup complete\n")
	_, _ = fmt.Fprintf(GinkgoWriter, "=============================================\n\n")
}
