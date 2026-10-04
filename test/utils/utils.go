package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // dot import is standard Ginkgo convention
)

// DebugLevel controls verbosity of debug output (0=minimal, 1=normal, 2=verbose, 3=trace).
var DebugLevel = getDebugLevel()

// GetE2EOutputDir returns the base output directory for e2e artifacts.
// Can be overridden via E2E_OUTPUT_DIR; otherwise uses RUN_ID-based folder.
func GetE2EOutputDir() string {
	if dir := os.Getenv("E2E_OUTPUT_DIR"); dir != "" {
		return dir
	}
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		runID = time.Now().UTC().Format("20060102T150405Z")
	}
	return filepath.Join("test", "e2e", "output", runID)
}

// sanitizeOutputName creates a filesystem-safe path segment from input.
func sanitizeOutputName(value string) string {
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

// GetE2EOutputDirForContext returns an output directory for a specific context.
func GetE2EOutputDirForContext(contextName string) string {
	base := GetE2EOutputDir()
	if contextName == "" {
		return base
	}
	return filepath.Join(base, sanitizeOutputName(contextName))
}

func getDebugLevel() int {
	level := os.Getenv("E2E_DEBUG_LEVEL")
	switch level {
	case "0":
		return 0
	case "2":
		return 2
	case "3":
		return 3
	default:
		return 1
	}
}

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

// CommandContext builds external commands used by repository-owned e2e helpers.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 -- e2e helpers execute fixed test tooling with repo-controlled arguments.
	return exec.CommandContext(ctx, name, args...)
}

// DebugLogf writes debug output at the specified level.
func DebugLogf(level int, format string, args ...interface{}) {
	if level <= DebugLevel {
		prefix := ""
		switch level {
		case 0:
			prefix = "[ERROR] "
		case 1:
			prefix = "[INFO] "
		case 2:
			prefix = "[DEBUG] "
		case 3:
			prefix = "[TRACE] "
		}
		_, _ = fmt.Fprintf(GinkgoWriter, prefix+format+"\n", args...)
	}
}

// Run executes the provided command within this context.
func Run(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	DebugLogf(2, "running: %s", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		DebugLogf(1, "command failed: %s\nerror: %v\noutput: %s", command, err, string(output))
		return output, fmt.Errorf("%s failed with error: (%w) %s", command, err, string(output))
	}
	if DebugLevel >= 3 {
		DebugLogf(3, "command output: %s", string(output))
	}

	return output, nil
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster with the specified name.
func LoadImageToKindClusterWithName(name string) error {
	cluster := "auth-operator-e2e"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := CommandContext(context.Background(), "kind", kindOptions...) // #nosec G204
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is.
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

// ShouldTeardown controls whether tests should tear down operator/CRDs.
func ShouldTeardown() bool {
	return os.Getenv("E2E_TEARDOWN") == "true"
}

// WaitForPodsReady waits for all pods matching the label selector to be Ready.
func WaitForPodsReady(labelSelector, namespace string, timeout time.Duration) error {
	cmd := CommandContext(context.Background(), "kubectl", "wait", "pod", // #nosec G204
		"-l", labelSelector,
		"-n", namespace,
		"--for=condition=Ready",
		fmt.Sprintf("--timeout=%s", timeout.String()))
	_, err := Run(cmd)
	return err
}

// WaitForDeploymentAvailable waits for deployments matching label selector to be Available.
func WaitForDeploymentAvailable(labelSelector, namespace string, timeout time.Duration) error {
	cmd := CommandContext(context.Background(), "kubectl", "wait", "deployment", // #nosec G204
		"-l", labelSelector,
		"-n", namespace,
		"--for=condition=Available",
		fmt.Sprintf("--timeout=%s", timeout.String()))
	_, err := Run(cmd)
	return err
}

// WaitForDeploymentGone waits until no deployment matching the label selector
// remains in the namespace.
//
// Suites that install their own operator use this to prove the manager is
// actually gone before later specs run. A manager that outlives its suite keeps
// reconciling cluster-wide and races the operator those later specs own.
//
// `kubectl wait --for=delete` needs the object to still exist when it starts, so
// it errors out if the deployment has already been removed. This polls instead,
// which makes "already gone" the success case.
func WaitForDeploymentGone(labelSelector, namespace string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		cmd := CommandContext(context.Background(), "kubectl", "get", "deployment", // #nosec G204
			"-l", labelSelector,
			"-n", namespace,
			"--no-headers",
			"--ignore-not-found")
		output, err := Run(cmd)
		if err == nil && strings.TrimSpace(string(output)) == "" {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("timeout waiting for deployments with label %s in namespace %s to be deleted",
				labelSelector, namespace)
		}
		time.Sleep(2 * time.Second)
	}
}

// WaitForServiceEndpoints waits for a service to have endpoints.
func WaitForServiceEndpoints(serviceName, namespace string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := CommandContext(context.Background(), "kubectl", "get", "endpoints", serviceName, // #nosec G204
			"-n", namespace,
			"-o", "jsonpath={.subsets}")
		output, err := Run(cmd)
		if err == nil && strings.TrimSpace(string(output)) != "" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for endpoints for service %s in namespace %s", serviceName, namespace)
}

// WaitForWebhookConfigurations waits for webhook configurations matching label selector.
func WaitForWebhookConfigurations(labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		validatingConfigs, validatingWebhooks, _, validatingErr := getWebhookCABundleCounts("validatingwebhookconfiguration", labelSelector)
		mutatingConfigs, mutatingWebhooks, _, mutatingErr := getWebhookCABundleCounts("mutatingwebhookconfiguration", labelSelector)
		switch {
		case validatingErr != nil:
			lastErr = validatingErr
		case mutatingErr != nil:
			lastErr = mutatingErr
		default:
			configs := validatingConfigs + mutatingConfigs
			webhooks := validatingWebhooks + mutatingWebhooks
			if configs > 0 && webhooks > 0 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("timeout waiting for webhook configurations with label %s: %w", labelSelector, lastErr)
	}
	return fmt.Errorf("timeout waiting for webhook configurations with label %s", labelSelector)
}

// WaitForWebhookCABundle waits for the caBundle to be populated in webhook configurations.
// This ensures the cert-rotator has injected the CA certificate before attempting TLS validation.
func WaitForWebhookCABundle(labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var (
		lastConfigs  int
		lastWebhooks int
		lastBundles  int
		lastErr      error
	)
	for time.Now().Before(deadline) {
		mutatingConfigs, mutatingWebhooks, mutatingBundles, mutatingErr := getWebhookCABundleCounts("mutatingwebhookconfiguration", labelSelector)
		validatingConfigs, validatingWebhooks, validatingBundles, validatingErr := getWebhookCABundleCounts("validatingwebhookconfiguration", labelSelector)

		switch {
		case mutatingErr != nil:
			lastErr = mutatingErr
		case validatingErr != nil:
			lastErr = validatingErr
		default:
			lastErr = nil
			lastConfigs = mutatingConfigs + validatingConfigs
			lastWebhooks = mutatingWebhooks + validatingWebhooks
			lastBundles = mutatingBundles + validatingBundles

			if lastConfigs > 0 && lastWebhooks > 0 && lastBundles == lastWebhooks {
				if DebugLevel >= 1 {
					_, _ = fmt.Fprintf(GinkgoWriter, "Webhook CA bundles populated (configs: %d, webhooks: %d)\n",
						lastConfigs, lastWebhooks)
				}
				return nil
			}

			if DebugLevel >= 2 {
				_, _ = fmt.Fprintf(GinkgoWriter, "Waiting for CA bundle injection (configs: %d, webhooks: %d, bundles: %d)\n",
					lastConfigs, lastWebhooks, lastBundles)
			}
		}

		time.Sleep(2 * time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("timeout waiting for webhook CA bundle to be injected (label: %s): %w", labelSelector, lastErr)
	}
	return fmt.Errorf("timeout waiting for webhook CA bundle to be injected (label: %s, configs: %d, webhooks: %d, bundles: %d)",
		labelSelector, lastConfigs, lastWebhooks, lastBundles)
}

type webhookConfigurationList struct {
	Items []webhookConfiguration `json:"items"`
}

type webhookConfiguration struct {
	Webhooks []webhookEntry `json:"webhooks"`
}

type webhookEntry struct {
	ClientConfig webhookClientConfig `json:"clientConfig"`
}

type webhookClientConfig struct {
	CABundle string `json:"caBundle"`
}

func getWebhookCABundleCounts(kind, labelSelector string) (configCount, webhookCount, bundleCount int, err error) {
	cmd := CommandContext(context.Background(), "kubectl", "get", kind, // #nosec G204
		"-l", labelSelector,
		"-o", "json")
	output, err := Run(cmd)
	if err != nil {
		return 0, 0, 0, err
	}
	return countWebhookCABundles(output)
}

func countWebhookCABundles(output []byte) (configCount, webhookCount, bundleCount int, err error) {
	var list webhookConfigurationList
	if err := json.Unmarshal(output, &list); err != nil {
		return 0, 0, 0, fmt.Errorf("parse webhook configuration list: %w", err)
	}

	configCount = len(list.Items)
	for _, item := range list.Items {
		webhookCount += len(item.Webhooks)
		for _, webhook := range item.Webhooks {
			if strings.TrimSpace(webhook.ClientConfig.CABundle) != "" {
				bundleCount++
			}
		}
	}

	return configCount, webhookCount, bundleCount, nil
}

// WaitForWebhookReady waits for the webhook to be fully operational by performing a
// dry-run RoleDefinition create that exercises the active validating webhook.
func WaitForWebhookReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	manifest := `apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: webhook-readiness-check
spec:
  targetRole: ClusterRole
  targetName: webhook-readiness-check
  scopeNamespaced: false
`
	var lastErr error

	for time.Now().Before(deadline) {
		cmd := CommandContext(context.Background(), "kubectl", "apply", "--dry-run=server", "-f", "-") // #nosec G204
		cmd.Stdin = strings.NewReader(manifest)
		_, err := Run(cmd)
		if err == nil {
			if DebugLevel >= 1 {
				_, _ = fmt.Fprintf(GinkgoWriter, "Webhook readiness check passed\n")
			}
			return nil
		}
		lastErr = err

		// Check if it's a TLS error - we should keep retrying
		errStr := err.Error()
		if strings.Contains(errStr, "x509") ||
			strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "tls") ||
			strings.Contains(errStr, "connection refused") {
			if DebugLevel >= 2 {
				_, _ = fmt.Fprintf(GinkgoWriter, "Webhook not ready (TLS error), retrying: %v\n", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		// If it's not a TLS error, we might have a different problem
		// but let's still retry a few times in case of transient issues
		if DebugLevel >= 2 {
			_, _ = fmt.Fprintf(GinkgoWriter, "Webhook dry-run failed (non-TLS error), retrying: %v\n", err)
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for webhook to be ready: %w", lastErr)
}

// ApplyManifest applies a YAML manifest from a string using server-side apply.
func ApplyManifest(manifest string) error {
	cmd := CommandContext(context.Background(), "kubectl", "apply", "--server-side", "--force-conflicts", "-f", "-") // #nosec G204
	cmd.Stdin = strings.NewReader(manifest)
	_, err := Run(cmd)
	return err
}

// GetResourceField gets a specific field from a resource using jsonpath.
func GetResourceField(resourceType, name, namespace, jsonpath string) (string, error) {
	args := []string{"get", resourceType, name, "-o", fmt.Sprintf("jsonpath=%s", jsonpath)}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	cmd := CommandContext(context.Background(), "kubectl", args...) // #nosec G204
	output, err := Run(cmd)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// CleanupWebhooks removes ValidatingWebhookConfigurations and MutatingWebhookConfigurations
// with the specified label selector. This is important between test runs to avoid conflicts.
func CleanupWebhooks(labelSelector string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "Cleaning up webhooks with label: %s\n", labelSelector)

	// Clean up ValidatingWebhookConfigurations
	cmd := CommandContext(context.Background(), "kubectl", "delete", "validatingwebhookconfiguration", // #nosec G204
		"-l", labelSelector, "--ignore-not-found=true")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}

	// Clean up MutatingWebhookConfigurations
	cmd = CommandContext(context.Background(), "kubectl", "delete", "mutatingwebhookconfiguration", // #nosec G204
		"-l", labelSelector, "--ignore-not-found=true")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// CleanupAllAuthOperatorWebhooks removes all auth-operator related webhooks.
func CleanupAllAuthOperatorWebhooks() {
	_, _ = fmt.Fprintf(GinkgoWriter, "Cleaning up all auth-operator webhooks\n")

	// Clean by name pattern
	webhookPatterns := []string{
		"auth-operator",
		"roledefinition",
		"binddefinition",
		"webhookauthorizer",
	}

	for _, pattern := range webhookPatterns {
		cmd := CommandContext(context.Background(), "kubectl", "get", "validatingwebhookconfiguration", "-o", "name") // #nosec G204
		output, _ := Run(cmd)
		for _, line := range GetNonEmptyLines(string(output)) {
			if strings.Contains(line, pattern) {
				name := strings.TrimPrefix(line, "validatingwebhookconfiguration.admissionregistration.k8s.io/")
				cmd := CommandContext(context.Background(), "kubectl", "delete", "validatingwebhookconfiguration", name, "--ignore-not-found=true") // #nosec G204
				_, _ = Run(cmd)
			}
		}

		cmd = CommandContext(context.Background(), "kubectl", "get", "mutatingwebhookconfiguration", "-o", "name") // #nosec G204
		output, _ = Run(cmd)
		for _, line := range GetNonEmptyLines(string(output)) {
			if strings.Contains(line, pattern) {
				name := strings.TrimPrefix(line, "mutatingwebhookconfiguration.admissionregistration.k8s.io/")
				cmd := CommandContext(context.Background(), "kubectl", "delete", "mutatingwebhookconfiguration", name, "--ignore-not-found=true") // #nosec G204
				_, _ = Run(cmd)
			}
		}
	}
}

// RemoveFinalizersForAll removes finalizers from all resources of a given type.
func RemoveFinalizersForAll(resourceType string) {
	cmd := CommandContext(context.Background(), "kubectl", "get", resourceType, "-A", // #nosec G204
		"-o", `jsonpath={range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}`)
	output, err := Run(cmd)
	if err != nil {
		warnError(err)
		return
	}

	for _, line := range GetNonEmptyLines(string(output)) {
		ns, name := parseNamespacedName(line)
		args := []string{"patch", resourceType, name, "--type=merge", "-p", `{"metadata":{"finalizers":[]}}`}
		if ns != "" {
			args = append(args, "-n", ns)
		}
		patch := CommandContext(context.Background(), "kubectl", args...) // #nosec G204
		if _, err := Run(patch); err != nil {
			warnError(err)
		}
	}
}

// parseNamespacedName parses "namespace/name" or "/name" for cluster-scoped resources.
func parseNamespacedName(value string) (namespace, name string) {
	parts := strings.SplitN(value, "/", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	if parts[0] == "" {
		return "", parts[1]
	}
	return parts[0], parts[1]
}

// CleanupResourcesByLabel deletes resources by label selector with optional namespace.
func CleanupResourcesByLabel(resourceType, labelSelector, namespace string) {
	args := []string{
		"delete", resourceType, "-l", labelSelector,
		"--ignore-not-found=true", "--wait=false", "--timeout=30s",
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	cmd := CommandContext(context.Background(), "kubectl", args...) // #nosec G204
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// CleanupNamespace deletes a namespace and waits for it to be fully removed.
func CleanupNamespace(namespace string) {
	cmd := CommandContext(context.Background(), "kubectl", "delete", "ns", namespace, "--ignore-not-found=true", "--wait=false") // #nosec G204
	_, _ = Run(cmd)

	// Wait for namespace to be deleted (with timeout)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := CommandContext(context.Background(), "kubectl", "get", "ns", namespace) // #nosec G204
		if _, err := Run(cmd); err != nil {
			// Namespace is gone
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// CleanupClusterResources cleans up cluster-scoped resources created by tests.
func CleanupClusterResources(labelSelector string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "Cleaning up cluster resources with label: %s\n", labelSelector)

	resources := []string{"clusterrole", "clusterrolebinding"}
	for _, resource := range resources {
		args := []string{
			"delete", resource, "-l", labelSelector,
			"--ignore-not-found=true", "--wait=false", "--timeout=30s",
		}
		cmd := CommandContext(context.Background(), "kubectl", args...) // #nosec G204
		if _, err := Run(cmd); err != nil {
			warnError(err)
		}
	}
}

// =============================================================================
// Debug and Diagnostic Functions
// =============================================================================.

// CollectClusterDebugInfo gathers comprehensive cluster debug information
// and writes it to GinkgoWriter. Call this on test failures.
func CollectClusterDebugInfo(contextName string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== DEBUG INFO COLLECTION: %s\n", contextName)
	_, _ = fmt.Fprintf(GinkgoWriter, "=== Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339))
	printSeparatorWithNewline()

	// Cluster connectivity
	collectSection("Cluster Info", func() {
		runDebugCommand("kubectl", "cluster-info")
		runDebugCommand("kubectl", "version", "--short")
	})

	// Nodes
	collectSection("Nodes", func() {
		runDebugCommand("kubectl", "get", "nodes", "-o", "wide")
		runDebugCommand("kubectl", "describe", "nodes")
	})

	// All namespaces and their status
	collectSection("Namespaces", func() {
		runDebugCommand("kubectl", "get", "namespaces", "-o", "wide")
	})

	// All pods across all namespaces
	collectSection("All Pods", func() {
		runDebugCommand("kubectl", "get", "pods", "-A", "-o", "wide")
	})

	// Auth-operator specific resources
	collectSection("Auth-Operator Resources", func() {
		runDebugCommand("kubectl", "get", "roledefinitions", "-A", "-o", "wide")
		runDebugCommand("kubectl", "get", "binddefinitions", "-A", "-o", "wide")
		runDebugCommand("kubectl", "get", "webhookauthorizers", "-A", "-o", "wide")
	})

	// Generated RBAC resources
	authOpLabel := "app.kubernetes.io/managed-by=auth-operator"
	collectSection("Generated RBAC Resources", func() {
		runDebugCommand("kubectl", "get", "clusterroles", "-l", authOpLabel, "-o", "wide")
		runDebugCommand("kubectl", "get", "clusterrolebindings", "-l", authOpLabel, "-o", "wide")
		runDebugCommand("kubectl", "get", "roles", "-A", "-l", authOpLabel, "-o", "wide")
		runDebugCommand("kubectl", "get", "rolebindings", "-A", "-l", authOpLabel, "-o", "wide")
	})

	// Webhooks
	collectSection("Webhook Configurations", func() {
		runDebugCommand("kubectl", "get", "validatingwebhookconfiguration", "-o", "wide")
		runDebugCommand("kubectl", "get", "mutatingwebhookconfiguration", "-o", "wide")
	})

	// Events (recent)
	collectSection("Recent Events (all namespaces)", func() {
		runDebugCommand("kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp")
	})

	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== END DEBUG INFO COLLECTION\n")
	printSeparatorWithNewline()
}

// CollectNamespaceDebugInfo gathers debug info for a specific namespace.
func CollectNamespaceDebugInfo(namespace, contextName string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== NAMESPACE DEBUG: %s (ns: %s)\n", contextName, namespace)
	_, _ = fmt.Fprintf(GinkgoWriter, "=== Timestamp: %s\n", time.Now().UTC().Format(time.RFC3339))
	printSeparatorWithNewline()

	collectSection("Namespace Details", func() {
		runDebugCommand("kubectl", "get", "ns", namespace, "-o", "yaml")
	})

	collectSection("All Resources in Namespace", func() {
		runDebugCommand("kubectl", "get", "all", "-n", namespace, "-o", "wide")
	})

	collectSection("Pods in Namespace", func() {
		runDebugCommand("kubectl", "get", "pods", "-n", namespace, "-o", "wide")
		runDebugCommand("kubectl", "describe", "pods", "-n", namespace)
	})

	collectSection("Events in Namespace", func() {
		runDebugCommand("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
	})

	collectSection("ConfigMaps and Secrets", func() {
		runDebugCommand("kubectl", "get", "configmaps", "-n", namespace)
		runDebugCommand("kubectl", "get", "secrets", "-n", namespace)
	})

	collectSection("Services and Endpoints", func() {
		runDebugCommand("kubectl", "get", "services", "-n", namespace, "-o", "wide")
		runDebugCommand("kubectl", "get", "endpoints", "-n", namespace)
	})

	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== END NAMESPACE DEBUG\n")
	printSeparatorWithNewline()
}

// CollectOperatorLogs collects logs from auth-operator pods in the specified namespace.
func CollectOperatorLogs(namespace string, tailLines int) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== OPERATOR LOGS (ns: %s, tail: %d)\n", namespace, tailLines)
	printSeparatorWithNewline()

	// Controller manager logs
	collectSection("Controller Manager Logs", func() {
		runDebugCommand("kubectl", "logs", "-n", namespace, "-l", "control-plane=controller-manager",
			"--tail", fmt.Sprintf("%d", tailLines), "--all-containers=true")
	})

	// Webhook server logs
	collectSection("Webhook Server Logs", func() {
		runDebugCommand("kubectl", "logs", "-n", namespace, "-l", "control-plane=webhook-server",
			"--tail", fmt.Sprintf("%d", tailLines), "--all-containers=true")
	})

	// Try Helm-style labels too
	collectSection("Controller Logs (Helm labels)", func() {
		runDebugCommand("kubectl", "logs", "-n", namespace, "-l", "app.kubernetes.io/component=controller",
			"--tail", fmt.Sprintf("%d", tailLines), "--all-containers=true")
	})

	collectSection("Webhook Logs (Helm labels)", func() {
		runDebugCommand("kubectl", "logs", "-n", namespace, "-l", "app.kubernetes.io/component=webhook",
			"--tail", fmt.Sprintf("%d", tailLines), "--all-containers=true")
	})

	// Previous container logs (if crashed)
	collectSection("Previous Controller Logs (if any)", func() {
		runDebugCommand("kubectl", "logs", "-n", namespace, "-l", "control-plane=controller-manager",
			"--tail", fmt.Sprintf("%d", tailLines), "--previous", "--all-containers=true")
	})

	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== END OPERATOR LOGS\n")
	printSeparatorWithNewline()
}

// CollectCRDDebugInfo collects detailed info about auth-operator CRDs and their instances.
func CollectCRDDebugInfo() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== CRD DEBUG INFO\n")
	printSeparatorWithNewline()

	collectSection("RoleDefinitions (detailed)", func() {
		runDebugCommand("kubectl", "get", "roledefinitions", "-A", "-o", "yaml")
	})

	collectSection("BindDefinitions (detailed)", func() {
		runDebugCommand("kubectl", "get", "binddefinitions", "-A", "-o", "yaml")
	})

	collectSection("WebhookAuthorizers (detailed)", func() {
		runDebugCommand("kubectl", "get", "webhookauthorizers", "-A", "-o", "yaml")
	})

	collectSection("CRD Status", func() {
		runDebugCommand("kubectl", "get", "crd", "roledefinitions.authorization.t-caas.telekom.com", "-o", "yaml")
		runDebugCommand("kubectl", "get", "crd", "binddefinitions.authorization.t-caas.telekom.com", "-o", "yaml")
		runDebugCommand("kubectl", "get", "crd", "webhookauthorizers.authorization.t-caas.telekom.com", "-o", "yaml")
	})

	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== END CRD DEBUG INFO\n")
	printSeparatorWithNewline()
}

// CollectDockerDebugInfo collects Docker/container runtime debug info.
func CollectDockerDebugInfo() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== DOCKER/CONTAINER DEBUG INFO\n")
	printSeparatorWithNewline()

	collectSection("Docker Info", func() {
		runDebugCommand("docker", "info")
	})

	collectSection("Docker Containers", func() {
		runDebugCommand("docker", "ps", "-a")
	})

	collectSection("Docker Images", func() {
		runDebugCommand("docker", "images")
	})

	collectSection("Docker Networks", func() {
		runDebugCommand("docker", "network", "ls")
	})

	collectSection("Kind Clusters", func() {
		runDebugCommand("kind", "get", "clusters")
	})

	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== END DOCKER DEBUG INFO\n")
	printSeparatorWithNewline()
}

// SaveDebugInfoToFile saves debug info to a file in the output directory.
func SaveDebugInfoToFile(outputDir, filename, content string) error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return err
	}

	filePath := filepath.Join(outputDir, filename)
	return os.WriteFile(filePath, []byte(content), 0o600)
}

// CollectAndSaveAllDebugInfo collects all debug info and saves to files
// into a per-test output directory. Console output is only produced when
// E2E_DEBUG_LEVEL >= 2 to avoid flooding stdout.
func CollectAndSaveAllDebugInfo(testContext string) {
	// Only output to GinkgoWriter if debug level is high
	if DebugLevel >= 2 {
		CollectClusterDebugInfo(testContext)
	} else {
		DebugLogf(1, "Saving debug info to files (set E2E_DEBUG_LEVEL=2 for console output)")
	}

	// Save to files for CI artifacts
	outputDir := GetE2EOutputDirForContext(testContext)
	_ = os.MkdirAll(outputDir, 0o750)

	// Cluster dump
	cmd := CommandContext(context.Background(), "kubectl", "cluster-info", "dump", "--output-directory", filepath.Join(outputDir, "cluster-dump")) // #nosec G204
	_, _ = Run(cmd)

	// All resources
	cmd = CommandContext(context.Background(), "kubectl", "get", "all", "-A", "-o", "wide") // #nosec G204
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "all-resources.txt", string(output))
	}

	// Events
	cmd = CommandContext(context.Background(), "kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp") // #nosec G204
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "events.txt", string(output))
	}

	// Pods
	cmd = CommandContext(context.Background(), "kubectl", "get", "pods", "-A", "-o", "wide") // #nosec G204
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "pods.txt", string(output))
	}

	// CRD instances
	for _, crd := range []string{"roledefinitions", "binddefinitions", "webhookauthorizers"} {
		cmd = CommandContext(context.Background(), "kubectl", "get", crd, "-A", "-o", "yaml") // #nosec G204
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, crd+".yaml", string(output))
		}
	}

	// Operator logs by namespace (if present)
	operatorNamespaces := []string{
		"auth-operator-system",
		"auth-operator-helm",
		"auth-operator-creator-e2e",
		"auth-operator-ha",
		"auth-operator-integration-test",
	}
	for _, ns := range operatorNamespaces {
		cmd = CommandContext(context.Background(), "kubectl", "get", "ns", ns, "-o", "name") // #nosec G204
		if _, err := Run(cmd); err != nil {
			continue
		}
		cmd = CommandContext(context.Background(), "kubectl", "logs", "-n", ns, "-l", "control-plane=controller-manager", "--tail=1000") // #nosec G204
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, fmt.Sprintf("%s-controller-logs.txt", ns), string(output))
		}
		cmd = CommandContext(context.Background(), "kubectl", "logs", "-n", ns, "-l", "app.kubernetes.io/component=webhook", "--tail=1000") // #nosec G204
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, fmt.Sprintf("%s-webhook-logs.txt", ns), string(output))
		}
	}

	DebugLogf(1, "Debug info saved to %s", outputDir)
}

// separator is used for debug output formatting (80 chars to fit line limits).
const separator = "================================================================================"

// printSeparator prints a separator line to GinkgoWriter.
func printSeparator() {
	_, _ = fmt.Fprintf(GinkgoWriter, "%s\n", separator)
}

// printSeparatorWithNewline prints a separator line with trailing newline.
func printSeparatorWithNewline() {
	_, _ = fmt.Fprintf(GinkgoWriter, "%s\n\n", separator)
}

// collectSection is a helper to print a section header and run collection functions.
func collectSection(title string, fn func()) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- %s ---\n", title)
	fn()
}

// runDebugCommand runs a command and prints output to GinkgoWriter (ignores errors).
func runDebugCommand(name string, args ...string) {
	cmd := CommandContext(context.Background(), name, args...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "$ %s %s\n[error: %v]\n", name, strings.Join(args, " "), err)
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "$ %s %s\n%s\n", name, strings.Join(args, " "), string(output))
	}
}
