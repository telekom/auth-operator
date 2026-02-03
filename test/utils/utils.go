package utils //nolint:revive

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
)

const (
	prometheusOperatorVersion = "v0.72.0"
	prometheusOperatorURL     = "https://github.com/prometheus-operator/prometheus-operator/" +
		"releases/download/%s/bundle.yaml"

	certmanagerVersion = "v1.14.4"
	certmanagerURLTmpl = "https://github.com/jetstack/cert-manager/releases/download/%s/cert-manager.yaml"
)

// DebugLevel controls verbosity of debug output (0=minimal, 1=normal, 2=verbose, 3=trace)
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
	return filepath.Join("test/e2e/output", runID)
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
func GetE2EOutputDirForContext(context string) string {
	base := GetE2EOutputDir()
	if context == "" {
		return base
	}
	return filepath.Join(base, sanitizeOutputName(context))
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

// DebugLog writes debug output at the specified level
func DebugLog(level int, format string, args ...interface{}) {
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

// DebugSection prints a visually distinct section header
func DebugSection(title string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	_, _ = fmt.Fprintf(GinkgoWriter, "═══════════════════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(GinkgoWriter, "  %s\n", title)
	_, _ = fmt.Fprintf(GinkgoWriter, "═══════════════════════════════════════════════════════════════════════════════\n\n")
}

// DebugSubSection prints a subsection header
func DebugSubSection(title string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n───────────────────────────────────────────────────────────────────────────────\n")
	_, _ = fmt.Fprintf(GinkgoWriter, "  %s\n", title)
	_, _ = fmt.Fprintf(GinkgoWriter, "───────────────────────────────────────────────────────────────────────────────\n")
}

// DebugTable prints data in a table format
func DebugTable(headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	for i, h := range headers {
		_, _ = fmt.Fprintf(GinkgoWriter, "%-*s  ", widths[i], h)
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")

	// Print separator
	for _, w := range widths {
		_, _ = fmt.Fprintf(GinkgoWriter, "%s  ", strings.Repeat("-", w))
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				_, _ = fmt.Fprintf(GinkgoWriter, "%-*s  ", widths[i], cell)
			}
		}
		_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	}
}

// InstallPrometheusOperator installs the prometheus Operator to be used to export the enabled metrics.
func InstallPrometheusOperator() error {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.CommandContext(context.Background(), "kubectl", "create", "-f", url)
	_, err := Run(cmd)
	return err
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	DebugLog(2, "running: %s", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		DebugLog(1, "command failed: %s\nerror: %v\noutput: %s", command, err, string(output))
		return output, fmt.Errorf("%s failed with error: (%w) %s", command, err, string(output))
	}
	if DebugLevel >= 3 {
		DebugLog(3, "command output: %s", string(output))
	}

	return output, nil
}

// RunWithTimeout executes a command with a timeout
func RunWithTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		DebugLog(1, "chdir dir: %s", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	DebugLog(2, "running with timeout %v: %s", timeout, command)

	done := make(chan error)
	var output []byte
	var cmdErr error

	go func() {
		output, cmdErr = cmd.CombinedOutput()
		done <- cmdErr
	}()

	select {
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil, fmt.Errorf("command timed out after %v: %s", timeout, command)
	case err := <-done:
		if err != nil {
			DebugLog(1, "command failed: %s\nerror: %v\noutput: %s", command, err, string(output))
			return output, fmt.Errorf("%s failed with error: (%w) %s", command, err, string(output))
		}
		return output, nil
	}
}

// UninstallPrometheusOperator uninstalls the prometheus
func UninstallPrometheusOperator() {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// IsCertManagerInstalled checks if cert-manager is already installed
func IsCertManagerInstalled() bool {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "deployment", "cert-manager-webhook",
		"-n", "cert-manager", "-o", "name")
	_, err := Run(cmd)
	return err == nil
}

// InstallCertManager installs the cert manager bundle with retry logic for network issues.
func InstallCertManager() error {
	// Skip if already installed
	if IsCertManagerInstalled() {
		_, _ = fmt.Fprintf(GinkgoWriter, "cert-manager already installed, skipping installation\n")
		// Still wait for it to be ready
		cmd := exec.CommandContext(context.Background(), "kubectl", "wait", "deployment.apps/cert-manager-webhook",
			"--for", "condition=Available",
			"--namespace", "cert-manager",
			"--timeout", "5m",
		)
		_, err := Run(cmd)
		return err
	}

	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)

	// Retry installation up to 3 times with exponential backoff
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, _ = fmt.Fprintf(GinkgoWriter, "Installing cert-manager (attempt %d/3)\n", attempt)
		cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", url, "--server-side", "--force-conflicts")
		if _, err := Run(cmd); err != nil {
			lastErr = err
			if attempt < 3 {
				backoff := time.Duration(attempt*10) * time.Second
				_, _ = fmt.Fprintf(GinkgoWriter, "cert-manager install failed, retrying in %v: %v\n", backoff, err)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		break
	}

	if lastErr != nil {
		return lastErr
	}

	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd := exec.CommandContext(context.Background(), "kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err := Run(cmd)
	return err
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster with the specified name.
func LoadImageToKindClusterWithName(name string) error {
	cluster := "auth-operator-e2e"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.CommandContext(context.Background(), "kind", kindOptions...)
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

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

// DeploymentExists checks if a deployment exists for a label selector in a namespace.
func DeploymentExists(labelSelector, namespace string) bool {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "deployment",
		"-l", labelSelector,
		"-n", namespace,
		"-o", "name")
	output, err := Run(cmd)
	if err != nil {
		return false
	}
	return len(GetNonEmptyLines(string(output))) > 0
}

// ShouldTeardown controls whether tests should tear down operator/CRDs.
func ShouldTeardown() bool {
	return os.Getenv("E2E_TEARDOWN") == "true"
}

// WaitForResource waits for a Kubernetes resource to exist
func WaitForResource(resourceType, name, namespace string, timeout time.Duration) error {
	args := []string{"get", resourceType, name}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(context.Background(), "kubectl", args...)
		if _, err := Run(cmd); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s/%s", resourceType, name)
}

// WaitForPodRunning waits for a pod matching the label selector to be running
func WaitForPodRunning(labelSelector, namespace string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
			"-l", labelSelector,
			"-n", namespace,
			"-o", "jsonpath={.items[0].status.phase}")
		output, err := Run(cmd)
		if err == nil && string(output) == "Running" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for pod with label %s to be running", labelSelector)
}

// WaitForPodsReady waits for all pods matching the label selector to be Ready
func WaitForPodsReady(labelSelector, namespace string, timeout time.Duration) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "wait", "pod",
		"-l", labelSelector,
		"-n", namespace,
		"--for=condition=Ready",
		fmt.Sprintf("--timeout=%s", timeout.String()))
	_, err := Run(cmd)
	return err
}

// WaitForDeploymentAvailable waits for deployments matching label selector to be Available
func WaitForDeploymentAvailable(labelSelector, namespace string, timeout time.Duration) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "wait", "deployment",
		"-l", labelSelector,
		"-n", namespace,
		"--for=condition=Available",
		fmt.Sprintf("--timeout=%s", timeout.String()))
	_, err := Run(cmd)
	return err
}

// WaitForServiceEndpoints waits for a service to have endpoints
func WaitForServiceEndpoints(serviceName, namespace string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "endpoints", serviceName,
			"-n", namespace,
			"-o", "jsonpath={.subsets}")
		output, err := Run(cmd)
		if err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for endpoints for service %s in namespace %s", serviceName, namespace)
}

// WaitForWebhookConfigurations waits for validating and mutating webhook configurations matching label selector
func WaitForWebhookConfigurations(labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		validating := exec.CommandContext(context.Background(), "kubectl", "get", "validatingwebhookconfiguration",
			"-l", labelSelector, "-o", "name")
		mutating := exec.CommandContext(context.Background(), "kubectl", "get", "mutatingwebhookconfiguration",
			"-l", labelSelector, "-o", "name")
		vOut, vErr := Run(validating)
		mOut, mErr := Run(mutating)
		if vErr == nil && mErr == nil && len(GetNonEmptyLines(string(vOut))) > 0 && len(GetNonEmptyLines(string(mOut))) > 0 {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for webhook configurations with label %s", labelSelector)
}

// WaitForWebhookCABundle waits for the caBundle to be populated in webhook configurations.
// This ensures the cert-rotator has injected the CA certificate before attempting TLS validation.
func WaitForWebhookCABundle(labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check if mutating webhook has caBundle populated
		mutatingCmd := exec.CommandContext(context.Background(), "kubectl", "get", "mutatingwebhookconfiguration",
			"-l", labelSelector,
			"-o", "jsonpath={.items[*].webhooks[*].clientConfig.caBundle}")
		mutatingOut, mutatingErr := Run(mutatingCmd)

		// Check if validating webhook has caBundle populated
		validatingCmd := exec.CommandContext(context.Background(), "kubectl", "get", "validatingwebhookconfiguration",
			"-l", labelSelector,
			"-o", "jsonpath={.items[*].webhooks[*].clientConfig.caBundle}")
		validatingOut, validatingErr := Run(validatingCmd)

		if mutatingErr == nil && validatingErr == nil {
			mutatingBundle := strings.TrimSpace(string(mutatingOut))
			validatingBundle := strings.TrimSpace(string(validatingOut))

			// Both must have non-empty caBundle values
			if mutatingBundle != "" && validatingBundle != "" {
				if DebugLevel >= 1 {
					_, _ = fmt.Fprintf(GinkgoWriter, "Webhook CA bundles populated (mutating: %d bytes, validating: %d bytes)\n",
						len(mutatingBundle), len(validatingBundle))
				}
				return nil
			}

			if DebugLevel >= 2 {
				_, _ = fmt.Fprintf(GinkgoWriter, "Waiting for CA bundle injection (mutating: %d bytes, validating: %d bytes)\n",
					len(mutatingBundle), len(validatingBundle))
			}
		}

		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for webhook CA bundle to be injected (label: %s)", labelSelector)
}

// WaitForWebhookReady waits for the webhook to be fully operational by performing a dry-run
// namespace create, which validates that the TLS certificate is properly configured and
// the webhook is responding correctly. This is more reliable than just checking pod readiness.
func WaitForWebhookReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	testNS := "webhook-readiness-check"
	var lastErr error

	for time.Now().Before(deadline) {
		// Perform a dry-run namespace create which will trigger the mutating webhook
		// If the webhook is ready with valid TLS, this will succeed
		cmd := exec.CommandContext(context.Background(), "kubectl", "create", "namespace", testNS,
			"--dry-run=server", "-o", "yaml")
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

// ApplyManifest applies a YAML manifest from a string using server-side apply
func ApplyManifest(manifest string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "--server-side", "--force-conflicts", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := Run(cmd)
	return err
}

// DeleteManifest deletes resources defined in a YAML manifest
func DeleteManifest(manifest string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "-f", "-", "--ignore-not-found=true")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := Run(cmd)
	return err
}

// GetResourceField gets a specific field from a resource using jsonpath
func GetResourceField(resourceType, name, namespace, jsonpath string) (string, error) {
	args := []string{"get", resourceType, name, "-o", fmt.Sprintf("jsonpath=%s", jsonpath)}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	output, err := Run(cmd)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// KindClusterExists checks if a kind cluster with the given name exists
func KindClusterExists(name string) bool {
	cmd := exec.CommandContext(context.Background(), "kind", "get", "clusters")
	output, err := Run(cmd)
	if err != nil {
		return false
	}
	clusters := GetNonEmptyLines(string(output))
	for _, cluster := range clusters {
		if cluster == name {
			return true
		}
	}
	return false
}

// CreateKindCluster creates a new kind cluster
func CreateKindCluster(name, k8sVersion string) error {
	if KindClusterExists(name) {
		_, _ = fmt.Fprintf(GinkgoWriter, "Kind cluster '%s' already exists\n", name)
		return nil
	}

	image := fmt.Sprintf("kindest/node:%s", k8sVersion)
	cmd := exec.CommandContext(context.Background(), "kind", "create", "cluster",
		"--name", name,
		"--image", image,
		"--wait", "5m")
	_, err := Run(cmd)
	return err
}

// DeleteKindCluster deletes a kind cluster
func DeleteKindCluster(name string) error {
	cmd := exec.CommandContext(context.Background(), "kind", "delete", "cluster", "--name", name)
	_, err := Run(cmd)
	return err
}

// CleanupWebhooks removes ValidatingWebhookConfigurations and MutatingWebhookConfigurations
// with the specified label selector. This is important between test runs to avoid conflicts.
func CleanupWebhooks(labelSelector string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "Cleaning up webhooks with label: %s\n", labelSelector)

	// Clean up ValidatingWebhookConfigurations
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "validatingwebhookconfiguration",
		"-l", labelSelector, "--ignore-not-found=true")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}

	// Clean up MutatingWebhookConfigurations
	cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "mutatingwebhookconfiguration",
		"-l", labelSelector, "--ignore-not-found=true")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// CleanupAllAuthOperatorWebhooks removes all auth-operator related webhooks
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
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "validatingwebhookconfiguration", "-o", "name")
		output, _ := Run(cmd)
		for _, line := range GetNonEmptyLines(string(output)) {
			if strings.Contains(line, pattern) {
				name := strings.TrimPrefix(line, "validatingwebhookconfiguration.admissionregistration.k8s.io/")
				cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "validatingwebhookconfiguration", name, "--ignore-not-found=true")
				_, _ = Run(cmd)
			}
		}

		cmd = exec.CommandContext(context.Background(), "kubectl", "get", "mutatingwebhookconfiguration", "-o", "name")
		output, _ = Run(cmd)
		for _, line := range GetNonEmptyLines(string(output)) {
			if strings.Contains(line, pattern) {
				name := strings.TrimPrefix(line, "mutatingwebhookconfiguration.admissionregistration.k8s.io/")
				cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "mutatingwebhookconfiguration", name, "--ignore-not-found=true")
				_, _ = Run(cmd)
			}
		}
	}
}

// RemoveFinalizersForAll removes finalizers from all resources of a given type
func RemoveFinalizersForAll(resourceType string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", resourceType, "-A",
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
		patch := exec.CommandContext(context.Background(), "kubectl", args...)
		if _, err := Run(patch); err != nil {
			warnError(err)
		}
	}
}

// parseNamespacedName parses "namespace/name" or "/name" for cluster-scoped resources
func parseNamespacedName(value string) (string, string) {
	parts := strings.SplitN(value, "/", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	if parts[0] == "" {
		return "", parts[1]
	}
	return parts[0], parts[1]
}

// CleanupResourcesByLabel deletes resources by label selector with optional namespace
func CleanupResourcesByLabel(resourceType, labelSelector, namespace string) {
	args := []string{
		"delete", resourceType, "-l", labelSelector,
		"--ignore-not-found=true", "--wait=false", "--timeout=30s",
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// CleanupNamespace deletes a namespace and waits for it to be fully removed
func CleanupNamespace(namespace string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", namespace, "--ignore-not-found=true", "--wait=false")
	_, _ = Run(cmd)

	// Wait for namespace to be deleted (with timeout)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "ns", namespace)
		if _, err := Run(cmd); err != nil {
			// Namespace is gone
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// CleanupClusterResources cleans up cluster-scoped resources created by tests
func CleanupClusterResources(labelSelector string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "Cleaning up cluster resources with label: %s\n", labelSelector)

	resources := []string{"clusterrole", "clusterrolebinding"}
	for _, resource := range resources {
		args := []string{
			"delete", resource, "-l", labelSelector,
			"--ignore-not-found=true", "--wait=false", "--timeout=30s",
		}
		cmd := exec.CommandContext(context.Background(), "kubectl", args...)
		if _, err := Run(cmd); err != nil {
			warnError(err)
		}
	}
}

// =============================================================================
// Debug and Diagnostic Functions
// =============================================================================

// CollectClusterDebugInfo gathers comprehensive cluster debug information
// and writes it to GinkgoWriter. Call this on test failures.
func CollectClusterDebugInfo(context string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== DEBUG INFO COLLECTION: %s\n", context)
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
	authOpLabel := "app.kubernetes.io/created-by=auth-operator"
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

// CollectNamespaceDebugInfo gathers debug info for a specific namespace
func CollectNamespaceDebugInfo(namespace, context string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n")
	printSeparator()
	_, _ = fmt.Fprintf(GinkgoWriter, "=== NAMESPACE DEBUG: %s (ns: %s)\n", context, namespace)
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

// CollectOperatorLogs collects logs from auth-operator pods in the specified namespace
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

// CollectPodDebugInfo collects detailed debug info for a specific pod
func CollectPodDebugInfo(namespace, podName string) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Pod Debug: %s/%s ===\n", namespace, podName)

	runDebugCommand("kubectl", "get", "pod", podName, "-n", namespace, "-o", "yaml")
	runDebugCommand("kubectl", "describe", "pod", podName, "-n", namespace)
	runDebugCommand("kubectl", "logs", podName, "-n", namespace, "--all-containers=true", "--tail=100")
}

// CollectCRDDebugInfo collects detailed info about auth-operator CRDs and their instances
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

// CollectDockerDebugInfo collects Docker/container runtime debug info
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

// TestSummary holds structured test run summary data for JSON output
type TestSummary struct {
	Timestamp   string                 `json:"timestamp"`
	RunID       string                 `json:"run_id"`
	Suite       string                 `json:"suite"`
	TotalTests  int                    `json:"total_tests"`
	Passed      int                    `json:"passed"`
	Failed      int                    `json:"failed"`
	Skipped     int                    `json:"skipped"`
	Duration    string                 `json:"duration"`
	DebugLevel  int                    `json:"debug_level"`
	OutputDir   string                 `json:"output_dir"`
	ClusterInfo map[string]string      `json:"cluster_info,omitempty"`
	FailedTests []string               `json:"failed_tests,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SaveTestSummaryJSON creates a structured JSON summary of the test run
func SaveTestSummaryJSON(
	suite string,
	passed, failed, skipped int,
	duration time.Duration,
	failedTests []string,
) error {
	summary := TestSummary{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		RunID:       os.Getenv("RUN_ID"),
		Suite:       suite,
		TotalTests:  passed + failed + skipped,
		Passed:      passed,
		Failed:      failed,
		Skipped:     skipped,
		Duration:    duration.String(),
		DebugLevel:  DebugLevel,
		OutputDir:   GetE2EOutputDir(),
		FailedTests: failedTests,
		ClusterInfo: getClusterInfo(),
		Metadata:    getTestMetadata(),
	}

	outputDir := GetE2EOutputDirForContext(suite)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	jsonData, err := jsonMarshalIndent(summary, "  ")
	if err != nil {
		return err
	}

	return SaveDebugInfoToFile(outputDir, "test-summary.json", string(jsonData))
}

// getClusterInfo collects basic cluster information
func getClusterInfo() map[string]string {
	info := make(map[string]string)

	// Kubernetes version
	cmd := exec.CommandContext(context.Background(), "kubectl", "version", "--client", "--short")
	if output, err := Run(cmd); err == nil {
		info["kubectl_version"] = strings.TrimSpace(string(output))
	}

	// Server version
	cmd = exec.CommandContext(context.Background(), "kubectl", "version", "-o", "json")
	if output, err := Run(cmd); err == nil {
		// Extract server version from JSON (simplified)
		if strings.Contains(string(output), "serverVersion") {
			info["server_version_available"] = "true"
		}
	}

	// Current context
	cmd = exec.CommandContext(context.Background(), "kubectl", "config", "current-context")
	if output, err := Run(cmd); err == nil {
		info["context"] = strings.TrimSpace(string(output))
	}

	return info
}

// getTestMetadata collects environment-based test metadata
func getTestMetadata() map[string]interface{} {
	metadata := make(map[string]interface{})

	// CI information
	if os.Getenv("CI") != "" {
		metadata["ci"] = true
		metadata["ci_job_id"] = os.Getenv("CI_JOB_ID")
		metadata["ci_pipeline_id"] = os.Getenv("CI_PIPELINE_ID")
	}

	// Git information
	if commit := os.Getenv("CI_COMMIT_SHA"); commit != "" {
		metadata["git_commit"] = commit
	}
	if branch := os.Getenv("CI_COMMIT_REF_NAME"); branch != "" {
		metadata["git_branch"] = branch
	}

	return metadata
}

// jsonMarshalIndent is a simple JSON marshal with indentation
// Uses manual construction to avoid importing encoding/json
func jsonMarshalIndent(v interface{}, indent string) ([]byte, error) {
	summary, ok := v.(TestSummary)
	if !ok {
		return nil, fmt.Errorf("unsupported type for JSON marshal")
	}

	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString(fmt.Sprintf("%s\"timestamp\": %q,\n", indent, summary.Timestamp))
	sb.WriteString(fmt.Sprintf("%s\"run_id\": %q,\n", indent, summary.RunID))
	sb.WriteString(fmt.Sprintf("%s\"suite\": %q,\n", indent, summary.Suite))
	sb.WriteString(fmt.Sprintf("%s\"total_tests\": %d,\n", indent, summary.TotalTests))
	sb.WriteString(fmt.Sprintf("%s\"passed\": %d,\n", indent, summary.Passed))
	sb.WriteString(fmt.Sprintf("%s\"failed\": %d,\n", indent, summary.Failed))
	sb.WriteString(fmt.Sprintf("%s\"skipped\": %d,\n", indent, summary.Skipped))
	sb.WriteString(fmt.Sprintf("%s\"duration\": %q,\n", indent, summary.Duration))
	sb.WriteString(fmt.Sprintf("%s\"debug_level\": %d,\n", indent, summary.DebugLevel))
	sb.WriteString(fmt.Sprintf("%s\"output_dir\": %q,\n", indent, summary.OutputDir))

	// Cluster info
	sb.WriteString(fmt.Sprintf("%s\"cluster_info\": {\n", indent))
	i := 0
	for k, v := range summary.ClusterInfo {
		if i > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteString(fmt.Sprintf("%s%s%q: %q", indent, indent, k, v))
		i++
	}
	sb.WriteString(fmt.Sprintf("\n%s},\n", indent))

	// Failed tests
	sb.WriteString(fmt.Sprintf("%s\"failed_tests\": [", indent))
	for j, t := range summary.FailedTests {
		if j > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%q", t))
	}
	sb.WriteString("]\n")

	sb.WriteString("}")
	return []byte(sb.String()), nil
}

// SaveDebugInfoToFile saves debug info to a file in the output directory
func SaveDebugInfoToFile(outputDir, filename, content string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	filePath := filepath.Join(outputDir, filename)
	return os.WriteFile(filePath, []byte(content), 0o644)
}

// CollectAndSaveAllDebugInfo collects all debug info and saves to files
// into a per-test output directory. Console output is only produced when
// E2E_DEBUG_LEVEL >= 2 to avoid flooding stdout.
func CollectAndSaveAllDebugInfo(testContext string) {
	// Only output to GinkgoWriter if debug level is high
	if DebugLevel >= 2 {
		CollectClusterDebugInfo(testContext)
	} else {
		DebugLog(1, "Saving debug info to files (set E2E_DEBUG_LEVEL=2 for console output)")
	}

	// Save to files for CI artifacts
	outputDir := GetE2EOutputDirForContext(testContext)
	_ = os.MkdirAll(outputDir, 0o755)

	// Cluster dump
	cmd := exec.CommandContext(context.Background(), "kubectl", "cluster-info", "dump", "--output-directory", filepath.Join(outputDir, "cluster-dump"))
	_, _ = Run(cmd)

	// All resources
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "all", "-A", "-o", "wide")
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "all-resources.txt", string(output))
	}

	// Events
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp")
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "events.txt", string(output))
	}

	// Pods
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-A", "-o", "wide")
	if output, err := Run(cmd); err == nil {
		_ = SaveDebugInfoToFile(outputDir, "pods.txt", string(output))
	}

	// CRD instances
	for _, crd := range []string{"roledefinitions", "binddefinitions", "webhookauthorizers"} {
		cmd = exec.CommandContext(context.Background(), "kubectl", "get", crd, "-A", "-o", "yaml")
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, crd+".yaml", string(output))
		}
	}

	// Operator logs by namespace (if present)
	operatorNamespaces := []string{
		"auth-operator-system",
		"auth-operator-helm",
		"auth-operator-ha",
		"auth-operator-integration-test",
	}
	for _, ns := range operatorNamespaces {
		cmd = exec.CommandContext(context.Background(), "kubectl", "get", "ns", ns, "-o", "name")
		if _, err := Run(cmd); err != nil {
			continue
		}
		cmd = exec.CommandContext(context.Background(), "kubectl", "logs", "-n", ns, "-l", "control-plane=controller-manager", "--tail=1000")
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, fmt.Sprintf("%s-controller-logs.txt", ns), string(output))
		}
		cmd = exec.CommandContext(context.Background(), "kubectl", "logs", "-n", ns, "-l", "app.kubernetes.io/component=webhook", "--tail=1000")
		if output, err := Run(cmd); err == nil {
			_ = SaveDebugInfoToFile(outputDir, fmt.Sprintf("%s-webhook-logs.txt", ns), string(output))
		}
	}

	DebugLog(1, "Debug info saved to %s", outputDir)
}

// separator is used for debug output formatting (80 chars to fit line limits)
const separator = "================================================================================"

// printSeparator prints a separator line to GinkgoWriter
func printSeparator() {
	_, _ = fmt.Fprintf(GinkgoWriter, "%s\n", separator)
}

// printSeparatorWithNewline prints a separator line with trailing newline
func printSeparatorWithNewline() {
	_, _ = fmt.Fprintf(GinkgoWriter, "%s\n\n", separator)
}

// collectSection is a helper to print a section header and run collection functions
func collectSection(title string, fn func()) {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- %s ---\n", title)
	fn()
}

// runDebugCommand runs a command and prints output to GinkgoWriter (ignores errors)
func runDebugCommand(name string, args ...string) {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "$ %s %s\n[error: %v]\n", name, strings.Join(args, " "), err)
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "$ %s %s\n%s\n", name, strings.Join(args, " "), string(output))
	}
}

// OnTestFailure is a helper to be called in AfterEach to collect debug info on failure
func OnTestFailure(namespaces ...string) {
	if CurrentSpecReport().Failed() {
		context := fmt.Sprintf("Test Failed: %s", CurrentSpecReport().FullText())
		CollectClusterDebugInfo(context)

		for _, ns := range namespaces {
			if ns != "" {
				CollectNamespaceDebugInfo(ns, context)
				CollectOperatorLogs(ns, 200)
			}
		}

		CollectCRDDebugInfo()
	}
}
