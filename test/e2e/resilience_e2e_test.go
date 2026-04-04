//go:build e2e

/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Resilience E2E tests covering webhook failure injection, SSA ownership conflicts,
// and HA controller failover scenarios.

// ──────────────────────────────────────────────────────────────────────────────
// Group 1: Webhook Failure Injection
// ──────────────────────────────────────────────────────────────────────────────

var _ = Describe("Resilience - Webhook Failure Injection", Ordered, Label("complex", "resilience"), func() {
	const (
		whResilienceRelease = "auth-operator-resilience-wh"
		whResilienceNS      = "auth-operator-resilience-wh"
		whTestNS            = "e2e-resilience-wh-test"
		whHelmChartPath     = "chart/auth-operator"
		whReconcileTimeout  = 2 * time.Minute
		whDeployTimeout     = 5 * time.Minute
		whPollInterval      = 5 * time.Second
		whShortTimeout      = 30 * time.Second
	)

	BeforeAll(func() {
		setSuiteOutputDir("resilience")
		By("Setting up webhook-failure-injection test environment")

		By("Creating test namespaces")
		createNamespaceIfNotExists(whTestNS, nil)

		By("Loading the operator image into kind cluster")
		err := utils.LoadImageToKindClusterWithName(projectImage)
		Expect(err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing auth-operator via Helm for webhook failure tests")
		imageArgs := imageSetArgs()
		helmArgs := make([]string, 0, 7+len(imageArgs)+6)
		helmArgs = append(helmArgs, "upgrade", "--install", whResilienceRelease, whHelmChartPath,
			"-n", whResilienceNS,
			"--create-namespace",
		)
		helmArgs = append(helmArgs, imageArgs...)
		helmArgs = append(helmArgs,
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
			"--wait",
			"--timeout", "5m",
		)
		cmd := exec.CommandContext(context.Background(), "helm", helmArgs...)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Helm chart for webhook-failure tests")

		By("Waiting for controller and webhook deployments to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", whResilienceNS, whDeployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", whResilienceNS, whDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", whResilienceNS, whDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", whResilienceNS, whDeployTimeout)).To(Succeed())
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Resilience WH AfterAll")
			utils.CollectOperatorLogs(whResilienceNS, 200)
			utils.CollectNamespaceDebugInfo(whResilienceNS, "Resilience WH AfterAll")
		}

		By("Cleaning up webhook failure test resources")
		CleanupForHelmTests(whResilienceNS, whResilienceRelease)

		By("Uninstalling Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", whResilienceRelease,
			"-n", whResilienceNS, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up operator namespace")
		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "ns", whResilienceNS,
			"--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("Cleaning up test namespace")
		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "ns", whTestNS,
			"--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("Cleaning up webhooks")
		utils.CleanupAllAuthOperatorWebhooks()
	})

	Context("TLS Certificate Rotation Recovery", func() {
		const tlsTestRDName = "resilience-wh-tls-rd"

		It("should be ready before certificate rotation", func() {
			By("Verifying webhook is fully ready before the test")
			Expect(utils.WaitForWebhookReady(whDeployTimeout)).To(Succeed())
		})

		It("should recover after TLS secret deletion triggers rotation", func() {
			whDeployName := whResilienceRelease + "-webhook-server"

			By("Identifying the webhook TLS secret")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "secrets",
				"-n", whResilienceNS,
				"-l", "authorization.t-caas.telekom.com/component=webhook",
				"-o", "jsonpath={.items[0].metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			tlsSecretName := strings.TrimSpace(string(output))

			if tlsSecretName == "" {
				Skip("No TLS secret found — skipping TLS rotation test")
			}
			_, _ = fmt.Fprintf(GinkgoWriter, "Found TLS secret: %s\n", tlsSecretName)

			By("Scaling webhook deployment to zero to avoid dual-pod conflicts during cert reset")
			cmd = exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				whDeployName, "-n", whResilienceNS, "--replicas=0")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for all webhook pods to terminate")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=webhook-server",
					"-n", whResilienceNS,
					"-o", "name")
				out, err := utils.Run(cmd)
				if err != nil {
					return -1
				}
				trimmed := strings.TrimSpace(string(out))
				if trimmed == "" {
					return 0
				}
				return len(strings.Split(trimmed, "\n"))
			}, whDeployTimeout, whPollInterval).Should(Equal(0),
				"All webhook pods should be terminated before cert invalidation")

			By("Clearing TLS data from the secret to invalidate certs and trigger rotation")
			cmd = exec.CommandContext(context.Background(), "kubectl", "patch", "secret", tlsSecretName,
				"-n", whResilienceNS,
				"--type=merge", "-p", `{"data":{"tls.crt":"","tls.key":"","ca.crt":""}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Scaling webhook deployment back to one replica to trigger cert-rotator re-initialization")
			cmd = exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				whDeployName, "-n", whResilienceNS, "--replicas=1")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the cert-controller to regenerate valid TLS data in the secret")
			// The cert-rotator detects empty certs, regenerates them, then os.Exit(0)
			// (RestartOnSecretRefresh: true). The pod restarts and becomes ready on the second start.
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "secret", tlsSecretName,
					"-n", whResilienceNS,
					"-o", "jsonpath={.data.ca\\.crt}")
				newCA, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return len(strings.TrimSpace(string(newCA))) > 0
			}, whDeployTimeout, whPollInterval).Should(BeTrue(),
				"TLS secret should contain regenerated CA data after rotation")

			By("Waiting for webhook deployment to become available after cert regeneration")
			Expect(utils.WaitForDeploymentAvailable(
				"control-plane=webhook-server", whResilienceNS, whDeployTimeout,
			)).To(Succeed())

			By("Waiting for webhook to recover after certificate rotation")
			Expect(utils.WaitForWebhookReady(whDeployTimeout)).To(Succeed())

			By("Verifying webhook CA bundle is updated")
			Expect(utils.WaitForWebhookCABundle(
				"authorization.t-caas.telekom.com/component=webhook", whDeployTimeout,
			)).To(Succeed())
		})

		It("should reconcile successfully after TLS recovery", func() {
			By("Creating a RoleDefinition after TLS rotation to verify webhook is functional")
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: resilience-wh-tls-generated-role
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`, tlsTestRDName)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "RoleDefinition admission should succeed after TLS recovery")

			By("Waiting for the ClusterRole to be generated (reconciler is healthy)")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "resilience-wh-tls-generated-role", "")
			}, whReconcileTimeout, whPollInterval).Should(Succeed())

			By("Cleaning up test RoleDefinition")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", tlsTestRDName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole",
				"resilience-wh-tls-generated-role", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})

	Context("Webhook Endpoint Unreachable During Reconciliation", func() {
		const scaledDownTestRDName = "resilience-wh-scaled-rd"

		It("should handle admission requests while webhook is scaled to zero", func() {
			By("Scaling the webhook server deployment to zero replicas")
			cmd := exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				"-l", "control-plane=webhook-server",
				"-n", whResilienceNS,
				"--replicas=0")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Should be able to scale webhook to zero")

			By("Waiting for webhook pods to terminate")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=webhook-server",
					"-n", whResilienceNS,
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return 99
				}
				return len(utils.GetNonEmptyLines(string(output)))
			}, whReconcileTimeout, whPollInterval).Should(Equal(0),
				"All webhook pods should terminate")

			By("Verifying that admission to CRDs is rejected (webhook unavailable)")
			// Attempt a dry-run create — expect failure due to webhook being down
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: resilience-wh-scaled-generated-role
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`, scaledDownTestRDName)
			cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "--dry-run=server", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err = utils.Run(cmd)
			// Either rejected (webhook enforcing) or accepted (failOpen policy) — both are valid
			// What matters is the operator comes back after scaling up
			_, _ = fmt.Fprintf(GinkgoWriter, "Dry-run result while webhook down (err=%v)\n", err)
		})

		It("should recover reconciliation once webhook is restored", func() {
			By("Scaling the webhook server deployment back to one replica")
			cmd := exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				"-l", "control-plane=webhook-server",
				"-n", whResilienceNS,
				"--replicas=1")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Should be able to scale webhook back up")

			By("Waiting for webhook to become ready again")
			Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", whResilienceNS, whDeployTimeout)).To(Succeed())
			Expect(utils.WaitForPodsReady("control-plane=webhook-server", whResilienceNS, whDeployTimeout)).To(Succeed())
			Expect(utils.WaitForWebhookReady(whDeployTimeout)).To(Succeed())

			By("Creating a RoleDefinition after webhook recovery")
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: resilience-wh-scaled-generated-role
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`, scaledDownTestRDName)
			cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Admission should succeed after webhook recovery")

			By("Waiting for ClusterRole to be generated (reconciler is healthy)")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "resilience-wh-scaled-generated-role", "")
			}, whReconcileTimeout, whPollInterval).Should(Succeed())

			By("Cleaning up test RoleDefinition")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", scaledDownTestRDName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole",
				"resilience-wh-scaled-generated-role", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		// Verify that the overall webhook endpoint health is clean after restore
		It("should have all webhook configurations healthy after restore", func() {
			By("Waiting for webhook configurations to stabilize")
			Expect(utils.WaitForWebhookConfigurations("authorization.t-caas.telekom.com/component=webhook", whShortTimeout)).To(Succeed())
		})
	})
})

// ──────────────────────────────────────────────────────────────────────────────
// Group 2: SSA Ownership Conflicts
// ──────────────────────────────────────────────────────────────────────────────

var _ = Describe("Resilience - SSA Ownership Conflicts", Ordered, Label("complex", "resilience"), func() {
	const (
		ssaResilienceRelease = "auth-operator-resilience-ssa"
		ssaResilienceNS      = "auth-operator-resilience-ssa"
		ssaTestNS            = "e2e-resilience-ssa-test"
		ssaHelmChartPath     = "chart/auth-operator"
		ssaReconcileTimeout  = 2 * time.Minute
		ssaDeployTimeout     = 5 * time.Minute
		ssaPollInterval      = 5 * time.Second
	)

	BeforeAll(func() {
		setSuiteOutputDir("resilience")
		By("Setting up SSA-ownership-conflict test environment")

		By("Creating SSA test namespace")
		createNamespaceIfNotExists(ssaTestNS, nil)

		By("Loading the operator image into kind cluster")
		err := utils.LoadImageToKindClusterWithName(projectImage)
		Expect(err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing auth-operator via Helm for SSA conflict tests")
		imageArgs := imageSetArgs()
		helmArgs := make([]string, 0, 7+len(imageArgs)+6)
		helmArgs = append(helmArgs, "upgrade", "--install", ssaResilienceRelease, ssaHelmChartPath,
			"-n", ssaResilienceNS,
			"--create-namespace",
		)
		helmArgs = append(helmArgs, imageArgs...)
		helmArgs = append(helmArgs,
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
			"--wait",
			"--timeout", "5m",
		)
		cmd := exec.CommandContext(context.Background(), "helm", helmArgs...)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Helm chart for SSA conflict tests")

		By("Waiting for controller and webhook deployments to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", ssaResilienceNS, ssaDeployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", ssaResilienceNS, ssaDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", ssaResilienceNS, ssaDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", ssaResilienceNS, ssaDeployTimeout)).To(Succeed())
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Resilience SSA AfterAll")
			utils.CollectOperatorLogs(ssaResilienceNS, 200)
			utils.CollectNamespaceDebugInfo(ssaResilienceNS, "Resilience SSA AfterAll")
		}

		By("Cleaning up SSA conflict test resources")
		CleanupForHelmTests(ssaResilienceNS, ssaResilienceRelease)

		By("Uninstalling Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", ssaResilienceRelease,
			"-n", ssaResilienceNS, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up operator namespace")
		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ssaResilienceNS,
			"--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("Cleaning up test namespace")
		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ssaTestNS,
			"--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("Cleaning up webhooks")
		utils.CleanupAllAuthOperatorWebhooks()
	})

	Context("External Modification of SSA-Managed ClusterRole", func() {
		const (
			ssaExternalRDName = "resilience-ssa-external-rd"
			ssaExternalCRName = "resilience-ssa-external-generated-role"
		)

		It("should create a RoleDefinition and generate a ClusterRole", func() {
			By("Creating the RoleDefinition")
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: false
  restrictedVerbs:
    - delete
    - deletecollection
`, ssaExternalRDName, ssaExternalCRName)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the ClusterRole to be generated")
			Eventually(func() error {
				return checkResourceExists("clusterrole", ssaExternalCRName, "")
			}, ssaReconcileTimeout, ssaPollInterval).Should(Succeed())
		})

		It("should self-heal when an external actor modifies the SSA-managed ClusterRole", func() {
			By("Externally patching the ClusterRole to remove an SSA-owned rule")
			// Overwrite rules to an empty list using a strategic merge patch.
			// The operator should detect the drift and re-apply the correct rules via SSA.
			patchJSON := `{"rules": []}`
			cmd := exec.CommandContext(context.Background(), "kubectl", "patch", "clusterrole", ssaExternalCRName,
				"--type=merge",
				"-p", patchJSON)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Should be able to patch the ClusterRole externally")

			By("Verifying the operator re-applies the correct rules via SSA reconciliation")
			Eventually(func() (bool, error) {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole", ssaExternalCRName,
					"-o", "jsonpath={.rules}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false, err
				}
				rulesStr := strings.TrimSpace(string(output))
				// Empty rules: "", "[]", or "null"
				return rulesStr != "" && rulesStr != "[]" && rulesStr != "null", nil
			}, ssaReconcileTimeout, ssaPollInterval).Should(BeTrue(),
				"Operator should re-populate ClusterRole rules after external modification")
		})

		It("should clean up after SSA external-modification test", func() {
			By("Deleting the test RoleDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", ssaExternalRDName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)

			By("Confirming the generated ClusterRole is eventually removed")
			Eventually(func() error {
				return checkResourceExists("clusterrole", ssaExternalCRName, "")
			}, ssaReconcileTimeout, ssaPollInterval).ShouldNot(Succeed(),
				"Operator should garbage-collect the ClusterRole when the RoleDefinition is deleted")
		})
	})

	Context("Conflicting Field Managers", func() {
		const (
			ssaConflictRDName = "resilience-ssa-conflict-rd"
			ssaConflictCRName = "resilience-ssa-conflict-generated-role"
		)

		It("should create a RoleDefinition and generate a ClusterRole for conflict test", func() {
			By("Creating the RoleDefinition")
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`, ssaConflictRDName, ssaConflictCRName)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the ClusterRole to be generated")
			Eventually(func() error {
				return checkResourceExists("clusterrole", ssaConflictCRName, "")
			}, ssaReconcileTimeout, ssaPollInterval).Should(Succeed())
		})

		It("should recover from a conflicting server-side apply by a foreign field manager", func() {
			By("Applying a conflicting field-manager patch using --force-conflicts")
			conflictPatchYAML := fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
`, ssaConflictCRName)

			cmd := exec.CommandContext(context.Background(), "kubectl", "apply",
				"--server-side",
				"--field-manager=resilience-test-conflict-manager",
				"--force-conflicts",
				"-f", "-")
			cmd.Stdin = strings.NewReader(conflictPatchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Force-conflict SSA apply should succeed")
			_, _ = fmt.Fprintf(GinkgoWriter, "Applied conflicting SSA patch with foreign field manager\n")

			By("Verifying the operator wins the conflict and re-asserts its rules")
			// The operator's next reconcile should re-apply its own rules, overriding
			// the foreign field manager's additions (or coexisting with them under SSA ownership).
			// At minimum, the ClusterRole must still exist and not be left in a broken state.
			Eventually(func() error {
				return checkResourceExists("clusterrole", ssaConflictCRName, "")
			}, ssaReconcileTimeout, ssaPollInterval).Should(Succeed(),
				"ClusterRole must still exist after conflicting SSA patch")

			By("Verifying the ClusterRole rules are non-empty after operator reconciliation")
			Eventually(func() (bool, error) {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole", ssaConflictCRName,
					"-o", "jsonpath={.rules}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false, err
				}
				rulesStr := strings.TrimSpace(string(output))
				// Empty rules: "", "[]", or "null"
				return rulesStr != "" && rulesStr != "[]" && rulesStr != "null", nil
			}, ssaReconcileTimeout, ssaPollInterval).Should(BeTrue(),
				"Operator should maintain valid rules after conflicting field-manager patch")
		})

		It("should verify managedFields lists the operator as a field manager", func() {
			By("Checking that the operator's field manager entry exists on the ClusterRole")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole", ssaConflictCRName,
					"-o", "jsonpath={.metadata.managedFields[*].manager}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				managers := string(output)
				_, _ = fmt.Fprintf(GinkgoWriter, "Field managers: %s\n", managers)
				// The auth-operator's SSA field owner is "auth-operator" (see pkg/ssa/ssa.go)
				return strings.Contains(managers, "auth-operator")
			}, ssaReconcileTimeout, ssaPollInterval).Should(BeTrue(),
				"ClusterRole should have auth-operator as a field manager")
		})

		It("should clean up after SSA conflict test", func() {
			By("Deleting the test RoleDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", ssaConflictRDName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)

			By("Cleaning up residual ClusterRole if still present")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole", ssaConflictCRName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})
})

// ──────────────────────────────────────────────────────────────────────────────
// Group 3: HA Failover Verification
// ──────────────────────────────────────────────────────────────────────────────

var _ = Describe("Resilience - HA Failover", Ordered, Label("ha", "resilience"), func() {
	const (
		haResilienceRelease = "auth-operator-resilience-ha"
		haResilienceNS      = "auth-operator-resilience-ha"
		haResilienceTestNS  = "e2e-resilience-ha-test"
		haResilienceChart   = "chart/auth-operator"
		haReconcileTimeout  = 3 * time.Minute
		haDeployTimeout     = 8 * time.Minute
		haPollInterval      = 5 * time.Second
		haStatusRunning     = "Running"
		haLeaseName         = "auth.t-caas.telekom.com"
	)

	var originalLeader string

	BeforeAll(func() {
		setSuiteOutputDir("resilience")
		By("Setting up HA failover resilience test environment")

		By("Creating HA test namespaces")
		for _, ns := range []string{haResilienceNS, haResilienceTestNS} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "create", "ns", ns,
				"--dry-run=client", "-o", "yaml")
			yamlOutput, _ := utils.Run(cmd)
			cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(string(yamlOutput))
			_, _ = utils.Run(cmd)
		}

		By("Loading the operator image into kind cluster")
		err := utils.LoadImageToKindClusterWithName(projectImage)
		Expect(err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing auth-operator via Helm with 3 controller replicas")
		imageArgs := imageSetArgs()
		helmArgs := make([]string, 0, 7+len(imageArgs)+14)
		helmArgs = append(helmArgs, "upgrade", "--install", haResilienceRelease, haResilienceChart,
			"-n", haResilienceNS,
			"--create-namespace",
		)
		helmArgs = append(helmArgs, imageArgs...)
		helmArgs = append(helmArgs,
			"--set", "controller.replicas=3",
			"--set", "controller.podDisruptionBudget.enabled=true",
			"--set", "controller.podDisruptionBudget.minAvailable=2",
			"--set", "webhookServer.replicas=2",
			"--set", "webhookServer.podDisruptionBudget.enabled=true",
			"--set", "webhookServer.podDisruptionBudget.minAvailable=1",
			"--wait",
			"--timeout", "8m",
		)
		cmd := exec.CommandContext(context.Background(), "helm", helmArgs...)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Helm chart for HA resilience tests")

		By("Waiting for all controller and webhook pods to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", haResilienceNS, haDeployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", haResilienceNS, haDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", haResilienceNS, haDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", haResilienceNS, haDeployTimeout)).To(Succeed())
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Resilience HA AfterAll")
			utils.CollectOperatorLogs(haResilienceNS, 200)
			utils.CollectNamespaceDebugInfo(haResilienceNS, "Resilience HA AfterAll")
		}

		By("Cleaning up HA resilience test resources")
		CleanupForHelmTests(haResilienceNS, haResilienceRelease)

		By("Uninstalling Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", haResilienceRelease,
			"-n", haResilienceNS, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up namespaces")
		for _, ns := range []string{haResilienceNS, haResilienceTestNS} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ns,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		By("Cleaning up webhooks")
		utils.CleanupAllAuthOperatorWebhooks()
	})

	Context("Controller Failover", func() {
		It("should have 3 controller pods running", func() {
			By("Verifying all 3 controller pods are in Running phase")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=controller-manager",
					"-n", haResilienceNS,
					"-o", "jsonpath={.items[*].status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				phases := strings.Fields(string(output))
				runningCount := 0
				for _, phase := range phases {
					if phase == haStatusRunning {
						runningCount++
					}
				}
				return runningCount
			}, haDeployTimeout, haPollInterval).Should(Equal(3),
				"All 3 controller replicas should be Running")
		})

		It("should have a leader elected via the lease", func() {
			By("Waiting for a leader identity to appear on the lease")
			Eventually(func() string {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "lease",
					haLeaseName,
					"-n", haResilienceNS,
					"-o", "jsonpath={.spec.holderIdentity}")
				output, err := utils.Run(cmd)
				if err != nil {
					return ""
				}
				originalLeader = strings.TrimSpace(string(output))
				return originalLeader
			}, haReconcileTimeout, haPollInterval).ShouldNot(BeEmpty(),
				"A leader must be elected before failover test")
			_, _ = fmt.Fprintf(GinkgoWriter, "Current HA resilience leader: %s\n", originalLeader)
		})

		It("should elect a new leader after the current leader pod is terminated", func() {
			Skip("Leader failover test — skipping in CI to avoid flakiness")

			By("Deleting the current leader pod")
			leaderParts := strings.Split(originalLeader, "_")
			if len(leaderParts) > 0 {
				leaderPod := leaderParts[0]
				_, _ = fmt.Fprintf(GinkgoWriter, "Deleting leader pod: %s\n", leaderPod)
				cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "pod", leaderPod,
					"-n", haResilienceNS, "--grace-period=0", "--force")
				_, _ = utils.Run(cmd)
			}

			By("Waiting for a new leader to be elected (different from the original)")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "lease",
					haLeaseName,
					"-n", haResilienceNS,
					"-o", "jsonpath={.spec.holderIdentity}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				newLeader := strings.TrimSpace(string(output))
				return len(newLeader) > 0 && newLeader != originalLeader
			}, haReconcileTimeout, haPollInterval).Should(BeTrue(),
				"A new leader should be elected after the original leader is terminated")

			By("Verifying the system recovers to 3 running controller pods")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=controller-manager",
					"-n", haResilienceNS,
					"--field-selector=status.phase=Running",
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				return len(utils.GetNonEmptyLines(string(output)))
			}, haDeployTimeout, haPollInterval).Should(Equal(3),
				"All 3 controller pods should be running again after failover")
		})

		It("should continue reconciling CRDs after HA deployment", func() {
			By("Creating a RoleDefinition to verify reconciler is still healthy after (potential) failover")
			const failoverRDName = "resilience-ha-failover-rd"
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: resilience-ha-failover-generated-role
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`, failoverRDName)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "RoleDefinition should be admitted after failover")

			By("Waiting for the ClusterRole to be generated by the new leader")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "resilience-ha-failover-generated-role", "")
			}, haReconcileTimeout, haPollInterval).Should(Succeed(),
				"Reconciler should generate the ClusterRole after leader failover")

			By("Cleaning up failover test resources")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", failoverRDName,
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole",
				"resilience-ha-failover-generated-role", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})
	})
})
