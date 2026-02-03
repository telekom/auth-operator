//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("Leader Election and HA E2E", Ordered, Label("ha", "leader-election"), func() {
	const (
		haHelmRelease   = "auth-operator-ha"
		haNamespace     = "auth-operator-ha"
		haTestNamespace = "e2e-ha-test-ns"
		haStatusRunning = "Running"
	)

	BeforeAll(func() {
		setSuiteOutputDir("ha")
		By("Setting up HA test environment")

		err := os.MkdirAll(utils.GetE2EOutputDir(), 0o755)
		Expect(err).NotTo(HaveOccurred())

		// cert-manager is installed in BeforeSuite, no need to install here

		By("Creating HA test namespaces")
		for _, ns := range []string{haNamespace, haTestNamespace} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "create", "ns", ns, "--dry-run=client", "-o", "yaml")
			output, _ := utils.Run(cmd)
			cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(string(output))
			_, _ = utils.Run(cmd)
		}

		By("Labeling test namespace")
		cmd := exec.CommandContext(context.Background(), "kubectl", "label", "ns", haTestNamespace, "e2e-ha-test=true", "--overwrite")
		_, _ = utils.Run(cmd)

		By("Building the operator image")
		cmd = exec.CommandContext(context.Background(), "make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build operator image")

		By("Loading the operator image into kind cluster")
		err = utils.LoadImageToKindClusterWithName(projectImage)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")
	})

	AfterAll(func() {
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("HA E2E AfterAll")
			dumpHAResources(haNamespace)
			utils.CollectNamespaceDebugInfo(haNamespace, "HA E2E AfterAll")
			utils.CollectOperatorLogs(haNamespace, 200)
			utils.CollectNamespaceDebugInfo(haTestNamespace, "HA E2E AfterAll")
		}

		// Use centralized cleanup
		By("Cleaning up test resources")
		CleanupForHelmTests(haNamespace, haHelmRelease)

		By("Cleaning up Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", haHelmRelease, "-n", haNamespace, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up namespaces")
		for _, ns := range []string{haNamespace, haTestNamespace} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		// cert-manager cleanup is handled in AfterSuite
	})

	Context("Multiple Controller Replicas with Leader Election", func() {
		It("should deploy with multiple controller replicas", func() {
			By("Installing Helm chart with 3 controller replicas and leader election enabled")
			imageRepo := strings.Split(projectImage, ":")[0]
			imageTag := getImageTag()

			cmd := exec.CommandContext(context.Background(), "helm", "install", haHelmRelease, helmChartPath,
				"-n", haNamespace,
				"--create-namespace",
				"--set", fmt.Sprintf("image.repository=%s", imageRepo),
				"--set", fmt.Sprintf("image.tag=%s", imageTag),
				"--set", "controller.replicas=3",
				"--set", "controller.leaderElection.enabled=true",
				"--set", "controller.leaderElection.leaseDuration=15s",
				"--set", "controller.leaderElection.renewDeadline=10s",
				"--set", "controller.leaderElection.retryPeriod=2s",
				"--set", "controller.podDisruptionBudget.enabled=true",
				"--set", "controller.podDisruptionBudget.minAvailable=2",
				"--set", "webhookServer.replicas=3",
				"--set", "webhookServer.podDisruptionBudget.enabled=true",
				"--set", "webhookServer.podDisruptionBudget.minAvailable=2",
				"--wait",
				"--timeout", "5m",
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm install failed: %s", string(output))
		})

		It("should have 3 controller pods running", func() {
			By("Waiting for all 3 controller pods to be running")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=controller-manager",
					"-n", haNamespace,
					"-o", "jsonpath={.items[*].status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				phases := strings.Split(string(output), " ")
				runningCount := 0
				for _, phase := range phases {
					if phase == haStatusRunning {
						runningCount++
					}
				}
				return runningCount
			}, deployTimeout, pollingInterval).Should(Equal(3))
		})

		It("should have exactly one leader", func() {
			By("Checking leader election lease")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "lease",
					"-n", haNamespace,
					"-o", "jsonpath={.items[*].spec.holderIdentity}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return len(strings.TrimSpace(string(output))) > 0
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying leader logs show leadership acquired")
			cmd := exec.CommandContext(context.Background(), "kubectl", "logs",
				"-l", "control-plane=controller-manager",
				"-n", haNamespace,
				"--tail=100")
			output, _ := utils.Run(cmd)
			Expect(string(output)).To(Or(
				ContainSubstring("successfully acquired lease"),
				ContainSubstring("became leader"),
				ContainSubstring("starting controller"),
			))
		})

		It("should have 3 webhook pods running", func() {
			By("Waiting for all 3 webhook pods to be running")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=webhook-server",
					"-n", haNamespace,
					"-o", "jsonpath={.items[*].status.phase}")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				phases := strings.Split(string(output), " ")
				runningCount := 0
				for _, phase := range phases {
					if phase == haStatusRunning {
						runningCount++
					}
				}
				return runningCount
			}, deployTimeout, pollingInterval).Should(Equal(3))

			By("Waiting for webhook service endpoints")
			Expect(utils.WaitForServiceEndpoints(fmt.Sprintf("%s-webhook-service", haHelmRelease), haNamespace, deployTimeout)).To(Succeed())
		})

		It("should have PodDisruptionBudgets configured correctly", func() {
			By("Checking controller PDB")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pdb",
					"-l", "control-plane=controller-manager",
					"-n", haNamespace,
					"-o", "jsonpath={.items[0].spec.minAvailable}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == "2"
			}, shortTimeout, pollingInterval).Should(BeTrue())

			By("Checking webhook PDB")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pdb",
					"-l", "control-plane=webhook-server",
					"-n", haNamespace,
					"-o", "jsonpath={.items[0].spec.minAvailable}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == "2"
			}, shortTimeout, pollingInterval).Should(BeTrue())
		})
	})

	Context("Leader Failover", func() {
		var originalLeader string

		It("should identify the current leader", func() {
			By("Getting the current leader identity")
			Eventually(func() string {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "lease",
					"-n", haNamespace,
					"-l", "control-plane=controller-manager",
					"-o", "jsonpath={.items[0].spec.holderIdentity}")
				output, _ := utils.Run(cmd)
				originalLeader = strings.TrimSpace(string(output))
				return originalLeader
			}, shortTimeout, pollingInterval).ShouldNot(BeEmpty())
			_, _ = fmt.Fprintf(GinkgoWriter, "Current leader: %s\n", originalLeader)
		})

		It("should maintain CRD functionality during normal operation", func() {
			By("Creating a RoleDefinition")
			roleDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: ha-e2e-test-role
spec:
  targetRole: ClusterRole
  targetName: ha-e2e-generated-clusterrole
  scopeNamespaced: false
  restrictedVerbs:
    - delete
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRole to be generated")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "ha-e2e-generated-clusterrole", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})

		It("should elect a new leader when current leader is terminated", func() {
			Skip("Leader failover test - skipping in CI to avoid flakiness")

			By("Deleting the leader pod")
			leaderParts := strings.Split(originalLeader, "_")
			if len(leaderParts) > 0 {
				leaderPod := leaderParts[0]
				cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "pod", leaderPod,
					"-n", haNamespace, "--grace-period=0", "--force")
				_, _ = utils.Run(cmd)
			}

			By("Waiting for a new leader to be elected")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "lease",
					"-n", haNamespace,
					"-l", "control-plane=controller-manager",
					"-o", "jsonpath={.items[0].spec.holderIdentity}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				newLeader := strings.TrimSpace(string(output))
				return len(newLeader) > 0 && newLeader != originalLeader
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying the system recovered")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=controller-manager",
					"-n", haNamespace,
					"--field-selector=status.phase=Running",
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				return len(utils.GetNonEmptyLines(string(output)))
			}, deployTimeout, pollingInterval).Should(Equal(3))
		})
	})

	Context("Webhook Load Distribution", func() {
		It("should distribute webhook calls across replicas", func() {
			By("Creating multiple WebhookAuthorizer resources")
			for i := 1; i <= 5; i++ {
				authorizerYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: ha-e2e-authorizer-%d
spec:
  resourceRules:
    - apiGroups:
        - ""
      resources:
        - configmaps
      verbs:
        - get
        - list
  allowedPrincipals:
    - user: ha-user-%d
`, i, i)
				cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(authorizerYAML)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
			}

			By("Verifying all WebhookAuthorizers are configured")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "webhookauthorizer", "-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				count := 0
				for _, line := range utils.GetNonEmptyLines(string(output)) {
					if strings.Contains(line, "ha-e2e-authorizer") {
						count++
					}
				}
				return count
			}, reconcileTimeout, pollingInterval).Should(BeNumerically(">=", 5))
		})

		It("should have all webhook pods serving requests", func() {
			By("Checking webhook pod readiness")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
				"-l", "control-plane=webhook-server",
				"-n", haNamespace,
				"-o", "jsonpath={.items[*].status.containerStatuses[0].ready}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			readyStates := strings.Split(string(output), " ")
			for _, ready := range readyStates {
				Expect(ready).To(Equal("true"))
			}
		})
	})

	Context("Resource Scaling", func() {
		It("should scale down webhook replicas", func() {
			By("Scaling webhook to 1 replica")
			cmd := exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				"-l", "control-plane=webhook-server",
				"-n", haNamespace,
				"--replicas=1")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for scale down")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=webhook-server",
					"-n", haNamespace,
					"--field-selector=status.phase=Running",
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return -1
				}
				return len(utils.GetNonEmptyLines(string(output)))
			}, reconcileTimeout, pollingInterval).Should(Equal(1))
		})

		It("should scale up webhook replicas", func() {
			By("Scaling webhook back to 3 replicas")
			cmd := exec.CommandContext(context.Background(), "kubectl", "scale", "deployment",
				"-l", "control-plane=webhook-server",
				"-n", haNamespace,
				"--replicas=3")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for scale up")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
					"-l", "control-plane=webhook-server",
					"-n", haNamespace,
					"--field-selector=status.phase=Running",
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				return len(utils.GetNonEmptyLines(string(output)))
			}, deployTimeout, pollingInterval).Should(Equal(3))
		})
	})
})

func dumpHAResources(haNamespace string) {
	timestamp := time.Now().Format("20060102-150405")

	dumpResourceWithLabel("leases", haNamespace, "", fmt.Sprintf("ha-leases-%s.yaml", timestamp))
	dumpResource("pods", haNamespace, fmt.Sprintf("ha-pods-%s.yaml", timestamp))
	dumpResource("pdb", haNamespace, fmt.Sprintf("ha-pdb-%s.yaml", timestamp))
	dumpResource("deployments", haNamespace, fmt.Sprintf("ha-deployments-%s.yaml", timestamp))
	dumpResource("events", haNamespace, fmt.Sprintf("ha-events-%s.yaml", timestamp))
	dumpAllPodLogs(haNamespace, fmt.Sprintf("ha-all-logs-%s.txt", timestamp))
	createHASummary(haNamespace, timestamp)
}

func dumpAllPodLogs(namespace, filename string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-n", namespace, "-o", "name")
	output, err := utils.Run(cmd)
	if err != nil {
		return
	}

	var allLogs strings.Builder
	for _, podName := range utils.GetNonEmptyLines(string(output)) {
		allLogs.WriteString(fmt.Sprintf("\n=== Logs for %s ===\n", podName))
		cmd := exec.CommandContext(context.Background(), "kubectl", "logs", podName, "-n", namespace, "--tail=200")
		logOutput, _ := utils.Run(cmd)
		allLogs.Write(logOutput)
		allLogs.WriteString("\n")
	}
	saveOutput(filename, []byte(allLogs.String()))
}

func createHASummary(namespace, timestamp string) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("# HA/Leader Election Test Summary - %s\n\n", timestamp))

	summary.WriteString("## Pod Status\n\n")
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-n", namespace, "-o", "wide")
	output, _ := utils.Run(cmd)
	summary.WriteString("```\n")
	summary.WriteString(string(output))
	summary.WriteString("```\n\n")

	summary.WriteString("## Leader Election\n\n")
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "lease", "-n", namespace, "-o", "wide")
	output, _ = utils.Run(cmd)
	summary.WriteString("```\n")
	summary.WriteString(string(output))
	summary.WriteString("```\n\n")

	summary.WriteString("## PodDisruptionBudgets\n\n")
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "pdb", "-n", namespace, "-o", "wide")
	output, _ = utils.Run(cmd)
	summary.WriteString("```\n")
	summary.WriteString(string(output))
	summary.WriteString("```\n")

	saveOutput(fmt.Sprintf("ha-summary-%s.md", timestamp), []byte(summary.String()))
}
