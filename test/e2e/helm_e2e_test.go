//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

const (
	helmReleaseName   = "auth-operator-e2e"
	helmChartPath     = "chart/auth-operator"
	helmNamespace     = "auth-operator-helm"
	helmTestNamespace = "e2e-helm-test-ns"

	// Common status strings
	helmStatusRunning = "Running"

	// Common label for auth-operator resources
	authOperatorLabel = "app.kubernetes.io/created-by=auth-operator"
)

var _ = Describe("Helm Chart E2E", Ordered, Label("helm"), func() {

	BeforeAll(func() {
		setSuiteOutputDir("helm")
		By("Setting up Helm test environment")

		// Create output directory
		err := os.MkdirAll(utils.GetE2EOutputDir(), 0o755)
		Expect(err).NotTo(HaveOccurred())

		// cert-manager is installed in BeforeSuite, no need to install here

		By("Creating Helm test namespace")
		cmd := exec.CommandContext(context.Background(), "kubectl", "create", "ns", helmNamespace, "--dry-run=client", "-o", "yaml")
		output, _ := utils.Run(cmd)
		cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(string(output))
		_, _ = utils.Run(cmd)

		By("Creating test namespace for CRD testing")
		cmd = exec.CommandContext(context.Background(), "kubectl", "create", "ns", helmTestNamespace, "--dry-run=client", "-o", "yaml")
		output, _ = utils.Run(cmd)
		cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(string(output))
		_, _ = utils.Run(cmd)

		// Label the test namespace
		cmd = exec.CommandContext(context.Background(), "kubectl", "label", "ns", helmTestNamespace,
			"e2e-helm-test=true", "--overwrite")
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
		By("Collecting logs and resources before cleanup")
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Helm E2E AfterAll")
			dumpAllGeneratedResources()
			utils.CollectNamespaceDebugInfo(helmNamespace, "Helm E2E AfterAll")
			utils.CollectOperatorLogs(helmNamespace, 200)
		}

		By("Cleaning up Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", helmReleaseName, "-n", helmNamespace, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		// Use centralized cleanup utility (includes namespace deletion)
		By("Cleaning up test resources and namespaces")
		CleanupForHelmTests(helmNamespace, helmReleaseName, helmTestNamespace)

		// cert-manager cleanup is handled in AfterSuite
	})

	Context("Helm Chart Validation", func() {
		It("should lint the Helm chart successfully", func() {
			By("Running helm lint")
			cmd := exec.CommandContext(context.Background(), "helm", "lint", helmChartPath, "--strict")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm lint failed: %s", string(output))
		})

		It("should template the chart without errors", func() {
			By("Running helm template")
			templateArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			cmd := exec.CommandContext(context.Background(), "helm", templateArgs...)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm template failed")
			Expect(string(output)).To(ContainSubstring("Deployment"))
			Expect(string(output)).To(ContainSubstring("ServiceAccount"))
			Expect(string(output)).To(ContainSubstring("ClusterRole"))

			// Save templated output
			saveOutput("helm-template-default.yaml", output)
		})

		It("should template with all features enabled", func() {
			By("Running helm template with all features")
			templateArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			templateArgs = append(templateArgs,
				"--set", "controller.replicas=2",
				"--set", "controller.podDisruptionBudget.enabled=true",
				"--set", "webhookServer.replicas=2",
				"--set", "webhookServer.podDisruptionBudget.enabled=true",
				"--set", "metrics.serviceMonitor.enabled=true",
			)
			cmd := exec.CommandContext(context.Background(), "helm", templateArgs...)
			Expect(err).NotTo(HaveOccurred(), "Helm template with all features failed")
			Expect(string(output)).To(ContainSubstring("PodDisruptionBudget"))
			Expect(string(output)).To(ContainSubstring("ServiceMonitor"))

			// Save templated output
			saveOutput("helm-template-all-features.yaml", output)
		})

		It("should template with scheduling constraints", func() {
			By("Running helm template with nodeSelector, tolerations, and affinity")
			templateArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			templateArgs = append(templateArgs,
				"--set", "nodeSelector.kubernetes\\.io/os=linux",
				"--set", "tolerations[0].key=dedicated",
				"--set", "tolerations[0].operator=Equal",
				"--set", "tolerations[0].value=control-plane",
				"--set", "tolerations[0].effect=NoSchedule",
				"--set", "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=node-role.kubernetes.io/control-plane",
				"--set", "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=Exists",
				"--set", "priorityClassName=system-cluster-critical",
				"--set", "global.logLevel=4",
				"--set", "image.pullPolicy=Always",
				"--set-string", "podAnnotations.prometheus\\.io/scrape=true",
				"--set-string", "podLabels.environment=test",
			)
			cmd := exec.CommandContext(context.Background(), "helm", templateArgs...)
			Expect(err).NotTo(HaveOccurred(), "Helm template with scheduling constraints failed")

			outputStr := string(output)
			// Verify nodeSelector
			Expect(outputStr).To(ContainSubstring("nodeSelector:"))
			Expect(outputStr).To(ContainSubstring("kubernetes.io/os: linux"))

			// Verify tolerations
			Expect(outputStr).To(ContainSubstring("tolerations:"))
			Expect(outputStr).To(ContainSubstring("dedicated"))

			// Verify affinity
			Expect(outputStr).To(ContainSubstring("affinity:"))
			Expect(outputStr).To(ContainSubstring("nodeAffinity:"))

			// Verify priorityClassName
			Expect(outputStr).To(ContainSubstring("priorityClassName: system-cluster-critical"))

			// Verify global log level
			Expect(outputStr).To(ContainSubstring("--verbosity=4"))

			// Verify imagePullPolicy
			Expect(outputStr).To(ContainSubstring("imagePullPolicy: Always"))

			// Verify pod annotations
			Expect(outputStr).To(ContainSubstring("prometheus.io/scrape"))

			// Verify pod labels
			Expect(outputStr).To(ContainSubstring("environment: test"))

			// Save templated output
			saveOutput("helm-template-scheduling.yaml", output)
		})
	})

	Context("Helm Chart Installation", func() {
		It("should install the Helm chart successfully", func() {
			By("Installing the Helm chart")
			installArgs := append([]string{"install", helmReleaseName, helmChartPath,
				"-n", helmNamespace,
				"--create-namespace"},
				imageSetArgs()...,
			)
			installArgs = append(installArgs,
				"--set", "controller.replicas=1",
				"--set", "webhookServer.replicas=1",
				"--wait",
				"--timeout", "5m",
			)
			cmd := exec.CommandContext(context.Background(), "helm", installArgs...)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm install failed: %s", string(output))
		})

		It("should have all pods running", func() {
			By("Waiting for controller-manager pod to be running")
			Eventually(func() error {
				return verifyHelmPodRunning("control-plane=controller-manager", helmNamespace)
			}, deployTimeout, pollingInterval).Should(Succeed())

			By("Waiting for webhook-server pod to be running")
			Eventually(func() error {
				return verifyHelmPodRunning("control-plane=webhook-server", helmNamespace)
			}, deployTimeout, pollingInterval).Should(Succeed())

			By("Waiting for webhook service endpoints")
			Expect(utils.WaitForServiceEndpoints(fmt.Sprintf("%s-webhook-service", helmFullName()), helmNamespace, deployTimeout)).To(Succeed())
		})

		It("should have CRDs installed", func() {
			By("Checking RoleDefinition CRD exists")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "crd", "roledefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Checking BindDefinition CRD exists")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "crd", "binddefinitions.authorization.t-caas.telekom.com")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Checking WebhookAuthorizer CRD exists")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "crd", "webhookauthorizers.authorization.t-caas.telekom.com")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have RBAC resources created", func() {
			By("Checking ClusterRole exists")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole",
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(helmReleaseName))

			By("Checking ClusterRoleBinding exists")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding",
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(helmReleaseName))

			By("Checking ServiceAccount exists")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "serviceaccount", "-n", helmNamespace,
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})
	})

	Context("CRD Functionality via Helm Install", func() {
		It("should create RoleDefinition and generate ClusterRole", func() {
			By("Creating a RoleDefinition")
			roleDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: helm-e2e-cluster-reader
spec:
  targetRole: ClusterRole
  targetName: helm-e2e-generated-clusterrole
  scopeNamespaced: false
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRole to be generated")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "helm-e2e-generated-clusterrole", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RoleDefinition status")
			Eventually(func() bool {
				return checkRoleDefinitionReconciled("helm-e2e-cluster-reader")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should create RoleDefinition and generate namespaced Role", func() {
			By("Creating a RoleDefinition for namespaced Role")
			roleDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: helm-e2e-namespaced-reader
spec:
  targetRole: Role
  targetName: helm-e2e-generated-role
  targetNamespace: %s
  scopeNamespaced: true
  restrictedVerbs:
    - create
    - delete
`, helmTestNamespace)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(roleDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Role to be generated")
			Eventually(func() error {
				return checkResourceExists("role", "helm-e2e-generated-role", helmTestNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})

		It("should create BindDefinition and generate ClusterRoleBinding", func() {
			By("Creating a BindDefinition for ClusterRoleBinding")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: helm-e2e-cluster-binding
spec:
  targetName: helm-e2e-binding
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: helm-e2e-user@example.com
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: helm-e2e-group
  clusterRoleBindings:
    clusterRoleRefs:
      - helm-e2e-generated-clusterrole
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRoleBinding to be generated")
			// ClusterRoleBinding name format: {targetName}-{clusterRoleRef}-binding
			expectedCRBName := "helm-e2e-binding-helm-e2e-generated-clusterrole-binding"
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", expectedCRBName)
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying BindDefinition status")
			Eventually(func() bool {
				return checkBindDefinitionReconciled("helm-e2e-cluster-binding")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should create BindDefinition with namespace selector", func() {
			By("Creating a BindDefinition with namespace selector")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: helm-e2e-ns-binding
spec:
  targetName: helm-e2e-ns-binding
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: helm-ns-user@example.com
  roleBindings:
    - clusterRoleRefs:
        - helm-e2e-generated-clusterrole
      namespaceSelector:
        - matchLabels:
            e2e-helm-test: "true"
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleBinding to be generated in labeled namespace")
			// RoleBinding name format: {targetName}-{clusterRoleRef}-binding
			expectedRBName := "helm-e2e-ns-binding-helm-e2e-generated-clusterrole-binding"
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rolebinding", expectedRBName,
					"-n", helmTestNamespace)
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})

		It("should create BindDefinition with ServiceAccount auto-creation", func() {
			By("Creating a BindDefinition with ServiceAccount subject")
			bindDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: helm-e2e-sa-binding
spec:
  targetName: helm-e2e-sa-binding
  subjects:
    - kind: ServiceAccount
      name: helm-e2e-auto-sa
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - helm-e2e-generated-clusterrole
`, helmTestNamespace)
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ServiceAccount to be auto-created")
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "helm-e2e-auto-sa", helmTestNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying BindDefinition status includes generated ServiceAccount")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", "helm-e2e-sa-binding",
					"-o", "jsonpath={.status.generatedServiceAccounts}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.Contains(string(output), "helm-e2e-auto-sa")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should create WebhookAuthorizer with allowed principals", func() {
			By("Creating a WebhookAuthorizer")
			authorizerYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: helm-e2e-authorizer
spec:
  resourceRules:
    - apiGroups:
        - ""
      resources:
        - pods
        - configmaps
      verbs:
        - get
        - list
  allowedPrincipals:
    - user: helm-allowed-user
    - groups:
        - helm-allowed-group
  namespaceSelector:
    matchLabels:
      e2e-helm-test: "true"
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(authorizerYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				return checkResourceExists("webhookauthorizer", "helm-e2e-authorizer", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			// Note: .status.authorizerConfigured is not implemented in the controller
		})

		It("should create WebhookAuthorizer with denied principals", func() {
			By("Creating a WebhookAuthorizer with denied principals")
			authorizerYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: helm-e2e-authorizer-deny
spec:
  resourceRules:
    - apiGroups:
        - ""
      resources:
        - secrets
      verbs:
        - "*"
  deniedPrincipals:
    - user: helm-denied-user
    - groups:
        - helm-denied-group
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(authorizerYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				return checkResourceExists("webhookauthorizer", "helm-e2e-authorizer-deny", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			// Note: .status.authorizerConfigured is not implemented in the controller
		})

		It("should create WebhookAuthorizer with non-resource rules", func() {
			By("Creating a WebhookAuthorizer with non-resource rules")
			authorizerYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: helm-e2e-authorizer-nonresource
spec:
  nonResourceRules:
    - verbs:
        - get
      nonResourceURLs:
        - /healthz
        - /livez
        - /readyz
        - /metrics
  allowedPrincipals:
    - user: helm-health-user
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(authorizerYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				return checkResourceExists("webhookauthorizer", "helm-e2e-authorizer-nonresource", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			// Note: .status.authorizerConfigured is not implemented in the controller
		})
	})

	Context("Helm Upgrade", func() {
		It("should upgrade the Helm chart with PDB enabled", func() {
			By("Upgrading the Helm chart with PDB enabled")

			upgradeArgs := append([]string{"upgrade", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			upgradeArgs = append(upgradeArgs,
				"--set", "controller.replicas=2",
				"--set", "controller.podDisruptionBudget.enabled=true",
				"--set", "controller.podDisruptionBudget.minAvailable=1",
				"--set", "webhookServer.replicas=2",
				"--set", "webhookServer.podDisruptionBudget.enabled=true",
				"--set", "webhookServer.podDisruptionBudget.minAvailable=1",
				"--wait",
				"--timeout", "5m",
			)
			cmd := exec.CommandContext(context.Background(), "helm", upgradeArgs...)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm upgrade failed: %s", string(output))
		})

		It("should have PodDisruptionBudget created", func() {
			By("Checking PodDisruptionBudget exists")
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pdb", "-n", helmNamespace)
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if !strings.Contains(string(output), helmReleaseName) {
					return fmt.Errorf("PDB not found for release %s", helmReleaseName)
				}
				return nil
			}, shortTimeout, pollingInterval).Should(Succeed())
		})

		It("should have scaled replicas", func() {
			By("Checking controller has 2 replicas")
			Eventually(func() int {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "deployment",
					"-l", "control-plane=controller-manager",
					"-n", helmNamespace,
					"-o", "jsonpath={.items[0].spec.replicas}")
				output, err := utils.Run(cmd)
				if err != nil {
					return 0
				}
				var replicas int
				_, _ = fmt.Sscanf(string(output), "%d", &replicas)
				return replicas
			}, shortTimeout, pollingInterval).Should(Equal(2))
		})
	})

	Context("Resource Dump", func() {
		It("should dump all generated resources", func() {
			By("Dumping all generated resources")
			dumpAllGeneratedResources()
		})
	})
})

// Helper functions

// getImageRepo extracts the repository from projectImage, correctly handling
// registry:port/name:tag and name@sha256:digest formats.
func getImageRepo() string {
	// Handle digest references (name@sha256:...)
	if idx := strings.Index(projectImage, "@"); idx != -1 {
		return projectImage[:idx]
	}
	// Handle tag references - find last colon after last slash
	lastSlash := strings.LastIndex(projectImage, "/")
	lastColon := strings.LastIndex(projectImage, ":")
	if lastColon > lastSlash {
		return projectImage[:lastColon]
	}
	return projectImage
}

func getImageTag() string {
	// Digest references have no tag
	if strings.Contains(projectImage, "@") {
		return ""
	}
	lastSlash := strings.LastIndex(projectImage, "/")
	lastColon := strings.LastIndex(projectImage, ":")
	if lastColon > lastSlash {
		return projectImage[lastColon+1:]
	}
	return defaultImageTag
}

// getImageDigest extracts the digest from projectImage (e.g., sha256:abc...).
// Returns empty string for tag-based references.
func getImageDigest() string {
	if idx := strings.Index(projectImage, "@"); idx != -1 {
		return projectImage[idx+1:]
	}
	return ""
}

// imageSetArgs returns the appropriate --set arguments for image configuration,
// handling both tag and digest references correctly.
func imageSetArgs() []string {
	args := []string{"--set", fmt.Sprintf("image.repository=%s", getImageRepo())}
	if digest := getImageDigest(); digest != "" {
		args = append(args, "--set", fmt.Sprintf("image.digest=%s", digest))
	} else {
		args = append(args, "--set", fmt.Sprintf("image.tag=%s", getImageTag()))
	}
	return args
}

func helmFullName() string {
	if strings.Contains(helmReleaseName, "auth-operator") {
		return helmReleaseName
	}
	return fmt.Sprintf("%s-auth-operator", helmReleaseName)
}

func verifyHelmPodRunning(labelSelector, namespace string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
		"-l", labelSelector,
		"-n", namespace,
		"-o", "jsonpath={.items[0].status.phase}")
	output, err := utils.Run(cmd)
	if err != nil {
		return err
	}
	if string(output) != helmStatusRunning {
		return fmt.Errorf("pod not running, status: %s", string(output))
	}
	return nil
}

func saveOutput(filename string, content []byte) {
	fp := filepath.Join(utils.GetE2EOutputDir(), filename)
	err := os.WriteFile(fp, content, 0o644)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Failed to save output to %s: %v\n", fp, err)
	} else {
		_, _ = fmt.Fprintf(GinkgoWriter, "Saved output to %s\n", fp)
	}
}

func dumpAllGeneratedResources() {
	timestamp := time.Now().Format("20060102-150405")

	// Dump CRD instances
	dumpResource("roledefinitions", "", fmt.Sprintf("roledefinitions-%s.yaml", timestamp))
	dumpResource("binddefinitions", "", fmt.Sprintf("binddefinitions-%s.yaml", timestamp))
	dumpResource("webhookauthorizers", "", fmt.Sprintf("webhookauthorizers-%s.yaml", timestamp))

	// Dump generated ClusterRoles (with auth-operator label)
	dumpResourceWithLabel("clusterroles", "", "app.kubernetes.io/created-by=auth-operator",
		fmt.Sprintf("generated-clusterroles-%s.yaml", timestamp))

	// Dump generated Roles
	dumpResourceWithLabel("roles", "", "app.kubernetes.io/created-by=auth-operator",
		fmt.Sprintf("generated-roles-%s.yaml", timestamp))

	// Dump generated ClusterRoleBindings
	dumpResourceWithLabel("clusterrolebindings", "", "app.kubernetes.io/created-by=auth-operator",
		fmt.Sprintf("generated-clusterrolebindings-%s.yaml", timestamp))

	// Dump generated RoleBindings
	dumpResourceWithLabel("rolebindings", "", "app.kubernetes.io/created-by=auth-operator",
		fmt.Sprintf("generated-rolebindings-%s.yaml", timestamp))

	// Dump generated ServiceAccounts
	dumpResourceWithLabel("serviceaccounts", "", "app.kubernetes.io/created-by=auth-operator",
		fmt.Sprintf("generated-serviceaccounts-%s.yaml", timestamp))

	// Dump operator resources from Helm namespace
	if helmNamespace != "" {
		dumpResource("all", helmNamespace, fmt.Sprintf("helm-namespace-resources-%s.yaml", timestamp))
		dumpResource("pdb", helmNamespace, fmt.Sprintf("helm-pdb-%s.yaml", timestamp))
	}

	// Dump operator logs
	dumpLogs("control-plane=controller-manager", helmNamespace, fmt.Sprintf("controller-logs-%s.txt", timestamp))
	dumpLogs("control-plane=webhook-server", helmNamespace, fmt.Sprintf("webhook-logs-%s.txt", timestamp))

	// Create summary
	createResourceSummary(timestamp)
}

func dumpResource(resourceType, namespace, filename string) {
	args := []string{"get", resourceType, "-o", "yaml"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Failed to dump %s: %v\n", resourceType, err)
		return
	}
	saveOutput(filename, output)
}

func dumpResourceWithLabel(resourceType, namespace, labelSelector, filename string) {
	args := []string{"get", resourceType, "-l", labelSelector, "-o", "yaml"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Failed to dump %s with label %s: %v\n", resourceType, labelSelector, err)
		return
	}
	saveOutput(filename, output)
}

func dumpLogs(labelSelector, namespace, filename string) {
	args := []string{"logs", "-l", labelSelector, "--tail=500"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}

	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	output, _ := utils.Run(cmd)
	saveOutput(filename, output)
}

func createResourceSummary(timestamp string) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("# E2E Test Resource Summary - %s\n\n", timestamp))

	// Count CRDs
	summary.WriteString("## Custom Resources\n\n")
	countResource(&summary, "RoleDefinitions", "roledefinitions")
	countResource(&summary, "BindDefinitions", "binddefinitions")
	countResource(&summary, "WebhookAuthorizers", "webhookauthorizers")

	// Count generated resources
	summary.WriteString("\n## Generated RBAC Resources\n\n")
	countResourceWithLabel(&summary, "ClusterRoles", "clusterroles")
	countResourceWithLabel(&summary, "Roles", "roles")
	countResourceWithLabel(&summary, "ClusterRoleBindings", "clusterrolebindings")
	countResourceWithLabel(&summary, "RoleBindings", "rolebindings")
	countResourceWithLabel(&summary, "ServiceAccounts", "serviceaccounts")

	// Operator status
	summary.WriteString("\n## Operator Status\n\n")
	if helmNamespace != "" {
		cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-n", helmNamespace, "-o", "wide")
		output, _ := utils.Run(cmd)
		summary.WriteString("```\n")
		summary.WriteString(string(output))
		summary.WriteString("```\n")
	}

	saveOutput(fmt.Sprintf("summary-%s.md", timestamp), []byte(summary.String()))
	_, _ = fmt.Fprintf(GinkgoWriter, "\n%s\n", summary.String())
}

func countResource(summary *strings.Builder, name, resourceType string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", resourceType, "-o", "name")
	output, _ := utils.Run(cmd)
	count := len(utils.GetNonEmptyLines(string(output)))
	fmt.Fprintf(summary, "- %s: %d\n", name, count)
}

func countResourceWithLabel(summary *strings.Builder, name, resourceType string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", resourceType, "-l", authOperatorLabel, "-A", "-o", "name")
	output, _ := utils.Run(cmd)
	count := len(utils.GetNonEmptyLines(string(output)))
	fmt.Fprintf(summary, "- %s: %d\n", name, count)
}
