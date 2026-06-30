//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
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
	authOperatorLabel = "app.kubernetes.io/managed-by=auth-operator"
)

var _ = Describe("Helm Chart E2E", Ordered, Label("helm"), func() {

	BeforeAll(func() {
		setSuiteOutputDir("helm")
		By("Setting up Helm test environment")

		// Create output directory
		err := os.MkdirAll(utils.GetE2EOutputDir(), 0o750)
		Expect(err).NotTo(HaveOccurred())

		// cert-manager is installed in BeforeSuite, no need to install here

		By("Creating Helm test namespace")
		cmd := utils.CommandContext(context.Background(), "kubectl", "create", "ns", helmNamespace, "--dry-run=client", "-o", "yaml") // #nosec G204
		output, _ := utils.Run(cmd)
		cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
		cmd.Stdin = strings.NewReader(string(output))
		_, _ = utils.Run(cmd)

		By("Creating test namespace for CRD testing")
		cmd = utils.CommandContext(context.Background(), "kubectl", "create", "ns", helmTestNamespace, "--dry-run=client", "-o", "yaml") // #nosec G204
		output, _ = utils.Run(cmd)
		cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
		cmd.Stdin = strings.NewReader(string(output))
		_, _ = utils.Run(cmd)

		// Label the test namespace
		cmd = utils.CommandContext(context.Background(), "kubectl", "label", "ns", helmTestNamespace, // #nosec G204
			"t-caas.telekom.com/owner=tenant", "t-caas.telekom.com/tenant=e2e-helm", "--overwrite")
		_, _ = utils.Run(cmd)

		By("Building the operator image")
		cmd = utils.CommandContext(context.Background(), "make", "docker-build", fmt.Sprintf("IMG=%s", projectImage)) // #nosec G204
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
		cmd := utils.CommandContext(context.Background(), "helm", "uninstall", helmReleaseName, "-n", helmNamespace, "--wait", "--timeout", "2m") // #nosec G204
		_, _ = utils.Run(cmd)

		// Use centralized cleanup utility (includes namespace deletion)
		By("Cleaning up test resources and namespaces")
		CleanupForHelmTests(helmNamespace, helmReleaseName, helmTestNamespace)

		// cert-manager cleanup is handled in AfterSuite
	})

	Context("Helm Chart Validation", func() {
		It("should lint the Helm chart successfully", func() {
			By("Running helm lint")
			cmd := utils.CommandContext(context.Background(), "helm", "lint", helmChartPath, "--strict") // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm lint failed: %s", string(output))
		})

		It("should template the chart without errors", func() {
			By("Running helm template")
			templateArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			cmd := utils.CommandContext(context.Background(), "helm", templateArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm template failed")
			rendered := string(output)
			Expect(rendered).To(ContainSubstring("Deployment"))
			Expect(rendered).To(ContainSubstring("ServiceAccount"))
			Expect(rendered).To(ContainSubstring("ClusterRole"))
			Expect(rendered).NotTo(ContainSubstring("# Source: auth-operator/templates/namespace-mutating-webhook-configuration.yaml"))
			Expect(rendered).NotTo(ContainSubstring("# Source: auth-operator/templates/namespace-validating-webhook-configuration.yaml"))

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
				"--set", "metrics.serviceMonitor.tlsConfig.insecureSkipVerify=true",
				"--set", "namespaceAdmission.enabled=true",
			)
			cmd := utils.CommandContext(context.Background(), "helm", templateArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm template with all features failed: %s", string(output))
			rendered := string(output)
			Expect(rendered).To(ContainSubstring("PodDisruptionBudget"))
			Expect(rendered).To(ContainSubstring("ServiceMonitor"))
			Expect(rendered).To(ContainSubstring("# Source: auth-operator/templates/namespace-mutating-webhook-configuration.yaml"))
			Expect(rendered).To(ContainSubstring("# Source: auth-operator/templates/namespace-validating-webhook-configuration.yaml"))
			Expect(rendered).To(ContainSubstring("--cert-rotation-mutating-webhook="))

			// Save templated output
			saveOutput("helm-template-all-features.yaml", output)
		})

		It("should template metrics authentication by default and allow explicit opt-out", func() {
			By("Rendering the default chart")
			defaultArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			cmd := utils.CommandContext(context.Background(), "helm", defaultArgs...) // #nosec G204
			defaultOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "default helm template failed: %s", string(defaultOutput))
			Expect(string(defaultOutput)).To(ContainSubstring("--metrics-secure"))
			Expect(string(defaultOutput)).To(ContainSubstring("system:auth-delegator"))
			Expect(string(defaultOutput)).NotTo(ContainSubstring("auth-operator-e2e-metrics-reader"))

			By("Rendering the chart with metrics authentication disabled")
			optOutArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			optOutArgs = append(optOutArgs,
				"--set", "metrics.auth.enabled=false",
			)
			cmd = utils.CommandContext(context.Background(), "helm", optOutArgs...) // #nosec G204
			optOutOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "metrics auth opt-out helm template failed: %s", string(optOutOutput))
			Expect(string(optOutOutput)).NotTo(ContainSubstring("--metrics-secure"))
			Expect(string(optOutOutput)).NotTo(ContainSubstring("system:auth-delegator"))
			Expect(string(optOutOutput)).NotTo(ContainSubstring("auth-operator-e2e-metrics-reader"))

			By("Rendering the chart with ServiceMonitor enabled")
			authArgs := append([]string{"template", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			authArgs = append(authArgs,
				"--set", "metrics.serviceMonitor.enabled=true",
				"--set", "metrics.serviceMonitor.scraperRBAC.create=true",
				"--set", "metrics.serviceMonitor.scraperRBAC.serviceAccount.name=e2e-metrics-scraper",
				"--set", fmt.Sprintf("metrics.serviceMonitor.scraperRBAC.serviceAccount.namespace=%s", helmNamespace),
			)
			cmd = utils.CommandContext(context.Background(), "helm", authArgs...) // #nosec G204
			authOutput, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "authenticated metrics ServiceMonitor without TLS trust choice should fail")
			Expect(string(authOutput)).To(ContainSubstring("metrics.serviceMonitor.tlsConfig.caFile or metrics.serviceMonitor.tlsConfig.insecureSkipVerify=true is required"))

			By("Rendering the chart with authenticated metrics and explicit self-signed scrape opt-in")
			authArgs = append(authArgs,
				"--set", "metrics.serviceMonitor.tlsConfig.insecureSkipVerify=true",
			)
			cmd = utils.CommandContext(context.Background(), "helm", authArgs...) // #nosec G204
			authOutput, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "authenticated metrics helm template failed: %s", string(authOutput))
			authRendered := string(authOutput)
			Expect(authRendered).To(ContainSubstring("--metrics-secure"))
			Expect(authRendered).To(ContainSubstring("system:auth-delegator"))
			Expect(authRendered).To(ContainSubstring("nonResourceURLs:"))
			Expect(authRendered).To(ContainSubstring("- /metrics"))
			Expect(authRendered).To(ContainSubstring("scheme: https"))
			Expect(authRendered).To(ContainSubstring("bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token"))
			Expect(authRendered).To(ContainSubstring("insecureSkipVerify: true"))
			Expect(authRendered).To(ContainSubstring("name: e2e-metrics-scraper"))
			Expect(authRendered).To(ContainSubstring(fmt.Sprintf("namespace: %s", helmNamespace)))
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
			cmd := utils.CommandContext(context.Background(), "helm", templateArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm template with scheduling constraints failed: %s", string(output))

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
			cmd := utils.CommandContext(context.Background(), "helm", installArgs...) // #nosec G204
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
			for _, crd := range []string{
				"roledefinitions.authorization.t-caas.telekom.com",
				"binddefinitions.authorization.t-caas.telekom.com",
				"webhookauthorizers.authorization.t-caas.telekom.com",
				"rbacpolicies.authorization.t-caas.telekom.com",
				"restrictedroledefinitions.authorization.t-caas.telekom.com",
				"restrictedbinddefinitions.authorization.t-caas.telekom.com",
			} {
				By("Checking CRD exists: " + crd)
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "crd", crd) // #nosec G204
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should have RBAC resources created", func() {
			By("Checking ClusterRole exists")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "clusterrole", // #nosec G204
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(helmReleaseName))

			By("Checking ClusterRoleBinding exists")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", // #nosec G204
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(helmReleaseName))

			By("Checking ServiceAccount exists")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "serviceaccount", "-n", helmNamespace, // #nosec G204
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", helmReleaseName))
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})
	})

	Context("Metrics Authentication", func() {
		It("should require authenticated HTTPS metrics by default and support explicit opt-out", func() {
			By("Verifying deployments include --metrics-secure by default")
			args := helmDeploymentArgs("controller-manager")
			Expect(args).To(ContainSubstring("--metrics-secure"))
			args = helmDeploymentArgs("webhook-server")
			Expect(args).To(ContainSubstring("--metrics-secure"))

			By("Port-forwarding the secure metrics service")
			stopForward := startMetricsPortForward(18080)
			defer func() {
				if stopForward != nil {
					stopForward()
				}
			}()

			By("Rejecting anonymous metrics requests by default")
			Eventually(func() error {
				status, body, err := requestMetrics(context.Background(), "https", 18080, "")
				if err != nil {
					return err
				}
				if status != http.StatusUnauthorized {
					return fmt.Errorf("anonymous metrics returned HTTP %d: %s", status, body)
				}
				return nil
			}, shortTimeout, pollingInterval).Should(Succeed())
			stopForward()
			stopForward = nil

			By("Disabling metrics authentication explicitly")
			upgradeArgs := append([]string{"upgrade", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			upgradeArgs = append(upgradeArgs,
				"--set", "controller.replicas=1",
				"--set", "webhookServer.replicas=1",
				"--set", "metrics.auth.enabled=false",
				"--wait",
				"--timeout", "5m",
			)
			cmd := utils.CommandContext(context.Background(), "helm", upgradeArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm metrics auth opt-out upgrade failed: %s", string(output))

			By("Waiting for metrics auth opt-out rollout")
			Eventually(func() error {
				return utils.WaitForDeploymentAvailable("control-plane=controller-manager", helmNamespace, deployTimeout)
			}, deployTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return utils.WaitForDeploymentAvailable("control-plane=webhook-server", helmNamespace, deployTimeout)
			}, deployTimeout, pollingInterval).Should(Succeed())
			Expect(helmDeploymentArgs("controller-manager")).NotTo(ContainSubstring("--metrics-secure"))
			Expect(helmDeploymentArgs("webhook-server")).NotTo(ContainSubstring("--metrics-secure"))

			By("Reading opt-out HTTP metrics without a bearer token")
			stopForward = startMetricsPortForward(18082)
			defer stopForward()
			Eventually(func() error {
				status, body, err := requestMetrics(context.Background(), "http", 18082, "")
				if err != nil {
					return err
				}
				if status != http.StatusOK {
					return fmt.Errorf("opt-out metrics returned HTTP %d: %s", status, body)
				}
				if !strings.Contains(body, "# HELP") {
					return fmt.Errorf("opt-out metrics response did not contain Prometheus HELP text")
				}
				return nil
			}, shortTimeout, pollingInterval).Should(Succeed())
		})

		It("should allow authenticated scraping when metrics auth is enabled", func() {
			By("Creating the metrics scraper ServiceAccount")
			scraperYAML := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: e2e-metrics-scraper
  namespace: %s
`, helmNamespace)
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(scraperYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Enabling authenticated metrics with chart-managed scraper RBAC")
			upgradeArgs := append([]string{"upgrade", helmReleaseName, helmChartPath,
				"-n", helmNamespace},
				imageSetArgs()...,
			)
			upgradeArgs = append(upgradeArgs,
				"--set", "controller.replicas=1",
				"--set", "webhookServer.replicas=1",
				"--set", "metrics.auth.enabled=true",
				"--set", "metrics.serviceMonitor.scraperRBAC.create=true",
				"--set", "metrics.serviceMonitor.scraperRBAC.serviceAccount.name=e2e-metrics-scraper",
				"--set", fmt.Sprintf("metrics.serviceMonitor.scraperRBAC.serviceAccount.namespace=%s", helmNamespace),
				"--wait",
				"--timeout", "5m",
			)
			cmd = utils.CommandContext(context.Background(), "helm", upgradeArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm metrics auth upgrade failed: %s", string(output))

			By("Waiting for metrics auth rollout")
			Eventually(func() error {
				return utils.WaitForDeploymentAvailable("control-plane=controller-manager", helmNamespace, deployTimeout)
			}, deployTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return utils.WaitForDeploymentAvailable("control-plane=webhook-server", helmNamespace, deployTimeout)
			}, deployTimeout, pollingInterval).Should(Succeed())
			Expect(helmDeploymentArgs("controller-manager")).To(ContainSubstring("--metrics-secure"))
			Expect(helmDeploymentArgs("webhook-server")).To(ContainSubstring("--metrics-secure"))

			By("Verifying scraper ServiceAccount authorization")
			cmd = utils.CommandContext(context.Background(), "kubectl", "auth", "can-i", "get", "/metrics", // #nosec G204
				fmt.Sprintf("--as=system:serviceaccount:%s:e2e-metrics-scraper", helmNamespace))
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).To(Equal("yes"))

			By("Creating a bounded token for the scraper ServiceAccount")
			cmd = utils.CommandContext(context.Background(), "kubectl", "create", "token", "e2e-metrics-scraper", // #nosec G204
				"-n", helmNamespace,
				"--duration=10m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			token := strings.TrimSpace(string(output))
			Expect(token).NotTo(BeEmpty())

			By("Port-forwarding the secure metrics service")
			stopForward := startMetricsPortForward(18081)
			defer stopForward()

			By("Rejecting unauthenticated metrics requests")
			Eventually(func() error {
				status, body, err := requestMetrics(context.Background(), "https", 18081, "")
				if err != nil {
					return err
				}
				if status != http.StatusUnauthorized {
					return fmt.Errorf("unauthenticated metrics returned HTTP %d: %s", status, body)
				}
				return nil
			}, shortTimeout, pollingInterval).Should(Succeed())

			By("Allowing the authorized scraper ServiceAccount to read metrics")
			Eventually(func() error {
				status, body, err := requestMetrics(context.Background(), "https", 18081, token)
				if err != nil {
					return err
				}
				if status != http.StatusOK {
					return fmt.Errorf("authenticated metrics returned HTTP %d: %s", status, body)
				}
				if !strings.Contains(body, "# HELP") {
					return fmt.Errorf("authenticated metrics response did not contain Prometheus HELP text")
				}
				return nil
			}, shortTimeout, pollingInterval).Should(Succeed())
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRoleBinding to be generated")
			// ClusterRoleBinding name format: {targetName}-{clusterRoleRef}-binding
			expectedCRBName := "helm-e2e-binding-helm-e2e-generated-clusterrole-binding"
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", expectedCRBName) // #nosec G204
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
            t-caas.telekom.com/tenant: e2e-helm
`
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleBinding to be generated in labeled namespace")
			// RoleBinding name format: {targetName}-{clusterRoleRef}-binding
			expectedRBName := "helm-e2e-ns-binding-helm-e2e-generated-clusterrole-binding"
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "rolebinding", expectedRBName, // #nosec G204
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ServiceAccount to be auto-created")
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "helm-e2e-auto-sa", helmTestNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying BindDefinition status includes generated ServiceAccount")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", "helm-e2e-sa-binding", // #nosec G204
					"-o", "jsonpath={.status.generatedServiceAccounts}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.Contains(string(output), "helm-e2e-auto-sa")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should create restricted RBAC resources through the Helm-installed controller", func() {
			By("Creating an RBACPolicy for restricted Helm testing")
			restrictedYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: helm-e2e-restricted-policy
spec:
  appliesTo:
    namespaces:
      - %s
  roleLimits:
    allowClusterRoles: false
    forbiddenVerbs:
      - create
      - update
      - patch
      - delete
  bindingLimits:
    allowClusterRoleBindings: false
    roleBindingLimits:
      allowedRoleRefs:
        - helm-e2e-restricted-role
  subjectLimits:
    allowedKinds:
      - Group
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: helm-e2e-restricted-role
spec:
  policyRef:
    name: helm-e2e-restricted-policy
  targetRole: Role
  targetName: helm-e2e-restricted-role
  targetNamespace: %s
  scopeNamespaced: true
  restrictedVerbs:
    - create
    - update
    - patch
    - delete
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: helm-e2e-restricted-binding
spec:
  policyRef:
    name: helm-e2e-restricted-policy
  targetName: helm-e2e-restricted-binding
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: helm-e2e-restricted-group
  roleBindings:
    - namespace: %s
      roleRefs:
        - helm-e2e-restricted-role
`, helmTestNamespace, helmTestNamespace, helmTestNamespace)
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(restrictedYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RBACPolicy readiness")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "helm-e2e-restricted-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Waiting for RestrictedRoleDefinition readiness")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "helm-e2e-restricted-role", "PolicyCompliant") &&
					checkResourceCondition("restrictedroledefinition", "helm-e2e-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Waiting for restricted Role to be generated")
			Eventually(func() error {
				return checkResourceExists("role", "helm-e2e-restricted-role", helmTestNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Waiting for RestrictedBindDefinition readiness")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "helm-e2e-restricted-binding", "PolicyCompliant") &&
					checkResourceCondition("restrictedbinddefinition", "helm-e2e-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Waiting for restricted RoleBinding to be generated")
			Eventually(func() error {
				return checkResourceExists("rolebinding", "helm-e2e-restricted-binding-helm-e2e-restricted-role-binding", helmTestNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
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
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
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
				"--timeout", "7m",
			)
			cmd := utils.CommandContext(context.Background(), "helm", upgradeArgs...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm upgrade failed: %s", string(output))
		})

		It("should have PodDisruptionBudget created", func() {
			By("Checking PodDisruptionBudget exists")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "pdb", "-n", helmNamespace) // #nosec G204
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
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "deployment", // #nosec G204
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

func helmDeploymentArgs(controlPlane string) string {
	cmd := utils.CommandContext(context.Background(), "kubectl", "get", "deployment", // #nosec G204
		"-l", fmt.Sprintf("control-plane=%s", controlPlane),
		"-n", helmNamespace,
		"-o", "jsonpath={.items[0].spec.template.spec.containers[0].args}")
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(output)
}

func startMetricsPortForward(localPort int) func() {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := utils.CommandContext(ctx, "kubectl", "port-forward", // #nosec G204
		"-n", helmNamespace,
		fmt.Sprintf("svc/%s-metrics", helmFullName()),
		fmt.Sprintf("%d:8080", localPort))
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	ExpectWithOffset(1, cmd.Start()).To(Succeed())

	return func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
}

func requestMetrics(ctx context.Context, scheme string, localPort int, token string) (int, string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- e2e local port-forward to self-signed metrics cert.
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://127.0.0.1:%d/metrics", scheme, localPort), nil)
	if err != nil {
		return 0, "", fmt.Errorf("build metrics request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request metrics: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read metrics response: %w", err)
	}
	return resp.StatusCode, string(body), nil
}

func verifyHelmPodRunning(labelSelector, namespace string) error {
	cmd := utils.CommandContext(context.Background(), "kubectl", "get", "pods", // #nosec G204
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
	err := os.WriteFile(fp, content, 0o600)
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
	dumpResourceWithLabel("clusterroles", "", "app.kubernetes.io/managed-by=auth-operator",
		fmt.Sprintf("generated-clusterroles-%s.yaml", timestamp))

	// Dump generated Roles
	dumpResourceWithLabel("roles", "", "app.kubernetes.io/managed-by=auth-operator",
		fmt.Sprintf("generated-roles-%s.yaml", timestamp))

	// Dump generated ClusterRoleBindings
	dumpResourceWithLabel("clusterrolebindings", "", "app.kubernetes.io/managed-by=auth-operator",
		fmt.Sprintf("generated-clusterrolebindings-%s.yaml", timestamp))

	// Dump generated RoleBindings
	dumpResourceWithLabel("rolebindings", "", "app.kubernetes.io/managed-by=auth-operator",
		fmt.Sprintf("generated-rolebindings-%s.yaml", timestamp))

	// Dump generated ServiceAccounts
	dumpResourceWithLabel("serviceaccounts", "", "app.kubernetes.io/managed-by=auth-operator",
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

	cmd := utils.CommandContext(context.Background(), "kubectl", args...) // #nosec G204
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

	cmd := utils.CommandContext(context.Background(), "kubectl", args...) // #nosec G204
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

	cmd := utils.CommandContext(context.Background(), "kubectl", args...) // #nosec G204
	output, _ := utils.Run(cmd)
	saveOutput(filename, output)
}

func createResourceSummary(timestamp string) {
	var summary strings.Builder
	fmt.Fprintf(&summary, "# E2E Test Resource Summary - %s\n\n", timestamp)

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
		cmd := utils.CommandContext(context.Background(), "kubectl", "get", "pods", "-n", helmNamespace, "-o", "wide") // #nosec G204
		output, _ := utils.Run(cmd)
		summary.WriteString("```\n")
		summary.WriteString(string(output))
		summary.WriteString("```\n")
	}

	saveOutput(fmt.Sprintf("summary-%s.md", timestamp), []byte(summary.String()))
	_, _ = fmt.Fprintf(GinkgoWriter, "\n%s\n", summary.String())
}

func countResource(summary *strings.Builder, name, resourceType string) {
	cmd := utils.CommandContext(context.Background(), "kubectl", "get", resourceType, "-o", "name") // #nosec G204
	output, _ := utils.Run(cmd)
	count := len(utils.GetNonEmptyLines(string(output)))
	fmt.Fprintf(summary, "- %s: %d\n", name, count)
}

func countResourceWithLabel(summary *strings.Builder, name, resourceType string) {
	cmd := utils.CommandContext(context.Background(), "kubectl", "get", resourceType, "-l", authOperatorLabel, "-A", "-o", "name") // #nosec G204
	output, _ := utils.Run(cmd)
	count := len(utils.GetNonEmptyLines(string(output)))
	fmt.Fprintf(summary, "- %s: %d\n", name, count)
}
