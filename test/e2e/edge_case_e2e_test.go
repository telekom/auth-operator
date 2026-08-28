//go:build e2e

/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Edge-case E2E tests that verify deletion behaviour with shared resources,
// RoleRefsValid condition self-healing, and pre-existing resource preservation.
var _ = Describe("Edge Case - Deletion and Shared Resources", Ordered, Label("complex", "edge-case"), func() {
	const (
		edgeCaseNS         = "edge-case-ns"
		edgeCaseOperatorNS = "auth-operator-edge-case"
		edgeCaseRelease    = "auth-operator-edge-case"
		helmChartPath      = "chart/auth-operator"
		reconcileTimeout   = 2 * time.Minute
		deployTimeout      = 5 * time.Minute
		pollInterval       = 5 * time.Second
		sharedSAName       = "e2e-shared-sa"
		bdSharedA          = "e2e-edge-shared-sa-a"
		bdSharedB          = "e2e-edge-shared-sa-b"
		bdMissingRef       = "e2e-edge-missing-ref"
		healingRDName      = "e2e-edge-healing-rd"
		healingClusterRole = "e2e-edge-healing-role"
		preExistingSAName  = "e2e-preexisting-sa"
		bdPreExistingSA    = "e2e-edge-preexisting-sa-bd"
		ownershipBD        = "e2e-edge-sa-ownership-transfer"
		ownershipHelmSA    = "e2e-edge-helm-owned-sa"
		ownershipUnknownSA = "e2e-edge-unknown-owned-sa"
	)

	BeforeAll(func() {
		setSuiteOutputDir("edge-case")
		By("Setting up edge-case test environment")

		By("Creating edge-case test namespace")
		createNamespaceIfNotExists(edgeCaseNS, nil)

		By("Loading the operator image into kind cluster")
		err := utils.LoadImageToKindClusterWithName(projectImage)
		Expect(err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing auth-operator via Helm for edge-case tests")
		imageRepo := strings.Split(projectImage, ":")[0]
		imageTag := strings.Split(projectImage, ":")[1]
		if imageTag == "" {
			imageTag = defaultImageTag
		}

		cmd := utils.CommandContext(context.Background(), "helm", "upgrade", "--install", edgeCaseRelease, helmChartPath,
			"-n", edgeCaseOperatorNS,
			"--create-namespace",
			"--set", fmt.Sprintf("image.repository=%s", imageRepo),
			"--set", fmt.Sprintf("image.tag=%s", imageTag),
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
			// This suite reads the takeover counter through the in-cluster metrics
			// Service. Authentication is covered by the dedicated Helm E2E suite.
			"--set", "metrics.auth.enabled=false",
			"--wait",
			"--timeout", "5m",
		)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Helm chart for edge-case tests")

		By("Waiting for controller and webhook deployments to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", edgeCaseOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", edgeCaseOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", edgeCaseOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", edgeCaseOperatorNS, deployTimeout)).To(Succeed())

		By("Waiting for controller to be ready")
		Eventually(func() error {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", edgeCaseOperatorNS,
				"-o", "jsonpath={.items[*].status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if !strings.Contains(string(output), "Running") {
				return fmt.Errorf("controller not running: %s", string(output))
			}
			return nil
		}, deployTimeout, pollInterval).Should(Succeed())
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Edge Case E2E AfterAll")
			utils.CollectNamespaceDebugInfo(edgeCaseOperatorNS, "Edge Case E2E AfterAll")
			utils.CollectOperatorLogs(edgeCaseOperatorNS, 200)
		}

		By("Cleaning up edge-case test resources")

		for _, name := range []string{bdSharedA, bdSharedB, bdMissingRef, bdPreExistingSA, ownershipBD} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", name, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", healingRDName, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "sa", sharedSAName, "-n", edgeCaseNS, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "sa", preExistingSAName, "-n", edgeCaseNS, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
		for _, name := range []string{ownershipHelmSA, ownershipUnknownSA} {
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "sa", name, "-n", edgeCaseNS, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrole", healingClusterRole, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		for _, crbSuffix := range []string{
			"e2e-shared-a-view-binding",
			"e2e-shared-b-view-binding",
			fmt.Sprintf("e2e-missing-target-%s-binding", healingClusterRole),
			"e2e-preexisting-target-view-binding",
		} {
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding", crbSuffix, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		// Clean up cluster-scoped RBAC resources created by this operator instance
		cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding",
			"-l", "app.kubernetes.io/managed-by=auth-operator", "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		Eventually(func() error {
			attemptCtx, attemptCancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := utils.CommandContext(attemptCtx, "kubectl", "get", "clusterrolebinding",
				"-l", "app.kubernetes.io/managed-by=auth-operator", "--ignore-not-found=true", "-o", "name")
			out, err := utils.Run(cmd)
			attemptCancel()
			if err != nil {
				return fmt.Errorf("unable to get managed clusterrolebindings: %w", err)
			}
			if len(strings.TrimSpace(string(out))) > 0 {
				return fmt.Errorf("managed clusterrolebindings still exist: %s", string(out))
			}
			return nil
		}).WithTimeout(30 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		By("Uninstalling edge-case Helm release")
		cmd = utils.CommandContext(context.Background(), "helm", "uninstall", edgeCaseRelease, "-n", edgeCaseOperatorNS, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up edge-case namespaces")
		for _, ns := range []string{edgeCaseOperatorNS, edgeCaseNS} {
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
	})

	Context("Shared ServiceAccount Preservation on Deletion", func() {
		It("should preserve SA when one of two referencing BDs is deleted", func() {
			By("Creating two BindDefinitions that reference the same ServiceAccount")
			bdAYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: e2e-shared-a
  subjects:
    - kind: ServiceAccount
      name: %s
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - view
  automountServiceAccountToken: false
`, bdSharedA, sharedSAName, edgeCaseNS)
			applyYAML(bdAYAML)

			bdBYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: e2e-shared-b
  subjects:
    - kind: ServiceAccount
      name: %s
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - view
  automountServiceAccountToken: false
`, bdSharedB, sharedSAName, edgeCaseNS)
			applyYAML(bdBYAML)

			By("Waiting for both BDs to become Ready")
			for _, bdName := range []string{bdSharedA, bdSharedB} {
				Eventually(func() bool {
					cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdName,
						"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
					output, err := utils.Run(cmd)
					if err != nil {
						return false
					}
					return string(output) == statusTrue
				}, reconcileTimeout, pollInterval).Should(BeTrue(),
					fmt.Sprintf("BindDefinition %s should become Ready", bdName))
			}

			By("Verifying shared SA exists")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Shared SA should exist")

			By("Deleting BD-A while BD-B still references the same SA")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdSharedA)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BD-A to be fully deleted")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdSharedA)
				_, err := utils.Run(cmd)
				if err != nil {
					return nil // NotFound = success
				}
				return fmt.Errorf("BindDefinition %s still exists", bdSharedA)
			}, reconcileTimeout, pollInterval).Should(Succeed())

			By("Verifying shared SA is PRESERVED because BD-B still references it")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Shared SA should be preserved when another BD still references it")

			By("Deleting BD-B - now the SA should be removed")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdSharedB)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying shared SA is now DELETED")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
				_, err := utils.Run(cmd)
				if err != nil {
					return nil // NotFound = success
				}
				return fmt.Errorf("SA %s still exists after all referencing BDs deleted", sharedSAName)
			}, reconcileTimeout, pollInterval).Should(Succeed())
		})
	})

	Context("Pre-existing ServiceAccount Preservation", func() {
		It("should NOT delete a pre-existing SA that it does not own", func() {
			By("Creating a pre-existing SA before the BindDefinition")
			preExistingSAYAML := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
`, preExistingSAName, edgeCaseNS)
			applyYAML(preExistingSAYAML)

			By("Creating a BindDefinition that references the pre-existing SA")
			bdYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: e2e-preexisting-target
  subjects:
    - kind: ServiceAccount
      name: %s
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - view
`, bdPreExistingSA, preExistingSAName, edgeCaseNS)
			applyYAML(bdYAML)

			By("Waiting for BD to become Ready")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdPreExistingSA,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == statusTrue
			}, reconcileTimeout, pollInterval).Should(BeTrue())

			By("Deleting the BindDefinition")
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdPreExistingSA)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the pre-existing SA is preserved (no OwnerRef)")
			// The SA must never be deleted — use Consistently to verify stability over time
			Consistently(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "sa", preExistingSAName, "-n", edgeCaseNS)
				_, err := utils.Run(cmd)
				return err
			}, 10*time.Second, 2*time.Second).Should(Succeed(), "Pre-existing SA must NOT be deleted by finalizer")
		})
	})

	Context("ServiceAccount SSA ownership transfer", func() {
		It("keeps Helm and unknown-controller SAs usable and reports the transfer", func() {
			By("Creating a BindDefinition that generates the ServiceAccounts")
			bdYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: e2e-ownership-transfer
  subjects:
    - kind: ServiceAccount
      name: %s
      namespace: %s
    - kind: ServiceAccount
      name: %s
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - view
`, ownershipBD, ownershipHelmSA, edgeCaseNS, ownershipUnknownSA, edgeCaseNS)
			applyYAML(bdYAML)

			By("Waiting for auth-operator to create both ServiceAccounts and reach Ready")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				return err == nil && strings.TrimSpace(string(output)) == statusTrue
			}, reconcileTimeout, pollInterval).Should(BeTrue(), "ownership-transfer BindDefinition should become Ready")
			for _, name := range []string{ownershipHelmSA, ownershipUnknownSA} {
				Eventually(func() error {
					return checkResourceExists("serviceaccount", name, edgeCaseNS)
				}, reconcileTimeout, pollInterval).Should(Succeed(), "auth-operator should create %s", name)
			}
			By("Verifying the initial generated ServiceAccount status before external takeover")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
					"-o", "jsonpath={.status.generatedServiceAccounts}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				status := string(output)
				return strings.Contains(status, ownershipHelmSA) && strings.Contains(status, ownershipUnknownSA)
			}, reconcileTimeout, pollInterval).Should(BeTrue(), "initial status should report both generated ServiceAccounts")

			By("Transferring the auth-owned label fields to Helm and another controller")
			applyServerSideFieldManager(fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.toolkit.fluxcd.io/name: authn-authz-crs
`, ownershipHelmSA, edgeCaseNS), "helm-controller", true)
			applyServerSideFieldManager(fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: ExternalController
`, ownershipUnknownSA, edgeCaseNS), "unknown-controller", true)

			By("Waiting for the owner watch to report both transfers without stalling")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
					"-o", "jsonpath={.status.externalServiceAccounts}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				status := string(output)
				return strings.Contains(status, ownershipHelmSA) && strings.Contains(status, ownershipUnknownSA)
			}, reconcileTimeout, pollInterval).Should(BeTrue(), "owner watch should report both external ServiceAccounts")

			By("Checking status, condition, and external references for both recipients")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
				"-o", "jsonpath={.status.externalServiceAccounts}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(ownershipHelmSA))
			Expect(string(output)).To(ContainSubstring(ownershipUnknownSA))

			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
				"-o", "jsonpath={.status.conditions[?(@.type=='ServiceAccountOwnershipTransferred')].message}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("helm-controller"))
			Expect(string(output)).To(ContainSubstring("unknown-controller"))

			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD,
				"-o", "jsonpath={.status.conditions[?(@.type=='Stalled')].status}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).NotTo(Equal(statusTrue), "ownership conflict must not mark the BindDefinition Stalled")

			By("Verifying owner references were removed while external managers retain labels")
			for _, name := range []string{ownershipHelmSA, ownershipUnknownSA} {
				expectedManager := map[string]string{ownershipHelmSA: "helm-controller", ownershipUnknownSA: "unknown-controller"}[name]
				expectedManagedBy := map[string]string{ownershipHelmSA: "Helm", ownershipUnknownSA: "ExternalController"}[name]
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", name, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.ownerReferences}")
				output, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(output)).NotTo(ContainSubstring(ownershipBD))
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", name, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.labels.app\\.kubernetes\\.io/managed-by}")
				output, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.TrimSpace(string(output))).To(Equal(expectedManagedBy))
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", name, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.managedFields[*].manager}")
				output, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(output)).To(ContainSubstring(expectedManager))
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", name, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.annotations.authorization\\.t-caas\\.telekom\\.com/external-field-managers}")
				output, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(output)).To(ContainSubstring(expectedManager))
			}

			By("Verifying the generated binding still contains both ServiceAccount subjects")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding",
				"e2e-ownership-transfer-view-binding", "-o", "jsonpath={.subjects[*].name}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(ownershipHelmSA))
			Expect(string(output)).To(ContainSubstring(ownershipUnknownSA))

			By("Letting the external manager update its label after the transfer")
			applyServerSideFieldManager(fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.toolkit.fluxcd.io/name: authn-authz-crs-updated
`, ownershipHelmSA, edgeCaseNS), "helm-controller", false)
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "sa", ownershipHelmSA, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.labels.helm\\.toolkit\\.fluxcd\\.io/name}")
				output, err := utils.Run(cmd)
				return err == nil && strings.TrimSpace(string(output)) == "authn-authz-crs-updated"
			}, reconcileTimeout, pollInterval).Should(BeTrue(), "external manager must retain normal SSA ownership after transfer")

			By("Checking the takeover metric and warning event include the recipients")
			cleanupPortForward := startEdgeMetricsPortForward(edgeCaseOperatorNS, edgeCaseRelease, 18081)
			defer cleanupPortForward()
			Eventually(func() error {
				resp, getErr := http.Get("http://127.0.0.1:18081/metrics") // #nosec G107 -- local test endpoint.
				if getErr != nil {
					return getErr
				}
				defer resp.Body.Close()
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					return readErr
				}
				metric := fmt.Sprintf("auth_operator_serviceaccount_ownership_takeovers_total{binddefinition=\"%s\"}", ownershipBD)
				if !strings.Contains(string(body), metric) {
					return fmt.Errorf("metric %s not present", metric)
				}
				return nil
			}, reconcileTimeout, pollInterval).Should(Succeed())

			// Kubernetes aggregates Events with the same regarding object, reason,
			// and action.  The condition above is the durable record of every
			// transferred ServiceAccount; the Event API may retain only one of
			// those warning notes.  Query by reason and assert the stable event
			// contract for one retained transfer.  Either transfer may be retained.
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "events.events.k8s.io", "-A",
					"--field-selector=reason=ServiceAccountOwnershipTransferred,regarding.name="+ownershipBD,
					"-o", "jsonpath={range .items[*]}{.type}{\"|\"}{.reason}{\"|\"}{.note}{\"\\n\"}{end}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				events := string(output)
				if !strings.Contains(events, "Warning|ServiceAccountOwnershipTransferred|") {
					return false
				}
				helmEvent := strings.Contains(events, ownershipHelmSA) && strings.Contains(events, "helm-controller")
				unknownEvent := strings.Contains(events, ownershipUnknownSA) && strings.Contains(events, "unknown-controller")
				return helmEvent || unknownEvent
			}, reconcileTimeout, pollInterval).Should(BeTrue(), "takeover warning event should report the transferred ServiceAccount and field manager")

			By("Deleting the BindDefinition and proving transferred SAs are not deleted")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", ownershipBD)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", ownershipBD)
				_, err := utils.Run(cmd)
				if err != nil {
					return nil
				}
				return fmt.Errorf("BindDefinition %s still exists", ownershipBD)
			}, reconcileTimeout, pollInterval).Should(Succeed())
			for _, name := range []string{ownershipHelmSA, ownershipUnknownSA} {
				Consistently(func() error {
					return checkResourceExists("serviceaccount", name, edgeCaseNS)
				}, 15*time.Second, pollInterval).Should(Succeed(), "transferred ServiceAccount %s must survive BindDefinition deletion", name)
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "sa", name, "-n", edgeCaseNS,
					"-o", "jsonpath={.metadata.annotations}")
				output, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(output)).NotTo(ContainSubstring("referenced-by"))
				Expect(string(output)).NotTo(ContainSubstring("external-field-managers"))
			}
		})
	})

	Context("RoleRefsValid Condition Self-Healing", func() {
		It("should transition RoleRefsValid from False to True when missing role is created", func() {
			By("Creating a BindDefinition that references a non-existent ClusterRole")
			bdYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: e2e-missing-target
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: e2e-test-user
  clusterRoleBindings:
    clusterRoleRefs:
      - %s
`, bdMissingRef, healingClusterRole)
			applyYAML(bdYAML)

			By("Verifying RoleRefsValid starts as False")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
					"-o", "jsonpath={.status.conditions[?(@.type=='RoleRefsValid')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == statusFalse
			}, reconcileTimeout, pollInterval).Should(BeTrue(),
				"RoleRefsValid should be False when referenced ClusterRole does not exist")

			By("Verifying Ready is True despite missing refs (controller still creates bindings)")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal(statusTrue),
				"BD should be Ready even with missing role refs")

			By("Creating the missing ClusterRole via a RoleDefinition")
			rdYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: %s
spec:
  targetRole: ClusterRole
  targetName: %s
  scopeNamespaced: false
`, healingRDName, healingClusterRole)
			applyYAML(rdYAML)

			By("Waiting for the ClusterRole to be created by RoleDefinition")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "clusterrole", healingClusterRole)
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollInterval).Should(Succeed())

			By("Verifying RoleRefsValid self-heals to True after the role is created")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
					"-o", "jsonpath={.status.conditions[?(@.type=='RoleRefsValid')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == statusTrue
			}, reconcileTimeout, pollInterval).Should(BeTrue(),
				"RoleRefsValid should self-heal to True once the missing ClusterRole is created")
		})
	})
})

func applyServerSideFieldManager(manifest, manager string, force bool) {
	args := []string{"apply", "--server-side", "--field-manager=" + manager}
	if force {
		args = append(args, "--force-conflicts")
	}
	args = append(args, "-f", "-")
	cmd := utils.CommandContext(context.Background(), "kubectl", args...)
	cmd.Stdin = strings.NewReader(manifest)
	output, err := utils.Run(cmd)
	ExpectWithOffset(2, err).NotTo(HaveOccurred(), "Failed to apply SSA manifest: %s\nOutput: %s", manifest, string(output))
}

func startEdgeMetricsPortForward(namespace, service string, localPort int) func() {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := utils.CommandContext(ctx, "kubectl", "port-forward", "-n", namespace,
		fmt.Sprintf("svc/%s-metrics", service), fmt.Sprintf("%d:8080", localPort))
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	ExpectWithOffset(1, cmd.Start()).To(Succeed())
	return func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
}
