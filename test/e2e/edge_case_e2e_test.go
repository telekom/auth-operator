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

		cmd := exec.CommandContext(context.Background(), "helm", "upgrade", "--install", edgeCaseRelease, helmChartPath,
			"-n", edgeCaseOperatorNS,
			"--create-namespace",
			"--set", fmt.Sprintf("image.repository=%s", imageRepo),
			"--set", fmt.Sprintf("image.tag=%s", imageTag),
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
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
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
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

		for _, name := range []string{bdSharedA, bdSharedB, bdMissingRef, bdPreExistingSA} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", name, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", healingRDName, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "sa", sharedSAName, "-n", edgeCaseNS, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "sa", preExistingSAName, "-n", edgeCaseNS, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole", healingClusterRole, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		for _, crbSuffix := range []string{
			"e2e-shared-a-view-binding",
			"e2e-shared-b-view-binding",
			fmt.Sprintf("e2e-missing-target-%s-binding", healingClusterRole),
			"e2e-preexisting-target-view-binding",
		} {
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding", crbSuffix, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		// Clean up cluster-scoped RBAC resources created by this operator instance
		cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding",
			"-l", "app.kubernetes.io/created-by=auth-operator", "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		time.Sleep(5 * time.Second)

		By("Uninstalling edge-case Helm release")
		cmd = exec.CommandContext(context.Background(), "helm", "uninstall", edgeCaseRelease, "-n", edgeCaseOperatorNS, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up edge-case namespaces")
		for _, ns := range []string{edgeCaseOperatorNS, edgeCaseNS} {
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found=true")
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
					cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdName,
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
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Shared SA should exist")

			By("Deleting BD-A while BD-B still references the same SA")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdSharedA)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BD-A to be fully deleted")
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdSharedA)
				_, err := utils.Run(cmd)
				if err != nil {
					return nil // NotFound = success
				}
				return fmt.Errorf("BindDefinition %s still exists", bdSharedA)
			}, reconcileTimeout, pollInterval).Should(Succeed())

			By("Verifying shared SA is PRESERVED because BD-B still references it")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Shared SA should be preserved when another BD still references it")

			By("Deleting BD-B - now the SA should be removed")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdSharedB)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying shared SA is now DELETED")
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "sa", sharedSAName, "-n", edgeCaseNS)
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
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdPreExistingSA,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == statusTrue
			}, reconcileTimeout, pollInterval).Should(BeTrue())

			By("Deleting the BindDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", bdPreExistingSA)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the pre-existing SA is preserved (no OwnerRef)")
			// The SA must never be deleted — use Consistently to verify stability over time
			Consistently(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "sa", preExistingSAName, "-n", edgeCaseNS)
				_, err := utils.Run(cmd)
				return err
			}, 10*time.Second, 2*time.Second).Should(Succeed(), "Pre-existing SA must NOT be deleted by finalizer")
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
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
					"-o", "jsonpath={.status.conditions[?(@.type=='RoleRefsValid')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return string(output) == "False"
			}, reconcileTimeout, pollInterval).Should(BeTrue(),
				"RoleRefsValid should be False when referenced ClusterRole does not exist")

			By("Verifying Ready is True despite missing refs (controller still creates bindings)")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
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
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole", healingClusterRole)
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollInterval).Should(Succeed())

			By("Verifying RoleRefsValid self-heals to True after the role is created")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "binddefinition", bdMissingRef,
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
