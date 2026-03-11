// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

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

var _ = Describe("Restricted CRD E2E", Label("basic", "restricted"), func() {

	BeforeEach(func() {
		By("Waiting for controller-manager and webhook pods to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", operatorNamespace, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", operatorNamespace, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", operatorNamespace, deployTimeout)).To(Succeed())

		By("Waiting for webhook configurations and service endpoints")
		Expect(utils.WaitForWebhookConfigurations("authorization.t-caas.telekom.com/component=webhook", deployTimeout)).To(Succeed())
		Expect(utils.WaitForServiceEndpoints(webhookService, operatorNamespace, deployTimeout)).To(Succeed())

		By("Waiting for webhook CA bundle and TLS certificate")
		Expect(utils.WaitForWebhookCABundle("authorization.t-caas.telekom.com/component=webhook", deployTimeout)).To(Succeed())
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		By("Ensuring test namespace exists")
		ensureTestNamespace()
	})

	AfterEach(func() {
		By("Resetting restricted CRD e2e test state")
		cleanupRestrictedCRDTestState()
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info")
			utils.CollectAndSaveAllDebugInfo("Restricted CRD E2E AfterAll")
			utils.CollectNamespaceDebugInfo(operatorNamespace, "Restricted CRD E2E AfterAll")
			utils.CollectOperatorLogs(operatorNamespace, 200)
		}

		By("Cleaning up restricted CRD test resources")
		cleanupRestrictedCRDTestState()
	})

	Context("RBACPolicy CRD", func() {
		It("should create and reconcile an RBACPolicy", func() {
			By("Applying RBACPolicy")
			applyFixture("rbacpolicy.yaml")

			By("Verifying RBACPolicy was created")
			Eventually(func() error {
				return checkResourceExists("rbacpolicy", "e2e-test-policy", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RBACPolicy status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RBACPolicy spec is correct")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy",
				"-o", "jsonpath={.spec.appliesTo.namespaceSelector.matchLabels}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("e2e-test"))
		})

		It("should show bound resource count", func() {
			By("Applying RBACPolicy")
			applyFixture("rbacpolicy.yaml")

			By("Waiting for RBACPolicy to be ready")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying initial bound resource count is 0")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy",
				"-o", "jsonpath={.status.boundResourceCount}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("0"))
		})
	})

	Context("RestrictedBindDefinition CRD", func() {
		It("should create RoleBinding within policy limits", func() {
			By("Applying RBACPolicy first")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Ensuring prerequisite ClusterRole exists")
			applyFixture("roledefinition_clusterrole.yaml")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "e2e-cluster-reader", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Applying RestrictedBindDefinition")
			applyFixture("restrictedbinddefinition.yaml")

			By("Verifying RestrictedBindDefinition was created")
			Eventually(func() error {
				return checkResourceExists("restrictedbinddefinition", "e2e-test-restricted-binding", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RestrictedBindDefinition is policy compliant")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "PolicyCompliant")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RestrictedBindDefinition status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RoleBinding was created in test namespace")
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rolebinding",
					"-l", "app.kubernetes.io/managed-by=auth-operator",
					"-n", testNamespace,
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if len(string(output)) == 0 {
					return fmt.Errorf("no RoleBindings found in namespace %s", testNamespace)
				}
				return nil
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RBACPolicy bound count increased")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy",
					"-o", "jsonpath={.status.boundResourceCount}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) != "0"
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should reject bindings that violate policy", func() {
			By("Applying restrictive RBACPolicy")
			applyFixture("rbacpolicy_restrictive.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-restrictive-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedBindDefinition that violates the policy (CRB not allowed)")
			violatingYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: e2e-violating-binding
spec:
  policyRef:
    name: e2e-test-restrictive-policy
  targetName: e2e-violating-binding
  subjects:
    - kind: ServiceAccount
      name: e2e-test-sa
      namespace: e2e-test-ns
      apiGroup: ""
  clusterRoleBindings:
    clusterRoleRefs:
      - admin
  roleBindings:
    - namespace: e2e-test-ns
      clusterRoleRefs:
        - e2e-allowed-reader
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(violatingYAML)
			_, _ = utils.Run(cmd)

			By("Verifying RestrictedBindDefinition shows policy violations")
			// The RBD should be created but show PolicyCompliant=False
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "restrictedbinddefinition",
					"e2e-violating-binding",
					"-o", "jsonpath={.status.conditions[?(@.type=='PolicyCompliant')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusFalse
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Cleaning up violating binding")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition",
				"e2e-violating-binding", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		It("should clean up bindings when RestrictedBindDefinition is deleted", func() {
			By("Setting up RBACPolicy and prerequisite ClusterRole")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			applyFixture("roledefinition_clusterrole.yaml")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "e2e-cluster-reader", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Applying RestrictedBindDefinition")
			applyFixture("restrictedbinddefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Waiting for RoleBinding to be created")
			Eventually(func() error {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rolebinding",
					"-l", "app.kubernetes.io/managed-by=auth-operator",
					"-n", testNamespace,
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if len(string(output)) == 0 {
					return fmt.Errorf("no RoleBindings found")
				}
				return nil
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Deleting RestrictedBindDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition",
				"e2e-test-restricted-binding", "--timeout=60s")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleBinding to be cleaned up")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "rolebinding",
					"-l", "app.kubernetes.io/managed-by=auth-operator",
					"-n", testNamespace,
					"-o", "name")
				output, err := utils.Run(cmd)
				if err != nil {
					return true // Error likely means not found
				}
				return len(strings.TrimSpace(string(output))) == 0
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})
	})

	Context("RestrictedRoleDefinition CRD", func() {
		It("should create a Role within policy limits", func() {
			By("Applying RBACPolicy first")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedRoleDefinition")
			applyFixture("restrictedroledefinition.yaml")

			By("Verifying RestrictedRoleDefinition was created")
			Eventually(func() error {
				return checkResourceExists("restrictedroledefinition", "e2e-test-restricted-role", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RestrictedRoleDefinition is policy compliant")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "PolicyCompliant")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RestrictedRoleDefinition status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying Role was created in test namespace")
			Eventually(func() error {
				return checkResourceExists("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying Role excludes restricted APIs (velero.io)")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "role",
				"e2e-restricted-reader", "-n", testNamespace, "-o", "yaml")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(ContainSubstring("velero.io"))
		})

		It("should clean up roles when RestrictedRoleDefinition is deleted", func() {
			By("Setting up RBACPolicy")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedRoleDefinition")
			applyFixture("restrictedroledefinition.yaml")
			Eventually(func() error {
				return checkResourceExists("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Deleting RestrictedRoleDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "restrictedroledefinition",
				"e2e-test-restricted-role", "--timeout=60s")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Role to be cleaned up")
			Eventually(func() error {
				err := checkResourceExists("role", "e2e-restricted-reader", testNamespace)
				if err != nil {
					return nil // Resource not found = cleaned up
				}
				return fmt.Errorf("Role still exists")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("RBACPolicy Deletion Protection", func() {
		It("should prevent deletion of RBACPolicy with bound resources", func() {
			By("Creating RBACPolicy")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Creating RestrictedRoleDefinition that references the policy")
			applyFixture("restrictedroledefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Attempting to delete RBACPolicy (should be blocked by webhook)")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy",
				"e2e-test-policy", "--timeout=10s")
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "RBACPolicy deletion should be blocked when bound resources exist")

			By("Cleaning up: delete the RestrictedRoleDefinition first")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "restrictedroledefinition",
				"e2e-test-restricted-role", "--ignore-not-found=true", "--timeout=60s")
			_, _ = utils.Run(cmd)

			By("Now delete the RBACPolicy (should succeed)")
			Eventually(func() error {
				cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy",
					"e2e-test-policy", "--timeout=30s")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("New CRDs Installed", func() {
		It("should have RBACPolicy CRD installed", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "crd",
				"rbacpolicies.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have RestrictedBindDefinition CRD installed", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "crd",
				"restrictedbinddefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have RestrictedRoleDefinition CRD installed", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "crd",
				"restrictedroledefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

func checkResourceCondition(resourceType, name, conditionType string) bool {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", resourceType, name,
		"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", conditionType))
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == statusTrue
}

func cleanupRestrictedCRDTestState() {
	// Delete restricted resources first (they reference policies)
	for _, resource := range []string{
		"restrictedbinddefinition",
		"restrictedroledefinition",
	} {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", resource,
			"-l", "app.kubernetes.io/component=e2e-test",
			"--ignore-not-found=true", "--wait=false", "--timeout=30s")
		_, _ = utils.Run(cmd)
		utils.RemoveFinalizersForAll(resource)
	}

	// Delete violating binding if it exists
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition",
		"e2e-violating-binding", "--ignore-not-found=true", "--wait=false")
	_, _ = utils.Run(cmd)

	// Wait for restricted resources to be cleaned up
	time.Sleep(2 * time.Second)

	// Then delete policies (now that nothing references them)
	cmd = exec.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy",
		"-l", "app.kubernetes.io/component=e2e-test",
		"--ignore-not-found=true", "--wait=false", "--timeout=30s")
	_, _ = utils.Run(cmd)
	utils.RemoveFinalizersForAll("rbacpolicy")

	// Clean up managed RBAC resources
	managedByLabel := "app.kubernetes.io/managed-by=auth-operator"
	utils.CleanupResourcesByLabel("role", managedByLabel, testNamespace)
	utils.CleanupResourcesByLabel("rolebinding", managedByLabel, testNamespace)
	utils.CleanupResourcesByLabel("serviceaccount", managedByLabel, testNamespace)
}
