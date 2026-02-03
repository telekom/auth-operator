//go:build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("Integration Tests - Complex Multi-CRD Scenarios", Ordered, Label("integration"), func() {
	const (
		integrationNamespace = "auth-operator-integration-test"
		integrationRelease   = "auth-operator-int"
		testNS1              = "integration-ns-alpha"
		testNS2              = "integration-ns-beta"
		testNS3              = "integration-ns-gamma"
		helmChartPathInt     = "chart/auth-operator"
		deployTimeoutInt     = 3 * time.Minute
		pollingIntervalInt   = 3 * time.Second
		reconcileTimeoutInt  = 2 * time.Minute
	)

	BeforeAll(func() {
		setSuiteOutputDir("integration")
		By("Creating integration test namespace")
		createNamespaceIfNotExists(integrationNamespace, nil)

		By("Creating test namespaces with different labels")
		createNamespaceIfNotExists(testNS1, map[string]string{
			"integration-test": "true",
			"env":              "dev",
			"team":             "alpha",
		})
		createNamespaceIfNotExists(testNS2, map[string]string{
			"integration-test": "true",
			"env":              "staging",
			"team":             "beta",
		})
		createNamespaceIfNotExists(testNS3, map[string]string{
			"integration-test": "true",
			"env":              "prod",
			"team":             "gamma",
		})

		By("Installing auth-operator via Helm")
		cmd := exec.CommandContext(context.Background(), "make", "docker-build", "IMG=auth-operator:e2e-test")
		// Run make from project root
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "kind", "load", "docker-image", "auth-operator:e2e-test", "--name", kindClusterName)
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "helm", "upgrade", "--install", integrationRelease, helmChartPathInt,
			"-n", integrationNamespace,
			"--set", "image.repository=auth-operator",
			"--set", "image.tag=e2e-test",
			"--set", "controller.imagePullPolicy=IfNotPresent",
			"--set", "webhook.imagePullPolicy=IfNotPresent",
			"--set", "controller.replicaCount=1",
			"--set", "webhook.replicaCount=1",
			"--wait",
			"--timeout", "5m",
		)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for controller to be ready")
		Eventually(func() error {
			return verifyIntegrationControllerReady(integrationNamespace)
		}, deployTimeoutInt, pollingIntervalInt).Should(Succeed())

		By("Waiting for webhook pods and service endpoints")
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", integrationNamespace, deployTimeoutInt)).To(Succeed())
		Expect(utils.WaitForServiceEndpoints(fmt.Sprintf("%s-webhook-service", integrationRelease), integrationNamespace, deployTimeoutInt)).To(Succeed())
	})

	AfterAll(func() {
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Integration E2E AfterAll")
			utils.CollectNamespaceDebugInfo(integrationNamespace, "Integration E2E AfterAll")
			utils.CollectOperatorLogs(integrationNamespace, 200)
			for _, ns := range []string{testNS1, testNS2, testNS3} {
				utils.CollectNamespaceDebugInfo(ns, "Integration E2E AfterAll")
			}
		}

		// Use centralized cleanup
		By("Cleaning up test resources")
		namespaces := []string{integrationNamespace, testNS1, testNS2, testNS3}
		clusterRoles := []string{
			"int-cluster-admin-reader",
			"int-cluster-pod-reader",
			"int-cluster-secret-reader",
			"int-ns-configmap-reader",
		}
		clusterRoleBindings := []string{
			"int-multi-role-bind-int-cluster-admin-reader-binding",
			"int-multi-role-bind-int-cluster-pod-reader-binding",
		}
		CleanupForIntegrationTests(namespaces, clusterRoles, clusterRoleBindings)
	})

	Context("Multiple RoleDefinitions with Different Scopes", func() {
		It("should create multiple ClusterRoles from RoleDefinitions", func() {
			By("Creating RoleDefinition for admin-reader ClusterRole")
			roleDefAdminYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: int-roledefinition-admin-reader
spec:
  targetRole: ClusterRole
  targetName: int-cluster-admin-reader
  scopeNamespaced: false
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
  restrictedApis:
    - name: velero.io
      versions:
        - groupVersion: velero.io/v1
          version: v1
`
			applyYAML(roleDefAdminYAML)

			By("Creating RoleDefinition for pod-reader ClusterRole")
			roleDefPodYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: int-roledefinition-pod-reader
spec:
  targetRole: ClusterRole
  targetName: int-cluster-pod-reader
  scopeNamespaced: true
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
`
			applyYAML(roleDefPodYAML)

			By("Creating RoleDefinition for secret-reader ClusterRole")
			roleDefSecretYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: int-roledefinition-secret-reader
spec:
  targetRole: ClusterRole
  targetName: int-cluster-secret-reader
  scopeNamespaced: true
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
`
			applyYAML(roleDefSecretYAML)

			By("Waiting for all ClusterRoles to be created")
			clusterRoles := []string{
				"int-cluster-admin-reader",
				"int-cluster-pod-reader",
				"int-cluster-secret-reader",
			}
			for _, roleName := range clusterRoles {
				Eventually(func() error {
					return checkResourceExists("clusterrole", roleName, "")
				}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "ClusterRole %s should exist", roleName)
			}

			By("Verifying all RoleDefinitions have Created status")
			roleDefinitions := []string{
				"int-roledefinition-admin-reader",
				"int-roledefinition-pod-reader",
				"int-roledefinition-secret-reader",
			}
			for _, rdName := range roleDefinitions {
				Eventually(func() bool {
					return checkRoleDefinitionReconciled(rdName)
				}, reconcileTimeoutInt, pollingIntervalInt).Should(BeTrue(), "RoleDefinition %s should be reconciled", rdName)
			}
		})

		It("should create namespaced Role in specific namespace", func() {
			By("Creating RoleDefinition for namespaced Role")
			roleDefNsYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: int-roledefinition-ns-configmap
spec:
  targetRole: Role
  targetName: int-ns-configmap-reader
  targetNamespace: %s
  scopeNamespaced: true
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
`, testNS1)
			applyYAML(roleDefNsYAML)

			By("Waiting for Role to be created in target namespace")
			Eventually(func() error {
				return checkResourceExists("role", "int-ns-configmap-reader", testNS1)
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed())
		})
	})

	Context("BindDefinition with Multiple ClusterRole References", func() {
		It("should create multiple ClusterRoleBindings from single BindDefinition", func() {
			By("Creating BindDefinition referencing multiple ClusterRoles")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: int-binddefinition-multi-role
spec:
  targetName: int-multi-role-bind
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: int-multi-user@example.com
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: int-multi-group
  clusterRoleBindings:
    clusterRoleRefs:
      - int-cluster-admin-reader
      - int-cluster-pod-reader
`
			applyYAML(bindDefYAML)

			By("Waiting for both ClusterRoleBindings to be created")
			expectedCRBs := []string{
				"int-multi-role-bind-int-cluster-admin-reader-binding",
				"int-multi-role-bind-int-cluster-pod-reader-binding",
			}
			for _, crbName := range expectedCRBs {
				Eventually(func() error {
					return checkResourceExists("clusterrolebinding", crbName, "")
				}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "ClusterRoleBinding %s should exist", crbName)
			}

			By("Verifying BindDefinition status")
			Eventually(func() bool {
				return checkBindDefinitionReconciled("int-binddefinition-multi-role")
			}, reconcileTimeoutInt, pollingIntervalInt).Should(BeTrue())

			By("Verifying ClusterRoleBindings have correct subjects")
			for _, crbName := range expectedCRBs {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", crbName,
					"-o", "jsonpath={.subjects}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				subjects := string(output)
				Expect(subjects).To(ContainSubstring("int-multi-user@example.com"))
				Expect(subjects).To(ContainSubstring("int-multi-group"))
			}
		})
	})

	Context("BindDefinition with Namespace Selectors", func() {
		It("should create RoleBindings in namespaces matching label selector", func() {
			By("Creating BindDefinition with label selector for 'env' label")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: int-binddefinition-ns-selector
spec:
  targetName: int-ns-selector-bind
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: int-ns-selector-user@example.com
  roleBindings:
    - clusterRoleRefs:
        - int-cluster-secret-reader
      namespaceSelector:
        - matchLabels:
            integration-test: "true"
`
			applyYAML(bindDefYAML)

			By("Waiting for RoleBindings in all labeled namespaces")
			expectedRBName := "int-ns-selector-bind-int-cluster-secret-reader-binding"
			for _, ns := range []string{testNS1, testNS2, testNS3} {
				Eventually(func() error {
					return checkResourceExists("rolebinding", expectedRBName, ns)
				}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "RoleBinding should exist in namespace %s", ns)
			}

			By("Verifying BindDefinition status")
			Eventually(func() bool {
				return checkBindDefinitionReconciled("int-binddefinition-ns-selector")
			}, reconcileTimeoutInt, pollingIntervalInt).Should(BeTrue())
		})

		It("should create RoleBindings only in namespaces matching complex selector", func() {
			By("Creating BindDefinition with selector for env=dev or env=staging")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: int-binddefinition-env-selector
spec:
  targetName: int-env-selector-bind
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: int-dev-team
  roleBindings:
    - clusterRoleRefs:
        - int-cluster-pod-reader
      namespaceSelector:
        - matchLabels:
            env: dev
        - matchLabels:
            env: staging
`
			applyYAML(bindDefYAML)

			By("Waiting for RoleBindings in dev and staging namespaces")
			expectedRBName := "int-env-selector-bind-int-cluster-pod-reader-binding"

			for _, ns := range []string{testNS1, testNS2} {
				Eventually(func() error {
					return checkResourceExists("rolebinding", expectedRBName, ns)
				}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "RoleBinding should exist in namespace %s", ns)
			}

			Consistently(func() error {
				return checkResourceExists("rolebinding", expectedRBName, testNS3)
			}, 10*time.Second, 2*time.Second).ShouldNot(Succeed(), "RoleBinding should NOT exist in namespace %s", testNS3)
		})
	})

	Context("BindDefinition with ServiceAccount Auto-Creation", func() {
		It("should auto-create ServiceAccounts in multiple namespaces", func() {
			By("Creating BindDefinition with ServiceAccount subjects for different namespaces")
			bindDefYAML := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: int-binddefinition-multi-sa
spec:
  targetName: int-multi-sa-bind
  subjects:
    - kind: ServiceAccount
      name: int-auto-sa-alpha
      namespace: %s
    - kind: ServiceAccount
      name: int-auto-sa-beta
      namespace: %s
  clusterRoleBindings:
    clusterRoleRefs:
      - int-cluster-pod-reader
`, testNS1, testNS2)
			applyYAML(bindDefYAML)

			By("Waiting for ServiceAccounts to be auto-created")
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "int-auto-sa-alpha", testNS1)
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "ServiceAccount should exist in %s", testNS1)

			Eventually(func() error {
				return checkResourceExists("serviceaccount", "int-auto-sa-beta", testNS2)
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed(), "ServiceAccount should exist in %s", testNS2)

			By("Verifying ClusterRoleBinding was created with both ServiceAccounts")
			crbName := "int-multi-sa-bind-int-cluster-pod-reader-binding"
			Eventually(func() error {
				return checkResourceExists("clusterrolebinding", crbName, "")
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed())

			By("Verifying ClusterRoleBinding has both ServiceAccount subjects")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", crbName,
				"-o", "jsonpath={.subjects}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			subjects := string(output)
			Expect(subjects).To(ContainSubstring("int-auto-sa-alpha"))
			Expect(subjects).To(ContainSubstring("int-auto-sa-beta"))
		})
	})

	Context("Combined RoleDefinition and BindDefinition with roleRef", func() {
		It("should work with roleRefs referencing existing ClusterRoles", func() {
			By("Creating BindDefinition referencing system ClusterRole view")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: int-binddefinition-system-role
spec:
  targetName: int-system-role-bind
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: int-viewers
  clusterRoleBindings:
    clusterRoleRefs:
      - view
`
			applyYAML(bindDefYAML)

			By("Waiting for ClusterRoleBinding to be created")
			crbName := "int-system-role-bind-view-binding"
			Eventually(func() error {
				return checkResourceExists("clusterrolebinding", crbName, "")
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed())

			By("Verifying ClusterRoleBinding references the view ClusterRole")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", crbName,
				"-o", "jsonpath={.roleRef.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).To(Equal("view"))
		})
	})

	Context("Cleanup Verification", func() {
		It("should clean up generated resources when BindDefinition is deleted", func() {
			By("Verifying multi-role ClusterRoleBindings exist")
			for _, crbName := range []string{
				"int-multi-role-bind-int-cluster-admin-reader-binding",
				"int-multi-role-bind-int-cluster-pod-reader-binding",
			} {
				Expect(checkResourceExists("clusterrolebinding", crbName, "")).To(Succeed())
			}

			By("Deleting the multi-role BindDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", "int-binddefinition-multi-role")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRoleBindings to be deleted")
			for _, crbName := range []string{
				"int-multi-role-bind-int-cluster-admin-reader-binding",
				"int-multi-role-bind-int-cluster-pod-reader-binding",
			} {
				Eventually(func() error {
					err := checkResourceExists("clusterrolebinding", crbName, "")
					if err != nil {
						return nil
					}
					return fmt.Errorf("ClusterRoleBinding %s still exists", crbName)
				}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed())
			}
		})

		It("should clean up generated Roles when RoleDefinition is deleted", func() {
			By("Verifying namespaced Role exists")
			Expect(checkResourceExists("role", "int-ns-configmap-reader", testNS1)).To(Succeed())

			By("Deleting the namespaced RoleDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", "int-roledefinition-ns-configmap")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Role to be deleted")
			Eventually(func() error {
				err := checkResourceExists("role", "int-ns-configmap-reader", testNS1)
				if err != nil {
					return nil
				}
				return fmt.Errorf("Role still exists")
			}, reconcileTimeoutInt, pollingIntervalInt).Should(Succeed())
		})
	})
})

func verifyIntegrationControllerReady(namespace string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
		"-l", "control-plane=controller-manager",
		"-n", namespace,
		"-o", "jsonpath={.items[*].status.phase}")
	output, err := utils.Run(cmd)
	if err != nil {
		return err
	}
	if !strings.Contains(string(output), "Running") {
		return fmt.Errorf("controller not yet running, status: %s", string(output))
	}
	return nil
}

func createNamespaceIfNotExists(name string, labels map[string]string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "create", "ns", name, "--dry-run=client", "-o", "yaml")
	output, _ := utils.Run(cmd)

	cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(output))
	_, _ = utils.Run(cmd)

	if len(labels) > 0 {
		labelArgs := []string{"label", "ns", name, "--overwrite"}
		for k, v := range labels {
			labelArgs = append(labelArgs, fmt.Sprintf("%s=%s", k, v))
		}
		cmd = exec.CommandContext(context.Background(), "kubectl", labelArgs...)
		_, _ = utils.Run(cmd)
	}
}

func applyYAML(yaml string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	output, err := utils.Run(cmd)
	ExpectWithOffset(2, err).NotTo(HaveOccurred(), "Failed to apply YAML: %s\nOutput: %s", yaml, string(output))
}

func cleanupIntegrationTestCRDs() {
	binddefs := []string{
		"int-binddefinition-multi-role",
		"int-binddefinition-ns-selector",
		"int-binddefinition-env-selector",
		"int-binddefinition-multi-sa",
		"int-binddefinition-system-role",
	}
	roledefs := []string{
		"int-roledefinition-admin-reader",
		"int-roledefinition-pod-reader",
		"int-roledefinition-secret-reader",
		"int-roledefinition-ns-configmap",
	}

	// Use centralized cleanup for specific resources
	CleanupCRDsByName(roledefs, binddefs, nil)
	CleanupAllWebhookAuthorizersClusterWide()
}
