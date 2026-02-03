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
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Dev E2E tests use kustomize/make deploy instead of Helm
// This validates that the standard Kubernetes manifests work correctly
var _ = Describe("Dev Flavor E2E - Kustomize Deploy", Ordered, Label("dev"), func() {
	const (
		devNamespace       = "auth-operator-system"
		devTestNamespace   = "dev-e2e-test-ns"
		devWebhookService  = "auth-operator-webhook-service"
		deployTimeoutDev   = 5 * time.Minute
		reconcileTimeoutDv = 2 * time.Minute
		pollingIntervalDev = 5 * time.Second
	)

	BeforeAll(func() {
		By("Creating test namespace")
		createDevTestNamespace(devTestNamespace)

		setSuiteOutputDir("dev")

		// Always deploy fresh operator (no reuse)
		By("Building the operator image")
		cmd := exec.CommandContext(context.Background(), "make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build operator image")

		By("Loading the operator image into kind cluster")
		err = utils.LoadImageToKindClusterWithName(projectImage)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing CRDs via make install")
		cmd = exec.CommandContext(context.Background(), "make", "install")
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("Deploying the operator via make deploy")
		cmd = exec.CommandContext(context.Background(), "make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to deploy operator")

		By("Waiting for controller-manager to be ready")
		Eventually(func() error {
			return verifyDevControllerRunning(devNamespace)
		}, deployTimeoutDev, pollingIntervalDev).Should(Succeed())

		By("Waiting for webhook pods and configurations to be ready")
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", devNamespace, deployTimeoutDev)).To(Succeed())
		Expect(utils.WaitForWebhookConfigurations("authorization.t-caas.telekom.com/component=webhook", deployTimeoutDev)).To(Succeed())
		Expect(utils.WaitForServiceEndpoints(devWebhookService, devNamespace, deployTimeoutDev)).To(Succeed())

		By("Waiting for webhook CA bundle to be injected by cert-rotator")
		Expect(utils.WaitForWebhookCABundle("authorization.t-caas.telekom.com/component=webhook", deployTimeoutDev)).To(Succeed())

		By("Waiting for webhook TLS certificate to be ready")
		Expect(utils.WaitForWebhookReady(deployTimeoutDev)).To(Succeed())
	})

	AfterAll(func() {
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Dev E2E AfterAll")
			utils.CollectNamespaceDebugInfo(devNamespace, "Dev E2E AfterAll")
			utils.CollectOperatorLogs(devNamespace, 200)
			utils.CollectNamespaceDebugInfo(devTestNamespace, "Dev E2E AfterAll")
		}

		// Use centralized cleanup
		By("Cleaning up test resources")
		clusterRoles := []string{"dev-e2e-generated-clusterrole"}
		CleanupForDevTests(devNamespace, clusterRoles)

		if utils.ShouldTeardown() {
			time.Sleep(5 * time.Second)

			By("Cleaning up webhooks")
			utils.CleanupWebhooks("authorization.t-caas.telekom.com/component=webhook")
			utils.CleanupAllAuthOperatorWebhooks()

			By("Undeploying the operator")
			cmd := exec.CommandContext(context.Background(), "make", "undeploy", "ignore-not-found=true")
			_, _ = utils.Run(cmd)

			By("Uninstalling CRDs")
			cmd = exec.CommandContext(context.Background(), "make", "uninstall", "ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		By("Cleaning up test namespace")
		cleanupCmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", devTestNamespace, "--ignore-not-found=true")
		_, _ = utils.Run(cleanupCmd)
	})

	Context("Controller Deployment", func() {
		It("should have controller-manager running", func() {
			By("Verifying controller-manager pod is running")
			Expect(verifyDevControllerRunning(devNamespace)).To(Succeed())
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
	})

	Context("RoleDefinition CRD Functionality", func() {
		It("should create ClusterRole from RoleDefinition", func() {
			By("Creating a RoleDefinition")
			roleDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: dev-e2e-cluster-reader
spec:
  targetRole: ClusterRole
  targetName: dev-e2e-generated-clusterrole
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
				return checkResourceExists("clusterrole", "dev-e2e-generated-clusterrole", "")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(Succeed())

			By("Verifying ClusterRole has expected rules (read-only, no create/update/delete/patch)")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get", "clusterrole", "dev-e2e-generated-clusterrole", "-o", "jsonpath={.rules}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				rules := string(output)
				// Should have get, list, watch but NOT create, update, delete, patch (as per restrictedVerbs)
				return strings.Contains(rules, "get") &&
					strings.Contains(rules, "list") &&
					strings.Contains(rules, "watch") &&
					!strings.Contains(rules, `"create"`) &&
					!strings.Contains(rules, `"update"`) &&
					!strings.Contains(rules, `"delete"`) &&
					!strings.Contains(rules, `"patch"`)
			}, reconcileTimeoutDv, pollingIntervalDev).Should(BeTrue())

			By("Verifying RoleDefinition status")
			Eventually(func() bool {
				return checkRoleDefinitionReconciled("dev-e2e-cluster-reader")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(BeTrue())
		})
	})

	Context("BindDefinition CRD Functionality", func() {
		It("should create ClusterRoleBinding from BindDefinition", func() {
			By("Creating a BindDefinition for ClusterRoleBinding")
			bindDefYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: dev-e2e-cluster-binding
spec:
  targetName: dev-e2e-binding
  subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: dev-e2e-user@example.com
    - apiGroup: rbac.authorization.k8s.io
      kind: Group
      name: dev-e2e-group
  clusterRoleBindings:
    clusterRoleRefs:
      - dev-e2e-generated-clusterrole
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bindDefYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRoleBinding to be generated")
			expectedCRBName := "dev-e2e-binding-dev-e2e-generated-clusterrole-binding"
			Eventually(func() error {
				return checkResourceExists("clusterrolebinding", expectedCRBName, "")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(Succeed())

			By("Verifying ClusterRoleBinding has correct subjects and roleRef")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", expectedCRBName, "-o", "jsonpath={.subjects}")
			subjectsOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			subjects := string(subjectsOutput)
			Expect(subjects).To(ContainSubstring("dev-e2e-user@example.com"), "ClusterRoleBinding should contain User subject")
			Expect(subjects).To(ContainSubstring("dev-e2e-group"), "ClusterRoleBinding should contain Group subject")

			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "clusterrolebinding", expectedCRBName, "-o", "jsonpath={.roleRef.name}")
			roleRefOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(roleRefOutput)).To(Equal("dev-e2e-generated-clusterrole"), "ClusterRoleBinding should reference correct ClusterRole")

			By("Verifying BindDefinition status")
			Eventually(func() bool {
				return checkBindDefinitionReconciled("dev-e2e-cluster-binding")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(BeTrue())
		})
	})

	Context("WebhookAuthorizer CRD Functionality", func() {
		It("should create WebhookAuthorizer", func() {
			By("Creating a WebhookAuthorizer")
			authorizerYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: dev-e2e-authorizer
spec:
  resourceRules:
    - apiGroups:
        - ""
      resources:
        - pods
      verbs:
        - get
        - list
  allowedPrincipals:
    - user: dev-allowed-user
`
			cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(authorizerYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				return checkResourceExists("webhookauthorizer", "dev-e2e-authorizer", "")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(Succeed())

			By("Verifying WebhookAuthorizer has correct spec fields")
			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "webhookauthorizer", "dev-e2e-authorizer", "-o", "jsonpath={.spec.resourceRules}")
			rulesOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			rules := string(rulesOutput)
			Expect(rules).To(ContainSubstring("pods"), "WebhookAuthorizer should have pods resource")
			Expect(rules).To(ContainSubstring("get"), "WebhookAuthorizer should have get verb")
			Expect(rules).To(ContainSubstring("list"), "WebhookAuthorizer should have list verb")

			cmd = exec.CommandContext(context.Background(), "kubectl", "get", "webhookauthorizer", "dev-e2e-authorizer", "-o", "jsonpath={.spec.allowedPrincipals}")
			principalsOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(principalsOutput)).To(ContainSubstring("dev-allowed-user"), "WebhookAuthorizer should have correct allowedPrincipals")
		})
	})

	Context("Cleanup Functionality", func() {
		It("should clean up child resources when RoleDefinition is deleted", func() {
			By("Verifying ClusterRole exists before deletion")
			Expect(checkResourceExists("clusterrole", "dev-e2e-generated-clusterrole", "")).To(Succeed())

			By("Deleting the RoleDefinition")
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", "dev-e2e-cluster-reader")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for ClusterRole to be deleted")
			Eventually(func() error {
				err := checkResourceExists("clusterrole", "dev-e2e-generated-clusterrole", "")
				if err != nil {
					return nil
				}
				return fmt.Errorf("ClusterRole still exists")
			}, reconcileTimeoutDv, pollingIntervalDev).Should(Succeed())
		})
	})
})

func verifyDevControllerRunning(namespace string) error {
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "pods",
		"-l", "control-plane=controller-manager",
		"-n", namespace,
		"-o", "jsonpath={.items[0].status.phase}")
	output, err := utils.Run(cmd)
	if err != nil {
		return err
	}
	if string(output) != "Running" {
		return fmt.Errorf("controller pod not running, status: %s", string(output))
	}
	return nil
}

func createDevTestNamespace(namespace string) {
	cmd := exec.CommandContext(context.Background(), "kubectl", "create", "ns", namespace, "--dry-run=client", "-o", "yaml")
	output, _ := utils.Run(cmd)

	cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(output))
	_, _ = utils.Run(cmd)

	cmd = exec.CommandContext(context.Background(), "kubectl", "label", "ns", namespace, "dev-e2e-test=true", "--overwrite")
	_, _ = utils.Run(cmd)
}
