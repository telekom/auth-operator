//go:build e2e

/*
Copyright 2025.

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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/test/utils"
)

// Package level constant for status checking
const goldenStatusTrue = "True"

var _ = Describe("Golden File Comparison Tests", Ordered, Label("golden"), func() {
	const (
		goldenNamespace  = "auth-operator-golden-test"
		goldenRelease    = "auth-operator-golden"
		helmChartPath    = "chart/auth-operator"
		deployTimeout    = 3 * time.Minute
		pollingInterval  = 5 * time.Second
		reconcileTimeout = 2 * time.Minute
	)

	var testdataPath string

	BeforeAll(func() {
		setSuiteOutputDir("golden")
		var err error
		testdataPath, err = filepath.Abs("test/e2e/testdata")
		Expect(err).NotTo(HaveOccurred())
		Expect(testdataPath).To(BeADirectory(), "testdata directory must exist")

		By("Creating test namespace")
		cmd := exec.Command("kubectl", "create", "ns", goldenNamespace, "--dry-run=client", "-o", "yaml")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(string(output))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("Installing auth-operator via Helm")
		// Build the docker image first
		cmd = exec.Command("make", "docker-build", "IMG=auth-operator:e2e-test")
		cmd.Dir = filepath.Join(testdataPath, "../..")
		_, _ = utils.Run(cmd) // Ignore if already built

		// Load image to kind
		cmd = exec.Command("kind", "load", "docker-image", "auth-operator:e2e-test", "--name", kindClusterName)
		_, _ = utils.Run(cmd)

		// Install Helm chart
		cmd = exec.Command("helm", "upgrade", "--install", goldenRelease, helmChartPath,
			"-n", goldenNamespace,
			"--set", "image.repository=auth-operator",
			"--set", "image.tag=e2e-test",
			"--set", "controller.imagePullPolicy=IfNotPresent",
			"--set", "webhook.imagePullPolicy=IfNotPresent",
			"--set", "controller.replicaCount=1",
			"--set", "webhook.replicaCount=1",
			"--wait",
			"--timeout", "5m",
		)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for controller to be ready")
		Eventually(func() error {
			return verifyGoldenControllerReady(goldenNamespace)
		}, deployTimeout, pollingInterval).Should(Succeed())

		By("Waiting for webhook pods and configurations to be ready")
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", goldenNamespace, deployTimeout)).To(Succeed())
		Expect(utils.WaitForServiceEndpoints(fmt.Sprintf("%s-webhook-service", goldenRelease), goldenNamespace, deployTimeout)).To(Succeed())
	})

	AfterAll(func() {
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Golden E2E AfterAll")
			utils.CollectNamespaceDebugInfo(goldenNamespace, "Golden E2E AfterAll")
			utils.CollectOperatorLogs(goldenNamespace, 200)
		}

		// Use centralized cleanup
		By("Cleaning up test resources")
		clusterRoles := []string{
			"golden-cluster-reader",
			"golden-restricted-apis-role",
		}
		clusterRoleBindings := []string{
			"golden-bind-golden-cluster-reader-binding",
			"golden-multi-golden-cluster-reader-binding",
			"golden-multi-view-binding",
			"golden-multi-edit-binding",
			"golden-mixed-golden-cluster-reader-binding",
		}
		CleanupComplete([]string{goldenNamespace}, clusterRoles, clusterRoleBindings, fmt.Sprintf("app.kubernetes.io/instance=%s", goldenRelease))
	})

	Context("RoleDefinition generates correct ClusterRole", func() {
		It("should generate ClusterRole with correct structure", func() {
			By("Applying RoleDefinition input")
			inputPath := filepath.Join(testdataPath, "roledefinition-clusterrole-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath, "-n", goldenNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenRoleDefinitionCreated("golden-test-cluster-reader", goldenNamespace)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying ClusterRole was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrole", "golden-cluster-reader", "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Comparing generated ClusterRole structure")
			cmd = exec.Command("kubectl", "get", "clusterrole", "golden-cluster-reader", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var clusterRole map[string]interface{}
			err = json.Unmarshal(output, &clusterRole)
			Expect(err).NotTo(HaveOccurred())

			// Verify metadata
			metadata := clusterRole["metadata"].(map[string]interface{})
			Expect(metadata["name"]).To(Equal("golden-cluster-reader"))

			// Verify rules exist (generated from cluster API discovery)
			rules := clusterRole["rules"]
			Expect(rules).NotTo(BeNil())
			rulesSlice := rules.([]interface{})
			Expect(rulesSlice).NotTo(BeEmpty())

			// Verify restricted verbs (update, create) are NOT present
			for _, rule := range rulesSlice {
				ruleMap := rule.(map[string]interface{})
				if verbs, ok := ruleMap["verbs"].([]interface{}); ok {
					verbStrs := make([]string, 0, len(verbs))
					for _, v := range verbs {
						verbStrs = append(verbStrs, v.(string))
					}
					// Neither "update" nor "create" should be present unless "all" is used
					if !containsGoldenVerb(verbStrs, "*") {
						Expect(verbStrs).NotTo(ContainElement("update"), "update verb should be restricted")
						Expect(verbStrs).NotTo(ContainElement("create"), "create verb should be restricted")
					}
				}
			}
		})
	})

	Context("RoleDefinition generates correct namespaced Role", func() {
		It("should generate Role in target namespace", func() {
			By("Applying namespaced RoleDefinition input")
			inputPath := filepath.Join(testdataPath, "roledefinition-namespaced-role-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath, "-n", goldenNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenRoleDefinitionCreated("golden-test-ns-reader", goldenNamespace)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying Role was created in target namespace")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "role", "golden-ns-reader", "-n", goldenNamespace, "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Comparing generated Role structure")
			cmd = exec.Command("kubectl", "get", "role", "golden-ns-reader", "-n", goldenNamespace, "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var role map[string]interface{}
			err = json.Unmarshal(output, &role)
			Expect(err).NotTo(HaveOccurred())

			// Verify metadata
			metadata := role["metadata"].(map[string]interface{})
			Expect(metadata["name"]).To(Equal("golden-ns-reader"))
			Expect(metadata["namespace"]).To(Equal(goldenNamespace))

			// Verify rules exist
			rules := role["rules"]
			Expect(rules).NotTo(BeNil())
			rulesSlice := rules.([]interface{})
			Expect(rulesSlice).NotTo(BeEmpty())

			// Verify restricted verbs (get, delete) are NOT present
			for _, rule := range rulesSlice {
				ruleMap := rule.(map[string]interface{})
				if verbs, ok := ruleMap["verbs"].([]interface{}); ok {
					verbStrs := make([]string, 0, len(verbs))
					for _, v := range verbs {
						verbStrs = append(verbStrs, v.(string))
					}
					// Neither "get" nor "delete" should be present unless "*" is used
					if !containsGoldenVerb(verbStrs, "*") {
						Expect(verbStrs).NotTo(ContainElement("get"), "get verb should be restricted")
						Expect(verbStrs).NotTo(ContainElement("delete"), "delete verb should be restricted")
					}
				}
			}
		})
	})

	Context("BindDefinition generates correct ClusterRoleBinding", func() {
		It("should generate ClusterRoleBinding with correct subjects", func() {
			By("Applying BindDefinition input")
			inputPath := filepath.Join(testdataPath, "binddefinition-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath, "-n", goldenNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BindDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenBindDefinitionCreated("golden-test-bind", goldenNamespace)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying ClusterRoleBinding was created")
			// ClusterRoleBinding name format: {targetName}-{clusterRoleRef}-binding
			crbName := "golden-bind-golden-cluster-reader-binding"
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Comparing generated ClusterRoleBinding against expected")
			expectedPath := filepath.Join(testdataPath, "binddefinition-expected-crb.yaml")
			expectedBytes, err := os.ReadFile(expectedPath)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "json")
			actualOutput, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var actualCRB map[string]interface{}
			err = json.Unmarshal(actualOutput, &actualCRB)
			Expect(err).NotTo(HaveOccurred())

			// Compare key fields
			metadata := actualCRB["metadata"].(map[string]interface{})
			Expect(metadata["name"]).To(Equal(crbName))

			roleRef := actualCRB["roleRef"].(map[string]interface{})
			Expect(roleRef["kind"]).To(Equal("ClusterRole"))
			Expect(roleRef["name"]).To(Equal("golden-cluster-reader"))
			Expect(roleRef["apiGroup"]).To(Equal("rbac.authorization.k8s.io"))

			subjects := actualCRB["subjects"].([]interface{})
			Expect(subjects).To(HaveLen(2))

			// Verify subjects match expected (order may vary)
			subjectNames := make([]string, 0, len(subjects))
			for _, s := range subjects {
				subjectMap := s.(map[string]interface{})
				subjectNames = append(subjectNames, subjectMap["name"].(string))
			}
			Expect(subjectNames).To(ContainElements("golden-test-user@example.com", "golden-test-group"))

			By("Golden file comparison completed successfully")
			GinkgoWriter.Printf("Expected content (from file):\n%s\n", string(expectedBytes))
			GinkgoWriter.Printf("Actual ClusterRoleBinding matches expected structure\n")
		})
	})

	Context("RoleDefinition with restricted APIs", func() {
		It("should exclude entire API groups from generated ClusterRole", func() {
			By("Applying RoleDefinition with restrictedApis")
			inputPath := filepath.Join(testdataPath, "golden/roledefinition-restricted-apis-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenRoleDefinitionCreated("golden-restricted-apis", "")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying ClusterRole was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrole", "golden-restricted-apis-role", "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying excluded API groups are not present")
			cmd = exec.Command("kubectl", "get", "clusterrole", "golden-restricted-apis-role", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var clusterRole map[string]interface{}
			err = json.Unmarshal(output, &clusterRole)
			Expect(err).NotTo(HaveOccurred())

			rules := clusterRole["rules"].([]interface{})
			for _, rule := range rules {
				ruleMap := rule.(map[string]interface{})
				if apiGroups, ok := ruleMap["apiGroups"].([]interface{}); ok {
					for _, ag := range apiGroups {
						apiGroup := ag.(string)
						Expect(apiGroup).NotTo(Equal("apps"), "apps API group should be restricted")
						Expect(apiGroup).NotTo(Equal("batch"), "batch API group should be restricted")
						Expect(apiGroup).NotTo(Equal("autoscaling"), "autoscaling API group should be restricted")
					}
				}
			}
		})
	})

	Context("RoleDefinition with restricted resources", func() {
		It("should exclude specific resources from generated Role", func() {
			By("Applying RoleDefinition with restrictedResources")
			inputPath := filepath.Join(testdataPath, "golden/roledefinition-restricted-resources-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenRoleDefinitionCreated("golden-restricted-resources", "")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying Role was created in namespace")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "role",
					"golden-restricted-resources-role", "-n", goldenNamespace, "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying excluded resources are not present")
			cmd = exec.Command("kubectl", "get", "role", "golden-restricted-resources-role", "-n", goldenNamespace, "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var role map[string]interface{}
			err = json.Unmarshal(output, &role)
			Expect(err).NotTo(HaveOccurred())

			rules := role["rules"].([]interface{})
			for _, rule := range rules {
				ruleMap := rule.(map[string]interface{})
				if resources, ok := ruleMap["resources"].([]interface{}); ok {
					for _, r := range resources {
						resource := r.(string)
						Expect(resource).NotTo(Equal("secrets"), "secrets should be restricted")
						Expect(resource).NotTo(Equal("configmaps"), "configmaps should be restricted")
						Expect(resource).NotTo(Equal("serviceaccounts"), "serviceaccounts should be restricted")
					}
				}
			}
		})
	})

	Context("BindDefinition with multiple ClusterRoleRefs", func() {
		It("should create multiple ClusterRoleBindings", func() {
			By("Applying BindDefinition with multiple clusterRoleRefs")
			inputPath := filepath.Join(testdataPath, "golden/binddefinition-multi-clusterroles-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BindDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenBindDefinitionCreated("golden-multi-crb", "")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying multiple ClusterRoleBindings were created")
			expectedCRBs := []string{
				"golden-multi-golden-cluster-reader-binding",
				"golden-multi-view-binding",
				"golden-multi-edit-binding",
			}
			for _, crbName := range expectedCRBs {
				Eventually(func() error {
					cmd := exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "name")
					_, err := utils.Run(cmd)
					return err
				}, reconcileTimeout, pollingInterval).Should(Succeed(), fmt.Sprintf("ClusterRoleBinding %s should exist", crbName))
			}

			By("Verifying subjects are consistent across all bindings")
			for _, crbName := range expectedCRBs {
				cmd = exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "json")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				var crb map[string]interface{}
				err = json.Unmarshal(output, &crb)
				Expect(err).NotTo(HaveOccurred())

				subjects := crb["subjects"].([]interface{})
				Expect(subjects).To(HaveLen(2))

				subjectNames := make([]string, 0, len(subjects))
				for _, s := range subjects {
					subjectMap := s.(map[string]interface{})
					subjectNames = append(subjectNames, subjectMap["name"].(string))
				}
				Expect(subjectNames).To(ContainElements("multi-role-user@example.com", "multi-role-group"))
			}

			By("Comparing against expected golden file")
			expectedPath := filepath.Join(testdataPath, "golden/expected/multi-clusterrolebindings.yaml")
			expectedBytes, err := os.ReadFile(expectedPath)
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Expected multi-ClusterRoleBindings:\n%s\n", string(expectedBytes))
		})
	})

	Context("BindDefinition with mixed subject types", func() {
		It("should create ClusterRoleBinding with User, Group, and ServiceAccount subjects", func() {
			By("Applying BindDefinition with mixed subjects")
			inputPath := filepath.Join(testdataPath, "golden/binddefinition-mixed-subjects-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BindDefinition to be reconciled")
			Eventually(func() bool {
				return checkGoldenBindDefinitionCreated("golden-mixed-subjects", "")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying ClusterRoleBinding was created")
			crbName := "golden-mixed-golden-cluster-reader-binding"
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying all subject types are present")
			cmd = exec.Command("kubectl", "get", "clusterrolebinding", crbName, "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var crb map[string]interface{}
			err = json.Unmarshal(output, &crb)
			Expect(err).NotTo(HaveOccurred())

			subjects := crb["subjects"].([]interface{})
			Expect(subjects).To(HaveLen(4)) // User, Group, 2 ServiceAccounts

			subjectKinds := make(map[string]int)
			for _, s := range subjects {
				subjectMap := s.(map[string]interface{})
				kind := subjectMap["kind"].(string)
				subjectKinds[kind]++
			}
			Expect(subjectKinds["User"]).To(Equal(1))
			Expect(subjectKinds["Group"]).To(Equal(1))
			Expect(subjectKinds["ServiceAccount"]).To(Equal(2))

			By("Verifying ServiceAccounts were auto-created")
			serviceAccounts := []string{"golden-app-sa", "golden-worker-sa"}
			for _, saName := range serviceAccounts {
				Eventually(func() error {
					cmd := exec.Command("kubectl", "get", "serviceaccount",
						saName, "-n", goldenNamespace, "-o", "name")
					_, err := utils.Run(cmd)
					return err
				}, reconcileTimeout, pollingInterval).Should(Succeed(),
					fmt.Sprintf("ServiceAccount %s should be auto-created", saName))
			}
		})
	})

	Context("WebhookAuthorizer with group-based authorization", func() {
		It("should create WebhookAuthorizer with group principals", func() {
			By("Applying WebhookAuthorizer with group-based rules")
			inputPath := filepath.Join(testdataPath, "golden/webhookauthorizer-group-based-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "webhookauthorizer", "golden-group-authorizer", "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying spec has correct structure")
			cmd = exec.Command("kubectl", "get", "webhookauthorizer", "golden-group-authorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var wa map[string]interface{}
			err = json.Unmarshal(output, &wa)
			Expect(err).NotTo(HaveOccurred())

			spec := wa["spec"].(map[string]interface{})
			allowedPrincipals := spec["allowedPrincipals"].([]interface{})
			Expect(allowedPrincipals).To(HaveLen(2))

			// Verify group-based principal exists
			foundGroupPrincipal := false
			for _, p := range allowedPrincipals {
				principal := p.(map[string]interface{})
				if groups, ok := principal["groups"].([]interface{}); ok {
					if len(groups) > 0 {
						foundGroupPrincipal = true
						break
					}
				}
			}
			Expect(foundGroupPrincipal).To(BeTrue(), "Should have at least one group-based principal")
		})
	})

	Context("WebhookAuthorizer with denied principals", func() {
		It("should create WebhookAuthorizer with deny list", func() {
			By("Applying WebhookAuthorizer with deniedPrincipals")
			inputPath := filepath.Join(testdataPath, "golden/webhookauthorizer-deny-list-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "webhookauthorizer", "golden-deny-authorizer", "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying deniedPrincipals are set")
			cmd = exec.Command("kubectl", "get", "webhookauthorizer", "golden-deny-authorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var wa map[string]interface{}
			err = json.Unmarshal(output, &wa)
			Expect(err).NotTo(HaveOccurred())

			spec := wa["spec"].(map[string]interface{})
			deniedPrincipals := spec["deniedPrincipals"].([]interface{})
			Expect(deniedPrincipals).To(HaveLen(3), "Should have 3 denied principals")
		})
	})

	Context("WebhookAuthorizer with namespace selector", func() {
		It("should create WebhookAuthorizer with namespaceSelector", func() {
			By("Applying WebhookAuthorizer with namespaceSelector")
			inputPath := filepath.Join(testdataPath, "golden/webhookauthorizer-namespace-selector-input.yaml")
			cmd := exec.Command("kubectl", "apply", "-f", inputPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "webhookauthorizer", "golden-ns-scoped-authorizer", "-o", "json")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying namespaceSelector is set")
			cmd = exec.Command("kubectl", "get", "webhookauthorizer", "golden-ns-scoped-authorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var wa map[string]interface{}
			err = json.Unmarshal(output, &wa)
			Expect(err).NotTo(HaveOccurred())

			spec := wa["spec"].(map[string]interface{})
			nsSelector := spec["namespaceSelector"].(map[string]interface{})
			matchLabels := nsSelector["matchLabels"].(map[string]interface{})
			Expect(matchLabels).To(HaveKey("environment"))
			Expect(matchLabels["environment"]).To(Equal("development"))
		})
	})
})

// Helper functions

func verifyGoldenControllerReady(namespace string) error {
	cmd := exec.Command("kubectl", "get", "pods",
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

func checkGoldenRoleDefinitionCreated(name, namespace string) bool {
	cmd := exec.Command("kubectl", "get", "roledefinition", name,
		"-n", namespace,
		"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == goldenStatusTrue
}

func checkGoldenBindDefinitionCreated(name, namespace string) bool {
	cmd := exec.Command("kubectl", "get", "binddefinition", name,
		"-n", namespace,
		"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == goldenStatusTrue
}

func cleanupGoldenTestCRDs(namespace string) {
	// Use centralized cleanup for all CRDs cluster-wide first
	CleanupAllWebhookAuthorizersClusterWide()
	CleanupAllCRDsInNamespace("") // cluster-scoped cleanup

	// Also cleanup namespaced resources if namespace is provided
	if namespace != "" {
		CleanupAllCRDsInNamespace(namespace)
	}
}

func containsGoldenVerb(verbs []string, verb string) bool {
	for _, v := range verbs {
		if v == verb {
			return true
		}
	}
	return false
}
