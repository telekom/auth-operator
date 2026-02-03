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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/test/utils"
)

// Constants for complex e2e tests
const (
	statusTrue    = "True"
	statusRunning = "Running"
)

// Complex E2E tests that verify all controller features work in combination
var _ = Describe("Complex Feature Combinations", Ordered, Label("complex"), func() {
	const (
		complexNamespace     = "auth-operator-complex-test"
		complexRelease       = "auth-operator-complex"
		complexTestdataPath  = "test/e2e/testdata/complex"
		helmChartPath        = "chart/auth-operator"
		complexDeployTimeout = 5 * time.Minute
		complexReconcileTime = 3 * time.Minute
		complexPollInterval  = 5 * time.Second
	)

	BeforeAll(func() {
		setSuiteOutputDir("complex")
		By("Setting up complex test environment")

		By("Creating test namespaces with various labels")
		testNsPath := filepath.Join(complexTestdataPath, "namespace-test.yaml")
		teamAlphaNsPath := filepath.Join(complexTestdataPath, "namespace-team-alpha.yaml")
		teamBetaNsPath := filepath.Join(complexTestdataPath, "namespace-team-beta.yaml")

		for _, nsPath := range []string{testNsPath, teamAlphaNsPath, teamBetaNsPath} {
			cmd := exec.Command("kubectl", "apply", "-f", nsPath)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create namespace from %s", nsPath)
		}

		By("Building the operator image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to build operator image")

		By("Loading the operator image into kind cluster")
		err = utils.LoadImageToKindClusterWithName(projectImage)
		Expect(err).NotTo(HaveOccurred(), "Failed to load image into kind cluster")

		By("Installing auth-operator via Helm")
		imageRepo := strings.Split(projectImage, ":")[0]
		imageTag := strings.Split(projectImage, ":")[1]
		if imageTag == "" {
			imageTag = "latest"
		}

		cmd = exec.Command("helm", "upgrade", "--install", complexRelease, helmChartPath,
			"-n", complexNamespace,
			"--create-namespace",
			"--set", fmt.Sprintf("image.repository=%s", imageRepo),
			"--set", fmt.Sprintf("image.tag=%s", imageTag),
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
			"--wait",
			"--timeout", "5m",
		)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Helm chart")

		By("Waiting for controller and webhook deployments to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", complexNamespace, complexDeployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", complexNamespace, complexDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", complexNamespace, complexDeployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", complexNamespace, complexDeployTimeout)).To(Succeed())

		By("Waiting for controller to be ready")
		Eventually(func() error {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", complexNamespace,
				"-o", "jsonpath={.items[*].status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if !strings.Contains(string(output), "Running") {
				return fmt.Errorf("controller not running: %s", string(output))
			}
			return nil
		}, complexDeployTimeout, complexPollInterval).Should(Succeed())
	})

	AfterAll(func() {
		// Only collect verbose debug info on failure or when E2E_DEBUG_LEVEL >= 2
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Complex E2E AfterAll")
			utils.CollectNamespaceDebugInfo(complexNamespace, "Complex E2E AfterAll")
			utils.CollectOperatorLogs(complexNamespace, 200)
		}

		// Use centralized cleanup
		By("Cleaning up test resources")
		clusterRoles := []string{"complex-filtered-role"}
		clusterRoleBindings := []string{
			"complex-filtered-role",
		}
		CleanupForComplexTests(complexNamespace, clusterRoles, clusterRoleBindings)

		time.Sleep(5 * time.Second)

		By("Uninstalling Helm release")
		cmd := exec.Command("helm", "uninstall", complexRelease, "-n", complexNamespace, "--wait", "--timeout", "2m")
		_, _ = utils.Run(cmd)

		By("Cleaning up test namespaces")
		testNamespaces := []string{
			complexNamespace, "complex-e2e-test-ns",
			"complex-e2e-ns-team-a", "complex-e2e-ns-team-b",
		}
		for _, ns := range testNamespaces {
			cmd = exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}

		By("Cleaning up cluster-scoped resources")
		cmd = exec.Command("kubectl", "delete", "clusterrole",
			"complex-filtered-role", "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding",
			"-l", "app.kubernetes.io/created-by=auth-operator", "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})

	Context("RoleDefinition with ALL restrictions combined", func() {
		It("should create ClusterRole excluding APIs, resources, and verbs", func() {
			By("Applying complex RoleDefinition with all restrictions")
			cmd := exec.Command("kubectl", "apply", "-f",
				filepath.Join(complexTestdataPath, "roledefinition-all-restrictions.yaml"))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "roledefinition", "complex-all-restrictions",
					"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusTrue
			}, complexReconcileTime, complexPollInterval).Should(BeTrue())

			By("Verifying ClusterRole was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrole", "complex-filtered-role")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying excluded API groups are not present")
			cmd = exec.Command("kubectl", "get", "clusterrole", "complex-filtered-role", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var role map[string]interface{}
			err = json.Unmarshal(output, &role)
			Expect(err).NotTo(HaveOccurred())

			rules := role["rules"].([]interface{})
			excludedGroups := []string{"apps", "batch", "autoscaling", "networking.k8s.io", "policy"}
			excludedResources := []string{"secrets", "configmaps", "serviceaccounts", "endpoints"}
			excludedVerbs := []string{"create", "update", "patch", "delete", "deletecollection", "watch"}

			for _, rule := range rules {
				ruleMap := rule.(map[string]interface{})

				// Check API groups
				if apiGroups, ok := ruleMap["apiGroups"].([]interface{}); ok {
					for _, ag := range apiGroups {
						apiGroup := ag.(string)
						for _, excluded := range excludedGroups {
							Expect(apiGroup).NotTo(Equal(excluded),
								"API group %s should be excluded", excluded)
						}
					}
				}

				// Check resources
				if resources, ok := ruleMap["resources"].([]interface{}); ok {
					for _, r := range resources {
						resource := r.(string)
						for _, excluded := range excludedResources {
							Expect(resource).NotTo(Equal(excluded),
								"Resource %s should be excluded", excluded)
						}
					}
				}

				// Check verbs
				if verbs, ok := ruleMap["verbs"].([]interface{}); ok {
					verbStrs := make([]string, 0, len(verbs))
					for _, v := range verbs {
						verbStrs = append(verbStrs, v.(string))
					}
					// If not wildcard, check exclusions
					if !containsString(verbStrs, "*") {
						for _, excluded := range excludedVerbs {
							Expect(verbStrs).NotTo(ContainElement(excluded),
								"Verb %s should be excluded", excluded)
						}
					}
				}
			}

			By("Verifying only 'get' and 'list' verbs are present")
			foundGet := false
			foundList := false
			for _, rule := range rules {
				ruleMap := rule.(map[string]interface{})
				if verbs, ok := ruleMap["verbs"].([]interface{}); ok {
					for _, v := range verbs {
						verb := v.(string)
						if verb == "get" {
							foundGet = true
						}
						if verb == "list" {
							foundList = true
						}
					}
				}
			}
			Expect(foundGet).To(BeTrue(), "get verb should be present")
			Expect(foundList).To(BeTrue(), "list verb should be present")
		})

		It("should create namespaced Role with all restrictions", func() {
			By("Applying complex namespaced RoleDefinition")
			cmd := exec.Command("kubectl", "apply", "-f",
				filepath.Join(complexTestdataPath, "roledefinition-namespaced-all-restrictions.yaml"))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RoleDefinition to be reconciled")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "roledefinition", "complex-ns-all-restrictions",
					"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusTrue
			}, complexReconcileTime, complexPollInterval).Should(BeTrue())

			By("Verifying Role was created in target namespace")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "role", "complex-ns-filtered-role",
					"-n", "complex-e2e-test-ns")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying Role only contains namespaced resources")
			cmd = exec.Command("kubectl", "get", "role", "complex-ns-filtered-role",
				"-n", "complex-e2e-test-ns", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var role map[string]interface{}
			err = json.Unmarshal(output, &role)
			Expect(err).NotTo(HaveOccurred())

			rules := role["rules"].([]interface{})
			// Verify secrets and configmaps are excluded
			for _, rule := range rules {
				ruleMap := rule.(map[string]interface{})
				if resources, ok := ruleMap["resources"].([]interface{}); ok {
					for _, r := range resources {
						resource := r.(string)
						Expect(resource).NotTo(Equal("secrets"))
						Expect(resource).NotTo(Equal("configmaps"))
						Expect(resource).NotTo(Equal("pods/exec"))
						Expect(resource).NotTo(Equal("pods/attach"))
					}
				}
			}
		})
	})

	Context("BindDefinition with multiple roles and namespaces", func() {
		It("should create multiple ClusterRoleBindings from multiple clusterRoleRefs", func() {
			By("Applying complex multi-binding BindDefinition")
			cmd := exec.Command("kubectl", "apply", "-f",
				filepath.Join(complexTestdataPath, "binddefinition-multi-role-multi-ns.yaml"))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BindDefinition to be reconciled")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "binddefinition", "complex-multi-binding",
					"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusTrue
			}, complexReconcileTime, complexPollInterval).Should(BeTrue())

			By("Verifying ClusterRoleBinding for complex-filtered-role was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrolebinding",
					"complex-multi-complex-filtered-role-binding")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying ClusterRoleBinding for view role was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrolebinding",
					"complex-multi-view-binding")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying ClusterRoleBindings have all 4 subjects")
			cmd = exec.Command("kubectl", "get", "clusterrolebinding",
				"complex-multi-complex-filtered-role-binding", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var crb map[string]interface{}
			err = json.Unmarshal(output, &crb)
			Expect(err).NotTo(HaveOccurred())

			subjects := crb["subjects"].([]interface{})
			Expect(subjects).To(HaveLen(4), "Should have 4 subjects (User, Group, 2 ServiceAccounts)")

			// Verify subject types
			subjectKinds := make(map[string]int)
			for _, s := range subjects {
				subjectMap := s.(map[string]interface{})
				kind := subjectMap["kind"].(string)
				subjectKinds[kind]++
			}
			Expect(subjectKinds["User"]).To(Equal(1))
			Expect(subjectKinds["Group"]).To(Equal(1))
			Expect(subjectKinds["ServiceAccount"]).To(Equal(2))
		})

		It("should auto-create ServiceAccounts referenced in subjects", func() {
			By("Verifying ServiceAccount was auto-created in test namespace")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "serviceaccount", "complex-app-sa",
					"-n", "complex-e2e-test-ns")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying ServiceAccount was auto-created in team-a namespace")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "serviceaccount", "complex-worker-sa",
					"-n", "complex-e2e-ns-team-a")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying BindDefinition status shows generated ServiceAccounts")
			cmd := exec.Command("kubectl", "get", "binddefinition", "complex-multi-binding",
				"-o", "jsonpath={.status.generatedServiceAccounts}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("complex-app-sa"))
		})

		It("should create RoleBindings in namespaces matching label selectors", func() {
			By("Verifying RoleBinding was created in team-alpha namespace (matches team=alpha)")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "rolebinding",
					"-n", "complex-e2e-ns-team-a",
					"-l", "app.kubernetes.io/created-by=auth-operator")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if !strings.Contains(string(output), "complex-multi") {
					return fmt.Errorf("RoleBinding not found in team-a namespace")
				}
				return nil
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying RoleBinding was created in test namespace (matches team=alpha AND env=dev)")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "rolebinding",
					"-n", "complex-e2e-test-ns",
					"-l", "app.kubernetes.io/created-by=auth-operator")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if !strings.Contains(string(output), "complex-multi") {
					return fmt.Errorf("RoleBinding not found in test namespace")
				}
				return nil
			}, complexReconcileTime, complexPollInterval).Should(Succeed())
		})

		It("should create RoleBinding for explicit namespace reference", func() {
			By("Verifying RoleBinding for explicit namespace was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "rolebinding",
					"-n", "complex-e2e-test-ns",
					"-o", "jsonpath={.items[*].roleRef.name}")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if !strings.Contains(string(output), "complex-ns-filtered-role") {
					return fmt.Errorf("RoleBinding for explicit namespace not found")
				}
				return nil
			}, complexReconcileTime, complexPollInterval).Should(Succeed())
		})
	})

	Context("BindDefinition with complex namespace selectors", func() {
		It("should handle matchExpressions in namespaceSelector", func() {
			By("Applying BindDefinition with complex namespace selector")
			cmd := exec.Command("kubectl", "apply", "-f",
				filepath.Join(complexTestdataPath, "binddefinition-namespace-selector-complex.yaml"))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for BindDefinition to be reconciled")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "binddefinition", "complex-ns-selector",
					"-o", "jsonpath={.status.conditions[?(@.type=='Created')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusTrue
			}, complexReconcileTime, complexPollInterval).Should(BeTrue())

			By("Verifying RoleBinding was created in staging namespace (matches environment=staging)")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "rolebinding",
					"-n", "complex-e2e-ns-team-b",
					"-l", "app.kubernetes.io/created-by=auth-operator")
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if !strings.Contains(string(output), "complex-ns-select") {
					return fmt.Errorf("RoleBinding not found in team-b namespace")
				}
				return nil
			}, complexReconcileTime, complexPollInterval).Should(Succeed())
		})
	})

	Context("WebhookAuthorizer with all features", func() {
		It("should create WebhookAuthorizer with all features enabled", func() {
			By("Applying full-featured WebhookAuthorizer")
			cmd := exec.Command("kubectl", "apply", "-f",
				filepath.Join(complexTestdataPath, "webhookauthorizer-full-featured.yaml"))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying WebhookAuthorizer was created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "webhookauthorizer", "complex-full-authorizer")
				_, err := utils.Run(cmd)
				return err
			}, complexReconcileTime, complexPollInterval).Should(Succeed())

			By("Verifying WebhookAuthorizer spec is correct")
			cmd = exec.Command("kubectl", "get", "webhookauthorizer", "complex-full-authorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var wa map[string]interface{}
			err = json.Unmarshal(output, &wa)
			Expect(err).NotTo(HaveOccurred())

			spec := wa["spec"].(map[string]interface{})

			// Verify resourceRules
			resourceRules := spec["resourceRules"].([]interface{})
			Expect(resourceRules).To(HaveLen(3), "Should have 3 resourceRules")

			// Verify nonResourceRules
			nonResourceRules := spec["nonResourceRules"].([]interface{})
			Expect(nonResourceRules).To(HaveLen(2), "Should have 2 nonResourceRules")

			// Verify allowedPrincipals
			allowedPrincipals := spec["allowedPrincipals"].([]interface{})
			Expect(allowedPrincipals).To(HaveLen(4), "Should have 4 allowedPrincipals")

			// Verify deniedPrincipals
			deniedPrincipals := spec["deniedPrincipals"].([]interface{})
			Expect(deniedPrincipals).To(HaveLen(3), "Should have 3 deniedPrincipals")

			// Verify namespaceSelector
			nsSelector := spec["namespaceSelector"].(map[string]interface{})
			Expect(nsSelector).To(HaveKey("matchLabels"))
			Expect(nsSelector).To(HaveKey("matchExpressions"))
		})
	})

	Context("Cleanup and Finalizers", func() {
		It("should properly clean up child resources when RoleDefinition is deleted", func() {
			By("Verifying ClusterRole exists")
			cmd := exec.Command("kubectl", "get", "clusterrole", "complex-filtered-role")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting the RoleDefinition")
			cmd = exec.Command("kubectl", "delete", "roledefinition", "complex-all-restrictions")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying ClusterRole was deleted by finalizer")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrole", "complex-filtered-role")
				_, err := utils.Run(cmd)
				if err != nil {
					return nil // Resource not found = success
				}
				return fmt.Errorf("ClusterRole still exists")
			}, complexReconcileTime, complexPollInterval).Should(Succeed())
		})

		It("should properly clean up bindings when BindDefinition is deleted", func() {
			By("Verifying ClusterRoleBindings exist")
			cmd := exec.Command("kubectl", "get", "clusterrolebinding", "complex-multi-view-binding")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting the BindDefinition")
			cmd = exec.Command("kubectl", "delete", "binddefinition", "complex-multi-binding")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying ClusterRoleBindings were deleted by finalizer")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "clusterrolebinding", "complex-multi-view-binding")
				_, err := utils.Run(cmd)
				if err != nil {
					return nil // Resource not found = success
				}
				return fmt.Errorf("ClusterRoleBinding still exists")
			}, complexReconcileTime, complexPollInterval).Should(Succeed())
		})
	})
})

// Helper functions

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func cleanupComplexTestCRDs() {
	// Delete WebhookAuthorizers first
	cmd := exec.Command("kubectl", "delete", "webhookauthorizer", "--all", "--ignore-not-found=true")
	_, _ = utils.Run(cmd)

	// Delete BindDefinitions
	cmd = exec.Command("kubectl", "delete", "binddefinition", "--all", "--ignore-not-found=true")
	_, _ = utils.Run(cmd)

	// Delete RoleDefinitions
	cmd = exec.Command("kubectl", "delete", "roledefinition", "--all", "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}
