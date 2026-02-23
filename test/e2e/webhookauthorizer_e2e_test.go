//go:build e2e

/*
Copyright © 2026 Deutsche Telekom AG.
*/

package e2e

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("WebhookAuthorizer E2E", Ordered, Label("integration"), func() {
	const (
		waNamespace   = "auth-operator-wa-e2e"
		waRelease     = "auth-operator-wa"
		helmChartPath = "chart/auth-operator"
		deployTimeout = 3 * time.Minute
		pollingInt    = 3 * time.Second
		reconcileWait = 30 * time.Second
		testNSLabeled = "wa-e2e-labeled"
		testNSPlain   = "wa-e2e-plain"
	)

	BeforeAll(func() {
		setSuiteOutputDir("webhookauthorizer")

		By("Creating e2e namespaces")
		createNamespaceIfNotExists(waNamespace, nil)
		createNamespaceIfNotExists(testNSLabeled, map[string]string{
			"wa-e2e": "true",
			"env":    "production",
		})
		createNamespaceIfNotExists(testNSPlain, map[string]string{
			"wa-e2e": "true",
		})

		By("Installing auth-operator via Helm for WebhookAuthorizer E2E")
		cmd := exec.CommandContext(context.Background(), "kind", "load", "docker-image",
			projectImage, "--name", kindClusterName)
		_, _ = utils.Run(cmd)

		cmd = exec.CommandContext(context.Background(), "helm", "upgrade", "--install",
			waRelease, helmChartPath,
			"-n", waNamespace,
			"--set", "image.repository=auth-operator",
			"--set", "image.tag=e2e-test",
			"--set", "image.pullPolicy=Never",
			"--wait",
			"--timeout", deployTimeout.String(),
		)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Helm install failed: %s", string(output))
	})

	AfterAll(func() {
		By("Uninstalling auth-operator Helm release")
		cmd := exec.CommandContext(context.Background(), "helm", "uninstall", waRelease, "-n", waNamespace)
		_, _ = utils.Run(cmd)

		By("Cleaning up e2e namespaces")
		for _, ns := range []string{waNamespace, testNSLabeled, testNSPlain} {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		}
	})

	Context("Basic Allow/Deny", func() {
		const waBasicYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-basic
spec:
  allowedPrincipals:
    - user: e2e-allowed-user
  resourceRules:
    - verbs: ["get", "list"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating basic WebhookAuthorizer")
			applyYAML(waBasicYAML)
		})

		AfterAll(func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-basic", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should show WebhookAuthorizer as created", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-basic", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to get WebhookAuthorizer")
			Expect(string(output)).To(ContainSubstring("wa-e2e-basic"))
		})
	})

	Context("NamespaceSelector Filtering", func() {
		const waNSSelectorYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-ns-selector
spec:
  allowedPrincipals:
    - user: e2e-ns-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
  namespaceSelector:
    matchLabels:
      env: production
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer with namespace selector")
			applyYAML(waNSSelectorYAML)
		})

		AfterAll(func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-ns-selector", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should show namespace-scoped WebhookAuthorizer", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-ns-selector", "-o", "jsonpath={.spec.namespaceSelector}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("production"))
		})
	})

	Context("Live Update", func() {
		const waLiveYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-live-update
spec:
  allowedPrincipals:
    - user: e2e-live-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer for live update test")
			applyYAML(waLiveYAML)
		})

		AfterAll(func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-live-update", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should reflect resource changes", func() {
			By("Verifying initial state")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-live-update", "-o", "jsonpath={.spec.allowedPrincipals[0].user}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("e2e-live-user"))

			By("Updating the WebhookAuthorizer to change allowed user")
			patchJSON := `{"spec":{"allowedPrincipals":[{"user":"e2e-updated-user"}]}}`
			cmd = exec.CommandContext(context.Background(), "kubectl", "patch",
				"webhookauthorizer", "wa-e2e-live-update",
				"--type=merge", "-p", patchJSON)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Patch failed: %s", string(output))

			By("Verifying updated state")
			Eventually(func() string {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-live-update",
					"-o", "jsonpath={.spec.allowedPrincipals[0].user}")
				output, _ := utils.Run(cmd)
				return string(output)
			}, reconcileWait, pollingInt).Should(Equal("e2e-updated-user"))
		})
	})

	Context("Multiple WebhookAuthorizers", func() {
		const waMulti1YAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-multi-1
spec:
  allowedPrincipals:
    - user: e2e-multi-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`

		const waMulti2YAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-multi-2
spec:
  deniedPrincipals:
    - user: e2e-multi-user
  resourceRules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating multiple WebhookAuthorizers")
			applyYAML(waMulti1YAML)
			applyYAML(waMulti2YAML)
		})

		AfterAll(func() {
			for _, name := range []string{"wa-e2e-multi-1", "wa-e2e-multi-2"} {
				cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
					"webhookauthorizer", name, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
		})

		It("should list both WebhookAuthorizers", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("wa-e2e-multi-1"))
			Expect(string(output)).To(ContainSubstring("wa-e2e-multi-2"))
		})
	})

	Context("Status Reporting", func() {
		const waStatusYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-status
spec:
  allowedPrincipals:
    - user: e2e-status-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["configmaps"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer for status check")
			applyYAML(waStatusYAML)
		})

		AfterAll(func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-status", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should report status conditions", func() {
			// The controller (if running) should update conditions.
			// This test verifies the CRD supports the status subresource.
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-status", "-o", "json")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				var result map[string]interface{}
				if jsonErr := json.Unmarshal(output, &result); jsonErr != nil {
					return false
				}
				_, hasStatus := result["status"]
				return hasStatus
			}, reconcileWait, pollingInt).Should(BeTrue(), "Expected status field to be present")
		})
	})

	Context("Deletion Cleanup", func() {
		It("should cleanly delete a WebhookAuthorizer", func() {
			waDeleteYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-delete
spec:
  allowedPrincipals:
    - user: e2e-delete-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`
			By("Creating WebhookAuthorizer to delete")
			applyYAML(waDeleteYAML)

			By("Verifying it exists")
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-delete")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting the WebhookAuthorizer")
			cmd = exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-delete", "--timeout=30s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Delete failed: %s", string(output))

			By("Verifying it's gone")
			Eventually(func() bool {
				cmd := exec.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-delete")
				_, err := utils.Run(cmd)
				return err != nil // Should error (NotFound)
			}, reconcileWait, pollingInt).Should(BeTrue())
		})
	})

	Context("NonResourceRules E2E", func() {
		const waNonResourceYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-nonresource
spec:
  allowedPrincipals:
    - user: e2e-health-user
  nonResourceRules:
    - verbs: ["get"]
      nonResourceURLs: ["/healthz", "/readyz"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer with non-resource rules")
			applyYAML(waNonResourceYAML)
		})

		AfterAll(func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-nonresource", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should have non-resource rules in spec", func() {
			cmd := exec.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-nonresource",
				"-o", "jsonpath={.spec.nonResourceRules[0].nonResourceURLs}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("/healthz"))
		})
	})
})
