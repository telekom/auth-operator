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
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("Kustomize Overlay Validation", Label("kustomize"), func() {

	Context("Default Overlay", func() {
		It("should build without errors", func() {
			By("Building the default kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/default")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/default")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying essential resources are present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: Deployment"), "Missing Deployment")
			Expect(outputStr).To(ContainSubstring("kind: ServiceAccount"), "Missing ServiceAccount")
			Expect(outputStr).To(ContainSubstring("kind: ClusterRole"), "Missing ClusterRole")
			Expect(outputStr).To(ContainSubstring("kind: ClusterRoleBinding"), "Missing ClusterRoleBinding")
		})

		It("should have valid YAML syntax", func() {
			By("Building and validating YAML")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/default")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-", "--dry-run=client", "-o", "yaml")
			cmd.Stdin = strings.NewReader(string(output))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Invalid YAML in config/default")
		})
	})

	Context("CRD Overlay", func() {
		It("should build without errors", func() {
			By("Building the CRD kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/crd")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/crd")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying CRDs are present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: CustomResourceDefinition"), "Missing CRD")
			Expect(outputStr).To(ContainSubstring("roledefinitions.authorization.t-caas.telekom.com"),
				"Missing RoleDefinition CRD")
			Expect(outputStr).To(ContainSubstring("binddefinitions.authorization.t-caas.telekom.com"),
				"Missing BindDefinition CRD")
			Expect(outputStr).To(ContainSubstring("webhookauthorizers.authorization.t-caas.telekom.com"),
				"Missing WebhookAuthorizer CRD")
		})
	})

	Context("RBAC Overlay", func() {
		It("should build without errors", func() {
			By("Building the RBAC kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/rbac")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/rbac")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying RBAC resources are present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: ClusterRole"), "Missing ClusterRole")
			Expect(outputStr).To(ContainSubstring("kind: ClusterRoleBinding"), "Missing ClusterRoleBinding")
			Expect(outputStr).To(ContainSubstring("kind: ServiceAccount"), "Missing ServiceAccount")
		})
	})

	Context("Manager Overlay", func() {
		It("should build without errors", func() {
			By("Building the manager kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/manager")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/manager")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying Deployment is present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: Deployment"), "Missing Deployment")
		})
	})

	Context("Webhook Overlay", func() {
		It("should build without errors", func() {
			By("Building the webhook kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/webhook")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/webhook")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying webhook resources are present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: Service"), "Missing Service")
		})
	})

	Context("Cert-Manager Overlay", func() {
		It("should build without errors", func() {
			By("Building the cert-manager kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/certmanager")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/certmanager")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying Certificate is present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: Certificate"), "Missing Certificate")
			Expect(outputStr).To(ContainSubstring("kind: Issuer"), "Missing Issuer")
		})
	})

	Context("Prometheus Overlay", func() {
		It("should build without errors", func() {
			By("Building the prometheus kustomize overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/prometheus")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Kustomize build failed for config/prometheus")
			Expect(string(output)).NotTo(BeEmpty())

			By("Verifying ServiceMonitor is present")
			outputStr := string(output)
			Expect(outputStr).To(ContainSubstring("kind: ServiceMonitor"), "Missing ServiceMonitor")
		})
	})

	Context("Manifest Consistency", func() {
		It("should have matching CRD versions across overlays", func() {
			By("Building CRD overlay")
			crdCmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/crd")
			crdOutput, err := utils.Run(crdCmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying v1alpha1 version is present")
			Expect(string(crdOutput)).To(ContainSubstring("v1alpha1"))
		})

		It("should have consistent namespace references", func() {
			By("Building default overlay")
			cmd := exec.CommandContext(context.Background(), "kustomize", "build", "config/default")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying namespace is set consistently")
			Expect(string(output)).To(ContainSubstring("namespace: auth-operator-system"))
		})
	})
})
