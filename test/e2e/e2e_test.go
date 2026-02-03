//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/test/utils"
)

var _ = Describe("Operator Setup", Ordered, Label("setup"), func() {
	BeforeAll(func() {
		setSuiteOutputDir("setup")
	})

	Context("Prerequisites", func() {
		It("should have kubectl available", func() {
			cmd := exec.Command("kubectl", "version", "--client")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Client Version"))
		})

		It("should have kind available", func() {
			cmd := exec.Command("kind", "version")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("kind"))
		})

		It("should have docker available", func() {
			cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have a running kind cluster", func() {
			cmd := exec.Command("kubectl", "cluster-info")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "No Kubernetes cluster available. Run 'make kind-create' first.")
			Expect(string(output)).To(ContainSubstring("Kubernetes"))
		})
	})

	Context("CRDs", func() {
		It("should have RoleDefinition CRD installed", func() {
			cmd := exec.Command("kubectl", "get", "crd", "roledefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			if err != nil {
				Skip("CRDs not installed yet - run 'make install' first")
			}
		})

		It("should have BindDefinition CRD installed", func() {
			cmd := exec.Command("kubectl", "get", "crd", "binddefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			if err != nil {
				Skip("CRDs not installed yet - run 'make install' first")
			}
		})

		It("should have WebhookAuthorizer CRD installed", func() {
			cmd := exec.Command("kubectl", "get", "crd", "webhookauthorizers.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			if err != nil {
				Skip("CRDs not installed yet - run 'make install' first")
			}
		})
	})

	Context("Operator Deployment", func() {
		It("should have the controller-manager deployment", func() {
			cmd := exec.Command("kubectl", "get", "deployment",
				"-l", "control-plane=controller-manager",
				"-n", "auth-operator-system",
				"-o", "name")
			output, err := utils.Run(cmd)
			if err != nil || len(string(output)) == 0 {
				Skip("Operator not deployed yet - run 'make deploy' first")
			}
			Expect(string(output)).To(ContainSubstring("deployment"))
		})

		It("should have controller-manager pod running", func() {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", "auth-operator-system",
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			if err != nil {
				Skip("Operator not deployed yet - run 'make deploy' first")
			}
			Expect(string(output)).To(Equal("Running"))
		})
	})
})

var _ = Describe("API Versions", Label("api"), func() {
	It("should support authorization.t-caas.telekom.com/v1alpha1", func() {
		cmd := exec.Command("kubectl", "api-resources",
			"--api-group=authorization.t-caas.telekom.com",
			"-o", "name")
		output, err := utils.Run(cmd)
		if err != nil {
			Skip("CRDs not installed")
		}
		apiResources := string(output)
		Expect(apiResources).To(ContainSubstring("roledefinitions"))
		Expect(apiResources).To(ContainSubstring("binddefinitions"))
		Expect(apiResources).To(ContainSubstring("webhookauthorizers"))
	})

	It("should have correct short names", func() {
		cmd := exec.Command("kubectl", "api-resources",
			"--api-group=authorization.t-caas.telekom.com",
			"-o", "wide")
		output, err := utils.Run(cmd)
		if err != nil {
			Skip("CRDs not installed")
		}
		apiResources := string(output)
		Expect(apiResources).To(ContainSubstring("roledef"))
		Expect(apiResources).To(ContainSubstring("binddef"))
	})
})

// Debug helper - print cluster state for troubleshooting
var _ = Describe("Debug Info", Label("debug"), func() {
	It("prints comprehensive cluster state", func() {
		By("Collecting full cluster debug info")
		utils.CollectClusterDebugInfo("Manual Debug Run")

		By("Getting operator logs from all known namespaces")
		namespaces := []string{
			"auth-operator-system",
			"auth-operator-helm",
			"auth-operator-ha",
		}
		for _, ns := range namespaces {
			utils.CollectOperatorLogs(ns, 100)
		}

		By("Collecting CRD debug info")
		utils.CollectCRDDebugInfo()

		By("Collecting Docker/container debug info")
		utils.CollectDockerDebugInfo()
	})

	It("prints quick cluster state summary", func() {
		By("Getting all auth-operator resources")
		resources := []string{"roledefinitions", "binddefinitions", "webhookauthorizers"}
		for _, r := range resources {
			cmd := exec.Command("kubectl", "get", r, "-A", "-o", "wide")
			output, _ := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "\n=== %s ===\n%s\n", r, string(output))
		}

		By("Getting operator pods in all namespaces")
		cmd := exec.Command("kubectl", "get", "pods", "-A", "-l", "control-plane", "-o", "wide")
		output, _ := utils.Run(cmd)
		_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Operator Pods ===\n%s\n", string(output))

		By("Getting recent events")
		cmd = exec.Command("kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp", "--field-selector=type!=Normal")
		output, _ = utils.Run(cmd)
		_, _ = fmt.Fprintf(GinkgoWriter, "\n=== Recent Warning/Error Events ===\n%s\n", string(output))
	})

	It("saves debug info to files", func() {
		By("Collecting and saving all debug info")
		utils.CollectAndSaveAllDebugInfo("Debug Test Run")
		_, _ = fmt.Fprintf(GinkgoWriter, "Debug info saved to test/e2e/output/\n")
	})
})
