package e2e

import (
	"fmt"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Run e2e tests using the Ginkgo runner.
func TestE2E(t *testing.T) {
	isCI := os.Getenv("CI")
	if isCI == "true" {
		t.Skip("Skipping E2E tests in CI")
	}
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting auth-operator suite\n")
	RunSpecs(t, "e2e suite")
}
