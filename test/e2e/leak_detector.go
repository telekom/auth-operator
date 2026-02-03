package e2e

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/test/utils"
)

// ResourceSnapshot captures cluster state at a point in time
type ResourceSnapshot struct {
	Namespaces          []string
	ClusterRoles        []string
	ClusterRoleBindings []string
	RoleDefinitions     []string
	BindDefinitions     []string
	WebhookAuthorizers  []string
	ValidatingWebhooks  []string
	MutatingWebhooks    []string
}

// TakeSnapshot captures current cluster state for leak detection
func TakeSnapshot() (*ResourceSnapshot, error) {
	snapshot := &ResourceSnapshot{}

	// Capture namespaces (excluding system namespaces)
	cmd := exec.Command("kubectl", "get", "ns", "-o", "jsonpath={.items[*].metadata.name}")
	output, err := utils.Run(cmd)
	if err == nil {
		allNS := strings.Fields(string(output))
		// Filter out system namespaces
		systemNS := map[string]bool{
			"default": true, "kube-system": true, "kube-public": true,
			"kube-node-lease": true, "local-path-storage": true,
		}
		for _, ns := range allNS {
			if !systemNS[ns] {
				snapshot.Namespaces = append(snapshot.Namespaces, ns)
			}
		}
	}

	// Capture ClusterRoles (only auth-operator created)
	cmd = exec.Command("kubectl", "get", "clusterroles",
		"-l", "app.kubernetes.io/created-by=auth-operator",
		"-o", "jsonpath={.items[*].metadata.name}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.ClusterRoles = strings.Fields(string(output))
	}

	// Capture ClusterRoleBindings (only auth-operator created)
	cmd = exec.Command("kubectl", "get", "clusterrolebindings",
		"-l", "app.kubernetes.io/created-by=auth-operator",
		"-o", "jsonpath={.items[*].metadata.name}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.ClusterRoleBindings = strings.Fields(string(output))
	}

	// Capture RoleDefinitions
	cmd = exec.Command("kubectl", "get", "roledefinitions", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\" \"}{end}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.RoleDefinitions = strings.Fields(string(output))
	}

	// Capture BindDefinitions
	cmd = exec.Command("kubectl", "get", "binddefinitions", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\" \"}{end}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.BindDefinitions = strings.Fields(string(output))
	}

	// Capture WebhookAuthorizers
	cmd = exec.Command("kubectl", "get", "webhookauthorizers", "-A",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\" \"}{end}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.WebhookAuthorizers = strings.Fields(string(output))
	}

	// Capture ValidatingWebhookConfigurations (auth-operator related)
	cmd = exec.Command("kubectl", "get", "validatingwebhookconfigurations",
		"-o", "jsonpath={.items[?(@.metadata.name=~\".*auth-operator.*\")].metadata.name}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.ValidatingWebhooks = strings.Fields(string(output))
	}

	// Capture MutatingWebhookConfigurations (auth-operator related)
	cmd = exec.Command("kubectl", "get", "mutatingwebhookconfigurations",
		"-o", "jsonpath={.items[?(@.metadata.name=~\".*auth-operator.*\")].metadata.name}")
	output, err = utils.Run(cmd)
	if err == nil {
		snapshot.MutatingWebhooks = strings.Fields(string(output))
	}

	return snapshot, nil
}

// DetectLeaks compares two snapshots and returns detected leaks
func DetectLeaks(before, after *ResourceSnapshot) []string {
	leaks := []string{}

	// Check for new namespaces
	newNS := difference(after.Namespaces, before.Namespaces)
	if len(newNS) > 0 {
		leaks = append(leaks, fmt.Sprintf("Leaked namespaces: %v", newNS))
	}

	// Check for new ClusterRoles
	newCR := difference(after.ClusterRoles, before.ClusterRoles)
	if len(newCR) > 0 {
		leaks = append(leaks, fmt.Sprintf("Leaked ClusterRoles: %v", newCR))
	}

	// Check for new ClusterRoleBindings
	newCRB := difference(after.ClusterRoleBindings, before.ClusterRoleBindings)
	if len(newCRB) > 0 {
		leaks = append(leaks, fmt.Sprintf("Leaked ClusterRoleBindings: %v", newCRB))
	}

	// Check for remaining RoleDefinitions (should be 0 after cleanup)
	if len(after.RoleDefinitions) > 0 {
		leaked := difference(after.RoleDefinitions, before.RoleDefinitions)
		if len(leaked) > 0 {
			leaks = append(leaks, fmt.Sprintf("Remaining RoleDefinitions (%d): %v",
				len(leaked), leaked))
		}
	}

	// Check for remaining BindDefinitions
	if len(after.BindDefinitions) > 0 {
		leaked := difference(after.BindDefinitions, before.BindDefinitions)
		if len(leaked) > 0 {
			leaks = append(leaks, fmt.Sprintf("Remaining BindDefinitions (%d): %v",
				len(leaked), leaked))
		}
	}

	// Check for remaining WebhookAuthorizers
	if len(after.WebhookAuthorizers) > 0 {
		leaked := difference(after.WebhookAuthorizers, before.WebhookAuthorizers)
		if len(leaked) > 0 {
			leaks = append(leaks, fmt.Sprintf("Remaining WebhookAuthorizers (%d): %v",
				len(leaked), leaked))
		}
	}

	// Check for remaining webhooks
	newVWH := difference(after.ValidatingWebhooks, before.ValidatingWebhooks)
	if len(newVWH) > 0 {
		leaks = append(leaks, fmt.Sprintf("Remaining validating webhooks: %v", newVWH))
	}

	newMWH := difference(after.MutatingWebhooks, before.MutatingWebhooks)
	if len(newMWH) > 0 {
		leaks = append(leaks, fmt.Sprintf("Remaining mutating webhooks: %v", newMWH))
	}

	return leaks
}

// PrintLeakReport prints a formatted leak report
func PrintLeakReport(leaks []string) {
	w := ginkgo.GinkgoWriter
	if len(leaks) == 0 {
		_, _ = fmt.Fprintf(w, "\n")
		_, _ = fmt.Fprintf(w, "╔═══════════════════════════════════════════════════════════════════════╗\n")
		_, _ = fmt.Fprintf(w, "║ ✓ NO RESOURCE LEAKS DETECTED                                         ║\n")
		_, _ = fmt.Fprintf(w, "║   All test resources were properly cleaned up.                       ║\n")
		_, _ = fmt.Fprintf(w, "╚═══════════════════════════════════════════════════════════════════════╝\n\n")
		return
	}

	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(w, "╔═══════════════════════════════════════════════════════════════════════╗\n")
	_, _ = fmt.Fprintf(w, "║ ⚠️  RESOURCE LEAKS DETECTED                                            ║\n")
	_, _ = fmt.Fprintf(w, "╠═══════════════════════════════════════════════════════════════════════╣\n")

	for _, leak := range leaks {
		// Wrap long leak messages
		maxWidth := 69
		if len(leak) <= maxWidth {
			_, _ = fmt.Fprintf(w, "║ • %-67s ║\n", leak)
		} else {
			// Split long messages
			words := strings.Fields(leak)
			line := "• "
			for _, word := range words {
				if len(line)+len(word)+1 > maxWidth {
					_, _ = fmt.Fprintf(w, "║ %-69s ║\n", line)
					line = "  " + word + " "
				} else {
					line += word + " "
				}
			}
			if len(line) > 0 {
				_, _ = fmt.Fprintf(w, "║ %-69s ║\n", strings.TrimSpace(line))
			}
		}
	}

	_, _ = fmt.Fprintf(w, "╠═══════════════════════════════════════════════════════════════════════╣\n")
	_, _ = fmt.Fprintf(w, "║ Recommendation: Review AfterAll cleanup logic to ensure all          ║\n")
	_, _ = fmt.Fprintf(w, "║ resources are properly deleted. Leaks may affect subsequent tests.   ║\n")
	_, _ = fmt.Fprintf(w, "╚═══════════════════════════════════════════════════════════════════════╝\n\n")
}

// difference returns elements in 'a' that are not in 'b'
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}
