package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/telekom/auth-operator/test/utils"
)

// CleanupOptions configures cleanup behavior for test resources.
type CleanupOptions struct {
	Namespaces          []string // Namespaces to delete
	ClusterRoles        []string // ClusterRoles to delete (by name)
	ClusterRoleBindings []string // ClusterRoleBindings to delete (by name)
	RemoveCRDs          bool     // Remove all CRs (RoleDefinitions, BindDefinitions, WebhookAuthorizers)
	RemoveFinalizers    bool     // Remove finalizers from CRs before deletion
	WaitForDeletion     bool     // Wait for resources to be fully deleted
	WebhookSelector     string   // Cleanup webhooks matching label selector
}

// CleanupTestResources performs comprehensive cleanup of test resources.
// This function centralizes cleanup logic to avoid duplication across test files.
func CleanupTestResources(opts CleanupOptions) {
	if opts.RemoveFinalizers {
		utils.RemoveFinalizersForAll("roledefinition")
		utils.RemoveFinalizersForAll("binddefinition")
		utils.RemoveFinalizersForAll("webhookauthorizer")
		utils.RemoveFinalizersForAll("restrictedbinddefinition")
		utils.RemoveFinalizersForAll("restrictedroledefinition")
		utils.RemoveFinalizersForAll("rbacpolicy")
	}

	if opts.RemoveCRDs {
		cleanupAllCRDs()
	}

	// Cleanup webhooks BEFORE deleting namespaces — if webhooks are deleted
	// after the operator namespace, the webhook service won't exist and
	// namespace deletion will fail.
	if opts.WebhookSelector != "" {
		utils.CleanupWebhooks(opts.WebhookSelector)
	}
	utils.CleanupAllAuthOperatorWebhooks()

	for _, ns := range opts.Namespaces {
		utils.CleanupNamespace(ns)
	}

	for _, cr := range opts.ClusterRoles {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrole", cr, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
	for _, crb := range opts.ClusterRoleBindings {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "clusterrolebinding", crb, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}

	if opts.WaitForDeletion {
		waitForResourceDeletion(opts)
	}
}

func waitForResourceDeletion(opts CleanupOptions) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resourcesGone(opts) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	remaining := remainingResources(opts)
	_, _ = fmt.Fprintf(os.Stderr, "ERROR: WaitForDeletion deadline reached; remaining resources: %s\n", strings.Join(remaining, ", "))
}

func remainingResources(opts CleanupOptions) []string {
	var remaining []string
	for _, ns := range opts.Namespaces {
		if resourceExists("ns", ns) {
			remaining = append(remaining, "ns/"+ns)
		}
	}
	for _, cr := range opts.ClusterRoles {
		if resourceExists("clusterrole", cr) {
			remaining = append(remaining, "clusterrole/"+cr)
		}
	}
	for _, crb := range opts.ClusterRoleBindings {
		if resourceExists("clusterrolebinding", crb) {
			remaining = append(remaining, "clusterrolebinding/"+crb)
		}
	}
	return remaining
}

func resourcesGone(opts CleanupOptions) bool {
	for _, ns := range opts.Namespaces {
		if resourceExists("ns", ns) {
			return false
		}
	}
	for _, cr := range opts.ClusterRoles {
		if resourceExists("clusterrole", cr) {
			return false
		}
	}
	for _, crb := range opts.ClusterRoleBindings {
		if resourceExists("clusterrolebinding", crb) {
			return false
		}
	}
	return true
}

// #nosec G204 -- resource kind and name are controlled test fixtures, not user input.
func resourceExists(kind, name string) bool {
	attemptCtx, attemptCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer attemptCancel()
	cmd := exec.CommandContext(attemptCtx, "kubectl", "get", kind, name, "--ignore-not-found", "-o", "name")
	out, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: kubectl get %s %s failed: %v\n", kind, name, err)
		return true
	}
	return strings.TrimSpace(string(out)) != ""
}

// cleanupAllCRDs deletes all auth-operator custom resources.
func cleanupAllCRDs() {
	resources := []string{"restrictedbinddefinition", "restrictedroledefinition", "roledefinition", "binddefinition", "webhookauthorizer", "rbacpolicy"}
	for _, resource := range resources {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", resource, "-A", "--all", "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
}

// CleanupForHelmTests provides convenient cleanup for Helm-based tests
// Usage: CleanupForHelmTests(helmNamespace, helmReleaseName, additionalNamespaces...)
func CleanupForHelmTests(namespace, release string, additionalNamespaces ...string) {
	namespaces := make([]string, 0, 1+len(additionalNamespaces))
	namespaces = append(namespaces, namespace)
	namespaces = append(namespaces, additionalNamespaces...)
	CleanupTestResources(CleanupOptions{
		Namespaces:       namespaces,
		RemoveCRDs:       true,
		RemoveFinalizers: true,
		WaitForDeletion:  true,
		WebhookSelector:  "app.kubernetes.io/instance=" + release,
	})
}

// CleanupForDevTests provides convenient cleanup for dev/kustomize tests
// Usage: CleanupForDevTests(devNamespace, []string{"cluster-role-1", "cluster-role-2"}).
func CleanupForDevTests(namespace string, clusterRoles []string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:       []string{namespace},
		ClusterRoles:     clusterRoles,
		RemoveCRDs:       true,
		RemoveFinalizers: true,
		WaitForDeletion:  true,
	})
}

// CleanupForComplexTests provides convenient cleanup for complex scenario tests.
func CleanupForComplexTests(namespace string, clusterRoles, clusterRoleBindings []string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:          []string{namespace},
		ClusterRoles:        clusterRoles,
		ClusterRoleBindings: clusterRoleBindings,
		RemoveCRDs:          true,
		RemoveFinalizers:    true,
		WaitForDeletion:     true,
	})
}

// CleanupForIntegrationTests provides convenient cleanup for integration tests.
func CleanupForIntegrationTests(namespaces, clusterRoles, clusterRoleBindings []string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:          namespaces,
		ClusterRoles:        clusterRoles,
		ClusterRoleBindings: clusterRoleBindings,
		RemoveCRDs:          true,
		RemoveFinalizers:    true,
		WaitForDeletion:     true,
	})
}

// CleanupMinimal performs minimal cleanup (CRDs only, no cluster resources)
// Use when cluster resources should persist.
func CleanupMinimal() {
	CleanupTestResources(CleanupOptions{
		RemoveCRDs:       true,
		RemoveFinalizers: true,
		WaitForDeletion:  true,
	})
}

// CleanupComplete performs complete cleanup (everything)
// Use in AfterAll to ensure clean state.
func CleanupComplete(namespaces, clusterRoles, clusterRoleBindings []string, webhookSelector string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:          namespaces,
		ClusterRoles:        clusterRoles,
		ClusterRoleBindings: clusterRoleBindings,
		RemoveCRDs:          true,
		RemoveFinalizers:    true,
		WaitForDeletion:     true,
		WebhookSelector:     webhookSelector,
	})
}

// CleanupCRDsByName deletes specific CRD instances by name
// Use within tests for cleanup between test cases.
func CleanupCRDsByName(roledefs, binddefs, webhookauthorizers []string) {
	for _, name := range binddefs {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "binddefinition", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
	for _, name := range roledefs {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "roledefinition", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
	for _, name := range webhookauthorizers {
		cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "webhookauthorizer", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
}

// CleanupAllCRDsInNamespace deletes all auth-operator CRDs in a namespace
// Useful for cleaning up after golden tests or when namespace isolation is used.
func CleanupAllCRDsInNamespace(namespace string) {
	resources := []string{"binddefinition", "roledefinition", "webhookauthorizer"}
	for _, resource := range resources {
		if namespace != "" {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", resource, "--all", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		} else {
			cmd := exec.CommandContext(context.Background(), "kubectl", "delete", resource, "--all", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
	}
}

// CleanupAllWebhookAuthorizersClusterWide deletes all WebhookAuthorizers (cluster-scoped).
func CleanupAllWebhookAuthorizersClusterWide() {
	cmd := exec.CommandContext(context.Background(), "kubectl", "delete", "webhookauthorizer", "--all", "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}
