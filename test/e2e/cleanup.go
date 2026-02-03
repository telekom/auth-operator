package e2e

import (
	"os/exec"
	"time"

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/test/utils"
)

// CleanupOptions configures cleanup behavior for test resources
type CleanupOptions struct {
	Namespaces          []string // Namespaces to delete
	ClusterRoles        []string // ClusterRoles to delete (by name)
	ClusterRoleBindings []string // ClusterRoleBindings to delete (by name)
	RemoveCRDs          bool     // Remove all CRs (RoleDefinitions, BindDefinitions, WebhookAuthorizers)
	RemoveFinalizers    bool     // Remove finalizers from CRs before deletion
	WaitForDeletion     bool     // Wait for resources to be fully deleted
	WebhookSelector     string   // Cleanup webhooks matching label selector
}

// CleanupTestResources performs comprehensive cleanup of test resources
// This function centralizes cleanup logic to avoid duplication across test files
func CleanupTestResources(opts CleanupOptions) {
	// Step 1: Remove finalizers if requested (prevents stuck deletions)
	if opts.RemoveFinalizers {
		utils.RemoveFinalizersForAll("roledefinition")
		utils.RemoveFinalizersForAll("binddefinition")
		utils.RemoveFinalizersForAll("webhookauthorizer")
	}

	// Step 2: Delete CRs first (before operator teardown)
	if opts.RemoveCRDs {
		cleanupAllCRDs()
	}

	// Step 3: Cleanup webhooks BEFORE deleting namespaces
	// This is critical - if webhooks are deleted after the operator namespace,
	// the webhook service won't exist and namespace deletion will fail
	if opts.WebhookSelector != "" {
		utils.CleanupWebhooks(opts.WebhookSelector)
	}
	utils.CleanupAllAuthOperatorWebhooks()

	// Step 4: Delete namespaces (now safe since webhooks are gone)
	for _, ns := range opts.Namespaces {
		utils.CleanupNamespace(ns)
	}

	// Step 5: Delete cluster-scoped resources
	for _, cr := range opts.ClusterRoles {
		cmd := exec.Command("kubectl", "delete", "clusterrole", cr, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}

	for _, crb := range opts.ClusterRoleBindings {
		cmd := exec.Command("kubectl", "delete", "clusterrolebinding", crb, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}

	// Step 6: Wait for deletion to complete
	if opts.WaitForDeletion {
		time.Sleep(5 * time.Second)
	}
}

// cleanupAllCRDs deletes all auth-operator custom resources
func cleanupAllCRDs() {
	resources := []string{"roledefinition", "binddefinition", "webhookauthorizer"}
	for _, resource := range resources {
		cmd := exec.Command("kubectl", "delete", resource, "-A", "--all", "--ignore-not-found=true")
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
// Usage: CleanupForDevTests(devNamespace, []string{"cluster-role-1", "cluster-role-2"})
func CleanupForDevTests(namespace string, clusterRoles []string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:       []string{namespace},
		ClusterRoles:     clusterRoles,
		RemoveCRDs:       true,
		RemoveFinalizers: true,
		WaitForDeletion:  true,
	})
}

// CleanupForComplexTests provides convenient cleanup for complex scenario tests
func CleanupForComplexTests(namespace string, clusterRoles []string, clusterRoleBindings []string) {
	CleanupTestResources(CleanupOptions{
		Namespaces:          []string{namespace},
		ClusterRoles:        clusterRoles,
		ClusterRoleBindings: clusterRoleBindings,
		RemoveCRDs:          true,
		RemoveFinalizers:    true,
		WaitForDeletion:     true,
	})
}

// CleanupForIntegrationTests provides convenient cleanup for integration tests
func CleanupForIntegrationTests(namespaces []string, clusterRoles []string, clusterRoleBindings []string) {
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
// Use when cluster resources should persist
func CleanupMinimal() {
	CleanupTestResources(CleanupOptions{
		RemoveCRDs:       true,
		RemoveFinalizers: true,
		WaitForDeletion:  true,
	})
}

// CleanupComplete performs complete cleanup (everything)
// Use in AfterAll to ensure clean state
func CleanupComplete(namespaces []string, clusterRoles []string, clusterRoleBindings []string, webhookSelector string) {
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
// Use within tests for cleanup between test cases
func CleanupCRDsByName(roledefs, binddefs, webhookauthorizers []string) {
	for _, name := range binddefs {
		cmd := exec.Command("kubectl", "delete", "binddefinition", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
	for _, name := range roledefs {
		cmd := exec.Command("kubectl", "delete", "roledefinition", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
	for _, name := range webhookauthorizers {
		cmd := exec.Command("kubectl", "delete", "webhookauthorizer", name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
}

// CleanupAllCRDsInNamespace deletes all auth-operator CRDs in a namespace
// Useful for cleaning up after golden tests or when namespace isolation is used
func CleanupAllCRDsInNamespace(namespace string) {
	resources := []string{"binddefinition", "roledefinition", "webhookauthorizer"}
	for _, resource := range resources {
		if namespace != "" {
			cmd := exec.Command("kubectl", "delete", resource, "--all", "-n", namespace, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		} else {
			cmd := exec.Command("kubectl", "delete", resource, "--all", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
	}
}

// CleanupAllWebhookAuthorizersClusterWide deletes all WebhookAuthorizers (cluster-scoped)
func CleanupAllWebhookAuthorizersClusterWide() {
	cmd := exec.Command("kubectl", "delete", "webhookauthorizer", "--all", "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}
