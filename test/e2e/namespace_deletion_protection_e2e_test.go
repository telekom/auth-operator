//go:build e2e

/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Namespace deletion protection end-to-end tests.
//
// The feature is enforced twice (see chart/auth-operator/templates/
// namespace-deletion-protection-vap.yaml and internal/webhook/authorization/
// namespace_deletion_protection.go):
//
//  1. ValidatingAdmissionPolicy (primary) — rendered by the chart when
//     namespaceDeletionProtection.vap is "auto" (and the cluster supports VAP,
//     which the kind 1.34 e2e clusters do) or "enabled". Runs in-process in the
//     API server for ALL principals, including the cluster-admin identity the
//     e2e kubeconfig authenticates as — so every denial below also proves
//     there is no admin bypass.
//  2. Namespace validating webhook (fallback) — only registered when
//     namespaceAdmission.enabled=true, which no e2e suite installs live (the
//     cluster-wide Namespace webhooks would enforce T-CaaS ownership on every
//     namespace operation in the shared cluster and interfere with sibling
//     suites' fixtures and cleanup). The webhook enforcement path is covered
//     by unit tests in
//     internal/webhook/authorization/namespace_deletion_protection_test.go.
//
// Like the constrained impersonation suite, this suite owns its Helm release
// outright: it installs auth-operator into a dedicated namespace and
// unconditionally uninstalls it in AfterAll so the cluster-scoped VAP never
// leaks into other specs.
var _ = Describe("Namespace Deletion Protection", Ordered, Label("helm", "namespace-deletion-protection"), func() {
	const (
		nsdpRelease    = "auth-operator-nsdp"
		nsdpOperatorNS = "auth-operator-nsdp"
		nsdpChartPath  = "chart/auth-operator"

		// Release name contains the chart name, so auth-operator.fullname
		// resolves to the release name (see chart/_helpers.tpl).
		nsdpVAPName = nsdpRelease + "-namespace-deletion-protection"

		// Test namespaces created by this suite.
		nsdpOptInNS       = "e2e-nsdp-opt-in"
		nsdpPlatformNS    = "e2e-nsdp-platform"
		nsdpVAPDisabledNS = "e2e-nsdp-vap-disabled"

		// Label/annotation keys under test.
		nsdpOwnerLabel           = "t-caas.telekom.com/owner"
		nsdpProtectionLabel      = "t-caas.telekom.com/deletion-protection"
		nsdpAllowDeletionKey     = "t-caas.telekom.com/allow-deletion"
		nsdpProtectedMsgFragment = "is deletion-protected; annotate it with"
		nsdpSystemMsgFragment    = "protected system namespace"

		nsdpPollInterval = 3 * time.Second
	)

	// allTestNamespaces enumerates every namespace this suite may create, for
	// defensive cleanup. A protected namespace without the allow-deletion
	// annotation CANNOT be deleted while the VAP exists, so cleanup must
	// annotate first (or run after the release, and with it the VAP, is gone).
	allTestNamespaces := []string{nsdpOptInNS, nsdpPlatformNS, nsdpVAPDisabledNS}

	// nsdpHelmArgs builds the helm upgrade --install argument list with the
	// values this suite installs by default (chart defaults for
	// namespaceDeletionProtection: enabled=true, vap=auto), plus any overrides.
	nsdpHelmArgs := func(extra ...string) []string {
		args := append([]string{"upgrade", "--install", nsdpRelease, nsdpChartPath,
			"-n", nsdpOperatorNS,
			"--create-namespace"},
			imageSetArgs()...,
		)
		args = append(args,
			"--set", "controller.replicas=1",
			"--set", "webhookServer.replicas=1",
		)
		args = append(args, extra...)
		args = append(args, "--wait", "--timeout", "5m")
		return args
	}

	// attemptNamespaceDelete tries to delete a namespace and returns the
	// combined kubectl output and error. --wait=false so a successful delete
	// does not block on finalizers.
	attemptNamespaceDelete := func(name string, extraArgs ...string) (string, error) {
		args := append([]string{"delete", "namespace", name, "--wait=false"}, extraArgs...)
		cmd := utils.CommandContext(context.Background(), "kubectl", args...) // #nosec G204
		output, err := utils.Run(cmd)
		return string(output), err
	}

	// annotateAllowDeletion sets the escape-hatch annotation on a namespace.
	annotateAllowDeletion := func(name string) error {
		cmd := utils.CommandContext(context.Background(), "kubectl", "annotate", "ns", name, // #nosec G204
			fmt.Sprintf("%s=true", nsdpAllowDeletionKey), "--overwrite")
		_, err := utils.Run(cmd)
		return err
	}

	// deleteVAPObjects removes the ValidatingAdmissionPolicy and its binding
	// directly, as a defensive fallback for when a previous crashed run leaked
	// them (a leaked VAP would otherwise make leaked protected namespaces
	// undeletable).
	deleteVAPObjects := func() {
		for _, kind := range []string{"validatingadmissionpolicybinding", "validatingadmissionpolicy"} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", kind, nsdpVAPName, // #nosec G204
				"--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		}
	}

	BeforeAll(func() {
		setSuiteOutputDir("namespace-deletion-protection")

		By("Cleaning up leftovers from previous runs")
		cmd := utils.CommandContext(context.Background(), "helm", "uninstall", nsdpRelease, "-n", nsdpOperatorNS) // #nosec G204
		_, _ = utils.Run(cmd)
		deleteVAPObjects()
		for _, ns := range allTestNamespaces {
			_ = annotateAllowDeletion(ns) // best effort; namespace may not exist
			utils.CleanupNamespace(ns)
		}

		By("Loading the operator image into the kind cluster")
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())

		By("Installing auth-operator via Helm with default deletion protection values")
		// Chart defaults: namespaceDeletionProtection.enabled=true, vap=auto.
		// The live kind 1.34 API server advertises
		// admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy, so "auto"
		// renders the VAP. namespaceAdmission stays disabled (chart default),
		// so no Namespace webhooks are registered.
		installCmd := utils.CommandContext(context.Background(), "helm", nsdpHelmArgs()...) // #nosec G204
		output, err := utils.Run(installCmd)
		Expect(err).NotTo(HaveOccurred(), "Helm install failed: %s", string(output))

		By("Waiting for the operator deployments to become available")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", nsdpOperatorNS, deployTimeout)).To(Succeed())
		Expect(utils.WaitForDeploymentAvailable("control-plane=webhook-server", nsdpOperatorNS, deployTimeout)).To(Succeed())
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info (test failed or debug enabled)")
			utils.CollectAndSaveAllDebugInfo("Namespace Deletion Protection AfterAll")
			utils.CollectOperatorLogs(nsdpOperatorNS, 200)
		}

		// Annotate the escape hatch on every test namespace FIRST, while the
		// VAP may still exist: a protected namespace without the annotation
		// cannot be deleted, so plain cleanup would hang or fail.
		By("Annotating test namespaces with the allow-deletion escape hatch")
		for _, ns := range allTestNamespaces {
			_ = annotateAllowDeletion(ns) // best effort; namespace may already be gone
		}

		// The Helm release is owned by THIS suite and its VAP is cluster
		// scoped: leaving it behind would deny namespace deletions performed
		// by other suites' cleanup. The uninstall is therefore unconditional
		// (same reasoning as the constrained impersonation suite).
		By("Uninstalling the Helm release")
		cmd := utils.CommandContext(context.Background(), "helm", "uninstall", nsdpRelease, "-n", nsdpOperatorNS, "--wait", "--timeout", "2m") // #nosec G204
		_, _ = utils.Run(cmd)
		Expect(utils.WaitForDeploymentGone("control-plane=controller-manager", nsdpOperatorNS, deployTimeout)).To(Succeed(),
			"the namespace deletion protection operator must be gone before later specs run")

		By("Removing any leftover ValidatingAdmissionPolicy objects")
		deleteVAPObjects()

		By("Cleaning up test namespaces")
		for _, ns := range allTestNamespaces {
			utils.CleanupNamespace(ns)
		}
		utils.CleanupNamespace(nsdpOperatorNS)
	})

	Context("ValidatingAdmissionPolicy enforcement (vap=auto on a VAP-capable cluster)", func() {
		It("should install the ValidatingAdmissionPolicy and its binding", func() {
			By("Checking the ValidatingAdmissionPolicy exists")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "validatingadmissionpolicy", nsdpVAPName) // #nosec G204
				_, err := utils.Run(cmd)
				return err
			}, shortTimeout, nsdpPollInterval).Should(Succeed())

			By("Checking the ValidatingAdmissionPolicyBinding exists and denies")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "validatingadmissionpolicybinding", nsdpVAPName, // #nosec G204
				"-o", "jsonpath={.spec.validationActions}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Deny"))
		})

		It("should hard-block deletion of system namespaces with no annotation escape hatch", func() {
			// --dry-run=server exercises the full admission chain (VAPs run for
			// dry-run requests) without ever risking actual deletion of a
			// system namespace. This also serves as the policy-activation
			// barrier for the following specs: once the API server enforces
			// here, the compiled policy is live.
			By("Attempting a server-side dry-run deletion of kube-node-lease")
			Eventually(func() error {
				output, err := attemptNamespaceDelete("kube-node-lease", "--dry-run=server")
				if err == nil {
					return fmt.Errorf("dry-run deletion of kube-node-lease was unexpectedly allowed: %s", output)
				}
				if !strings.Contains(output, nsdpSystemMsgFragment) {
					return fmt.Errorf("expected %q in denial, got: %s", nsdpSystemMsgFragment, output)
				}
				return nil
			}, shortTimeout, nsdpPollInterval).Should(Succeed(),
				"system namespaces must be hard-protected even for cluster-admin")

			By("Verifying kube-node-lease still exists")
			Expect(resourceExists("ns", "kube-node-lease")).To(BeTrue())
		})

		It("should deny deleting an opted-in namespace until the allow-deletion annotation is set", func() {
			By("Creating a namespace opted into deletion protection via label")
			createNamespaceIfNotExists(nsdpOptInNS, map[string]string{
				nsdpProtectionLabel: "enabled",
			})

			By("Attempting to delete the namespace without the annotation")
			output, err := attemptNamespaceDelete(nsdpOptInNS)
			Expect(err).To(HaveOccurred(), "deletion of a protected namespace must be denied, got: %s", output)
			Expect(output).To(ContainSubstring(nsdpProtectedMsgFragment))
			Expect(output).To(ContainSubstring(nsdpAllowDeletionKey))

			By("Verifying the namespace still exists")
			Expect(resourceExists("ns", nsdpOptInNS)).To(BeTrue())

			By("Setting the allow-deletion annotation")
			Expect(annotateAllowDeletion(nsdpOptInNS)).To(Succeed())

			By("Deleting the namespace with the annotation in place")
			output, err = attemptNamespaceDelete(nsdpOptInNS)
			Expect(err).NotTo(HaveOccurred(), "annotated namespace deletion should succeed: %s", output)

			By("Waiting for the namespace to be fully removed")
			Eventually(func() bool {
				return resourceExists("ns", nsdpOptInNS)
			}, shortTimeout, nsdpPollInterval).Should(BeFalse())
		})

		It("should deny deleting a platform-owned namespace without the annotation", func() {
			By("Creating a platform-owned namespace")
			// namespaceAdmission.enabled=false in this install (chart default),
			// so no Namespace webhooks restrict creating a namespace with the
			// platform owner label; this matches how the integration suite
			// creates labeled namespace fixtures.
			createNamespaceIfNotExists(nsdpPlatformNS, map[string]string{
				nsdpOwnerLabel: "platform",
			})

			By("Attempting to delete the platform-owned namespace")
			output, err := attemptNamespaceDelete(nsdpPlatformNS)
			Expect(err).To(HaveOccurred(), "deletion of a platform-owned namespace must be denied, got: %s", output)
			Expect(output).To(ContainSubstring(nsdpProtectedMsgFragment))

			By("Verifying the namespace still exists")
			Expect(resourceExists("ns", nsdpPlatformNS)).To(BeTrue())
			// Deliberately left in place without the annotation; AfterAll
			// annotates it before deleting to prove the cleanup path works
			// against a protected namespace.
		})
	})

	Context("Webhook fallback configuration (vap=disabled)", func() {
		AfterAll(func() {
			// ALWAYS restore the original install values (vap back to the
			// chart default "auto") so the earlier VAP-backed state is
			// re-established for anything running after this context,
			// including this suite's own AfterAll cleanup expectations.
			By("Restoring the original Helm values (vap=auto)")
			cmd := utils.CommandContext(context.Background(), "helm", nsdpHelmArgs()...) // #nosec G204
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Helm restore upgrade failed: %s", string(output))

			By("Verifying the ValidatingAdmissionPolicy is back")
			Eventually(func() error {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "validatingadmissionpolicy", nsdpVAPName) // #nosec G204
				_, err := utils.Run(cmd)
				return err
			}, shortTimeout, nsdpPollInterval).Should(Succeed())
		})

		It("should remove the ValidatingAdmissionPolicy when vap=disabled", func() {
			By("Upgrading the release with namespaceDeletionProtection.vap=disabled")
			upgradeCmd := utils.CommandContext(context.Background(), "helm", // #nosec G204
				nsdpHelmArgs("--set", "namespaceDeletionProtection.vap=disabled")...)
			output, err := utils.Run(upgradeCmd)
			Expect(err).NotTo(HaveOccurred(), "Helm vap=disabled upgrade failed: %s", string(output))

			By("Verifying the ValidatingAdmissionPolicy object is gone")
			Eventually(func() bool {
				return resourceExists("validatingadmissionpolicy", nsdpVAPName)
			}, shortTimeout, nsdpPollInterval).Should(BeFalse())
			Expect(resourceExists("validatingadmissionpolicybinding", nsdpVAPName)).To(BeFalse())
		})

		It("should not enforce deletion protection without the VAP when the namespace webhook is not installed", func() {
			// With vap=disabled the fallback enforcement point is the
			// Namespace validating webhook, which requires
			// namespaceAdmission.enabled=true. No e2e suite installs those
			// cluster-wide Namespace webhooks live (they would enforce T-CaaS
			// namespace ownership on every namespace operation in the shared
			// cluster and break sibling suites' fixtures and cleanup), so the
			// webhook-side deny/annotate/allow behaviour is covered by unit
			// tests in
			// internal/webhook/authorization/namespace_deletion_protection_test.go.
			//
			// What CAN be proven here: with the VAP removed and no namespace
			// webhook registered, a protected namespace deletes freely —
			// demonstrating both that the vap=disabled upgrade took effect and
			// that the denials in the previous context really came from the VAP.
			By("Creating a namespace opted into deletion protection via label")
			createNamespaceIfNotExists(nsdpVAPDisabledNS, map[string]string{
				nsdpProtectionLabel: "enabled",
			})

			By("Deleting it without the allow-deletion annotation")
			output, err := attemptNamespaceDelete(nsdpVAPDisabledNS)
			Expect(err).NotTo(HaveOccurred(),
				"without VAP and namespace webhook, deletion must not be blocked: %s", output)

			By("Waiting for the namespace to be fully removed")
			Eventually(func() bool {
				return resourceExists("ns", nsdpVAPDisabledNS)
			}, shortTimeout, nsdpPollInterval).Should(BeFalse())
		})
	})
})
