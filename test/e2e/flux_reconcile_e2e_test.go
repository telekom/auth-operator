//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

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

// End-to-end reproduction of the production failure through Flux itself.
//
// The companion suite in flux_tenant_rbac_e2e_test.go proves the authorization
// property directly against the apiserver. This suite proves that the property
// actually manifests as the reported Flux error, for both reconcilers:
//
//	kustomize-controller -> OCIRepository  -> Kustomization  -> ConfigMap
//	helm-controller      -> HelmRepository -> HelmRelease    -> ConfigMap
//
// Both use spec.serviceAccountName, and both source from OCI artifacts served by
// the in-cluster registry, so nothing here depends on an external git host.
//
// The failure mode is reproduced by stripping the implicit
// system:discovery -> system:authenticated binding for the duration of a spec.
// That is the only way to make the production symptom appear in a stock kind
// cluster, because kube-apiserver ships that binding enabled and it is what
// masked the missing grant in the first place. The binding carries
// rbac.authorization.k8s.io/autoupdate: "true", so the apiserver restores it on
// restart; specs that remove it always restore it themselves.

const (
	fluxOCIRepoName  = "e2e-tenant-kustomize"
	fluxHelmRepoName = "e2e-tenant-charts"
	fluxKsName       = "e2e-tenant-ks"
	fluxHRName       = "e2e-tenant-hr"

	// The stable fragment of the production error. Deliberately not "unknown":
	// that word is a client-go artifact for a discarded non-text response body and
	// carries no diagnostic meaning.
	fluxDiscoveryFailureFragment = "server groups"

	fluxSourceReadyTimeout = 2 * time.Minute

	// JSONPath expressions for the Ready condition, shared by the wait helper and
	// the failure-message assertions.
	fluxReadyStatusPath  = `{.status.conditions[?(@.type=="Ready")].status}`
	fluxReadyMessagePath = `{.status.conditions[?(@.type=="Ready")].message}`
)

var _ = Describe("Flux reconciliation with tenant impersonation", Ordered, Label("flux-rbac"), func() {
	BeforeAll(func() {
		setSuiteOutputDir("flux-reconcile")
		skipUnlessWorkloadMode()

		By("Verifying Flux CRDs are present")
		for _, crd := range []string{
			"ocirepositories.source.toolkit.fluxcd.io",
			"helmrepositories.source.toolkit.fluxcd.io",
			"kustomizations.kustomize.toolkit.fluxcd.io",
			"helmreleases.helm.toolkit.fluxcd.io",
		} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "crd", crd, "-o", "name")
			if _, err := utils.Run(cmd); err != nil {
				Skip("Flux CRDs not installed. Run: make test-e2e-flux-rbac")
			}
		}

		By("Applying both candidate fixes so the happy-path specs can reconcile")
		// A tenant object that sets spec.serviceAccountName needs the controller
		// identity to hold BOTH the impersonate verb (Defect A) and, for the
		// impersonated identity, API discovery (Defect B). The specs that reproduce
		// each failure remove the relevant grant for their own duration.
		applyFluxRBACImpersonateGrant()
		applyFluxRBACDiscoveryGrant()

		By("Creating the OCI sources")
		createFluxOCISources()
	})

	AfterAll(func() {
		By("Deleting Flux objects")
		deleteFluxTestObjects()

		By("Removing the candidate fixes")
		removeFluxRBACImpersonateGrant()
		removeFluxRBACDiscoveryGrant()
	})

	//--------------------------------------------------------------------------
	// Sources must be healthy, otherwise a later failure proves nothing.
	//--------------------------------------------------------------------------
	Context("OCI sources", func() {
		It("reconciles the OCIRepository to Ready", func() {
			waitForFluxReady("ocirepository", fluxOCIRepoName, fluxSourceReadyTimeout)
		})

		It("reconciles the HelmRepository to Ready", func() {
			waitForFluxReady("helmrepository", fluxHelmRepoName, fluxSourceReadyTimeout)
		})
	})

	//--------------------------------------------------------------------------
	// The reproduction, per controller.
	//--------------------------------------------------------------------------
	Context("kustomize-controller", func() {
		It("reconciles a Kustomization that impersonates the tenant ServiceAccount", func() {
			createFluxKustomization(fluxKsName, fluxRBACTenantNS, fluxRBACServiceAcct)
			DeferCleanup(func() {
				deleteFluxObject("kustomization", fluxKsName, fluxRBACTenantNS)
			})

			waitForFluxReady("kustomization", fluxKsName, fluxRBACReconcileTimeout)

			By("Verifying the ConfigMap was actually applied")
			Eventually(func() error {
				return checkResourceExists("configmap", "e2e-tenant-values", fluxRBACTenantNS)
			}, fluxRBACReconcileTimeout, fluxRBACPollInterval).Should(Succeed())
		})

		It("fails the dry-run with 'server groups' when the controller cannot impersonate", func() {
			// Reproduces the production symptom via its actual cause: the controller
			// identity holds no impersonate verb, so the impersonated client is
			// refused, and discovery is the first call it makes. No cluster surgery
			// is needed - this is simply the shipped configuration.
			removeFluxRBACImpersonateGrant()
			DeferCleanup(applyFluxRBACImpersonateGrant)

			createFluxKustomization(fluxKsName+"-nodisc", fluxRBACTenantNS, fluxRBACServiceAcct)
			DeferCleanup(func() {
				deleteFluxObject("kustomization", fluxKsName+"-nodisc", fluxRBACTenantNS)
			})

			Eventually(func() string {
				msg, _ := utils.GetResourceField("kustomization", fluxKsName+"-nodisc",
					fluxRBACTenantNS, fluxReadyMessagePath)
				return msg
			}, fluxRBACReconcileTimeout, fluxRBACPollInterval).Should(
				ContainSubstring(fluxDiscoveryFailureFragment),
				"expected the discovery failure that produced "+
					"'dry-run failed (Forbidden): failed to get server groups' in production")
		})
	})

	Context("helm-controller", func() {
		It("reconciles a HelmRelease that impersonates the tenant ServiceAccount", func() {
			createFluxHelmRelease(fluxHRName, fluxRBACTenantNS, fluxRBACServiceAcct)
			DeferCleanup(func() {
				deleteFluxObject("helmrelease", fluxHRName, fluxRBACTenantNS)
			})

			waitForFluxReady("helmrelease", fluxHRName, fluxRBACReconcileTimeout)

			By("Verifying the chart's ConfigMap was actually rendered and applied")
			Eventually(func() error {
				return checkResourceExists("configmap", fluxHRName+"-values", fluxRBACTenantNS)
			}, fluxRBACReconcileTimeout, fluxRBACPollInterval).Should(Succeed())
		})

		It("fails with 'server groups' when the controller cannot impersonate", func() {
			// The production report showed this failure for the HelmRelease as well
			// as the ConfigMap, so it is pinned for helm-controller too.
			removeFluxRBACImpersonateGrant()
			DeferCleanup(applyFluxRBACImpersonateGrant)

			createFluxHelmRelease(fluxHRName+"-nodisc", fluxRBACTenantNS, fluxRBACServiceAcct)
			DeferCleanup(func() {
				deleteFluxObject("helmrelease", fluxHRName+"-nodisc", fluxRBACTenantNS)
			})

			Eventually(func() string {
				msg, _ := utils.GetResourceField("helmrelease", fluxHRName+"-nodisc",
					fluxRBACTenantNS, fluxReadyMessagePath)
				return msg
			}, fluxRBACReconcileTimeout, fluxRBACPollInterval).Should(
				ContainSubstring(fluxDiscoveryFailureFragment),
				"expected the HelmRelease dry-run to fail on discovery")
		})
	})

	//--------------------------------------------------------------------------
	// Impersonation matrix. Runs on both gate states via the two make targets.
	//--------------------------------------------------------------------------
	Context("Impersonation path", func() {
		It("behaves identically under both ConstrainedImpersonation gate states", func() {
			// ConstrainedImpersonation (KEP-5284) is beta and default-on from 1.36.
			// Flux sets only rest.ImpersonationConfig.UserName, and both the legacy
			// and the constrained filter append system:authenticated to the
			// impersonated identity, so tenant reconciliation must not depend on
			// which filter is active. E2E_CONSTRAINED_IMPERSONATION records which
			// fixture is running purely so a failure names the right cluster.
			gate := getEnvOrDefault("E2E_CONSTRAINED_IMPERSONATION", "unset")
			_, _ = fmt.Fprintf(GinkgoWriter, "ConstrainedImpersonation fixture: %s\n", gate)

			createFluxKustomization(fluxKsName+"-matrix", fluxRBACTenantNS, fluxRBACServiceAcct)
			DeferCleanup(func() {
				deleteFluxObject("kustomization", fluxKsName+"-matrix", fluxRBACTenantNS)
			})

			waitForFluxReady("kustomization", fluxKsName+"-matrix", fluxRBACReconcileTimeout)
		})
	})
})

//------------------------------------------------------------------------------
// Fixture builders
//------------------------------------------------------------------------------

func createFluxOCISources() {
	GinkgoHelper()

	manifest := fmt.Sprintf(`apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: %s
  namespace: %s
spec:
  interval: 1m
  url: oci://%s/e2e/tenant-kustomize
  ref:
    tag: v1
  insecure: true
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: %s
  namespace: %s
spec:
  type: oci
  interval: 1m
  url: oci://%s/e2e/charts
  insecure: true
`, fluxOCIRepoName, fluxRBACTenantNS, fluxRBACRegistry,
		fluxHelmRepoName, fluxRBACTenantNS, fluxRBACRegistry)

	Expect(utils.ApplyManifest(manifest)).To(Succeed(), "failed to create OCI sources")
}

// createFluxKustomization creates a Kustomization impersonating the given
// ServiceAccount.
//
// spec.serviceAccountName is resolved in the Kustomization's OWN namespace. That
// is the subtlety behind the production incident: the Kustomization sat in
// schiff-tenant while the ServiceAccount existed only in t-caas-controllers, so
// Flux impersonated an identity that did not exist. Kubernetes does not verify
// ServiceAccount existence when impersonating, so it failed silently with no
// RoleBindings attached.
func createFluxKustomization(name, namespace, serviceAccount string) {
	GinkgoHelper()

	manifest := fmt.Sprintf(`apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: %s
  namespace: %s
spec:
  interval: 1m
  retryInterval: 10s
  timeout: 1m
  prune: true
  targetNamespace: %s
  sourceRef:
    kind: OCIRepository
    name: %s
  path: ./
  serviceAccountName: %s
`, name, namespace, namespace, fluxOCIRepoName, serviceAccount)

	Expect(utils.ApplyManifest(manifest)).To(Succeed(),
		"failed to create Kustomization %s/%s", namespace, name)
}

func createFluxHelmRelease(name, namespace, serviceAccount string) {
	GinkgoHelper()

	manifest := fmt.Sprintf(`apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: %s
  namespace: %s
spec:
  interval: 1m
  timeout: 1m
  chart:
    spec:
      chart: e2e-tenant-chart
      version: "0.1.0"
      sourceRef:
        kind: HelmRepository
        name: %s
        namespace: %s
  install:
    remediation:
      retries: 1
  serviceAccountName: %s
`, name, namespace, fluxHelmRepoName, namespace, serviceAccount)

	Expect(utils.ApplyManifest(manifest)).To(Succeed(),
		"failed to create HelmRelease %s/%s", namespace, name)
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// waitForFluxReady polls until a Flux object in the tenant namespace reports
// Ready=True, surfacing the condition message on timeout so failures are
// diagnosable rather than a bare "timed out".
func waitForFluxReady(kind, name string, timeout time.Duration) {
	GinkgoHelper()

	Eventually(func() string {
		status, err := utils.GetResourceField(kind, name, fluxRBACTenantNS, fluxReadyStatusPath)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(status)
	}, timeout, fluxRBACPollInterval).Should(Equal("True"),
		func() string {
			msg, _ := utils.GetResourceField(kind, name, fluxRBACTenantNS, fluxReadyMessagePath)
			return fmt.Sprintf("%s/%s/%s never became Ready; last message: %s",
				kind, fluxRBACTenantNS, name, msg)
		})
}

func deleteFluxObject(kind, name, namespace string) {
	cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
		kind, name, "-n", namespace, "--ignore-not-found=true", "--timeout=60s")
	_, _ = utils.Run(cmd)
}

func deleteFluxTestObjects() {
	for _, obj := range []struct{ kind, name string }{
		{"kustomization", fluxKsName},
		{"kustomization", fluxKsName + "-nodisc"},
		{"kustomization", fluxKsName + "-matrix"},
		{"helmrelease", fluxHRName},
		{"helmrelease", fluxHRName + "-nodisc"},
		{"ocirepository", fluxOCIRepoName},
		{"helmrepository", fluxHelmRepoName},
	} {
		deleteFluxObject(obj.kind, obj.name, fluxRBACTenantNS)
	}
}
