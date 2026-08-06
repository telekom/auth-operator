//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Tenant isolation guarantees for Flux-driven tenant reconciliation, in the
// workload topology a tenant cluster actually runs.
//
// The candidate fixes in flux_tenant_rbac_e2e_test.go widen what the Flux
// controller identity may do: one grants the impersonate verb, the other grants API
// discovery. This suite pins the boundaries that must NOT move as a result, and
// separately pins how Flux resolves spec.serviceAccountName across namespaces.
//
// Both fixes are applied throughout, because the boundaries have to hold in the end
// state, not only in the broken one.

var _ = Describe("Flux tenant isolation", Ordered, Label("flux-rbac"), func() {
	BeforeAll(func() {
		setSuiteOutputDir("flux-isolation")
		skipUnlessWorkloadMode()

		By("Verifying the tenant fixtures exist")
		for _, ns := range []string{
			fluxRBACControllersNS, fluxRBACTenantNS, fluxRBACForeignNS, fluxRBACUnlabelledNS,
		} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "namespace", ns, "-o", "name")
			if _, err := utils.Run(cmd); err != nil {
				Skip(fmt.Sprintf("namespace %s missing; run hack/ci/setup-kind-flux.sh", ns))
			}
		}

		By("Applying both candidate fixes")
		// Isolation must hold with the fixes in place, since that is the state the
		// cluster would actually run in.
		applyFluxRBACImpersonateGrant()
		applyFluxRBACDiscoveryGrant()
	})

	AfterAll(func() {
		removeFluxRBACImpersonateGrant()
		removeFluxRBACDiscoveryGrant()
	})

	//--------------------------------------------------------------------------
	// Cross-tenant boundaries.
	//--------------------------------------------------------------------------
	Context("Cross-tenant namespace access", func() {
		It("denies the tenant identity all access to another tenant's namespace", func() {
			for _, verb := range []string{"get", "list", "create", "update", "patch", "delete"} {
				for _, resource := range []string{"configmaps", "secrets", "deployments", "serviceaccounts"} {
					allowed := saCanDo(fluxRBACControllersNS, verb, resource, fluxRBACForeignNS)
					Expect(allowed).To(BeFalse(),
						"tenant %s must not be able to %s %s in the foreign namespace %s",
						fluxRBACTenant, verb, resource, fluxRBACForeignNS)
				}
			}
		})

		It("denies the tenant identity access to an unlabelled namespace", func() {
			// The auth-operator chart's tenantNamespaceSelector matches on
			// t-caas.telekom.com/owner and t-caas.telekom.com/tenant. A namespace a
			// user creates by hand without those labels must receive no RoleBinding,
			// so the tenant identity has no access there.
			for _, verb := range []string{"get", "create", "delete"} {
				allowed := saCanDo(fluxRBACControllersNS, verb, "configmaps", fluxRBACUnlabelledNS)
				Expect(allowed).To(BeFalse(),
					"tenant must not be able to %s configmaps in the unlabelled namespace %s",
					verb, fluxRBACUnlabelledNS)
			}
		})

		It("retains access to its own namespace", func() {
			// Guards against an over-broad isolation fix that locks the tenant out
			// of its own workloads and makes the negative specs above vacuous.
			for _, verb := range []string{"get", "create", "update", "delete"} {
				allowed := saCanDo(fluxRBACControllersNS, verb, "configmaps", fluxRBACTenantNS)
				Expect(allowed).To(BeTrue(),
					"tenant must retain %s on configmaps in its own namespace %s",
					verb, fluxRBACTenantNS)
			}
		})

		It("denies cluster-scoped resource access", func() {
			for _, resource := range []string{"namespaces", "nodes", "persistentvolumes", "clusterroles"} {
				for _, verb := range []string{"create", "update", "delete"} {
					allowed := saCanDo(fluxRBACControllersNS, verb, resource, "")
					Expect(allowed).To(BeFalse(),
						"tenant must not be able to %s cluster-scoped %s", verb, resource)
				}
			}
		})
	})

	//--------------------------------------------------------------------------
	// Namespace resolution of spec.serviceAccountName.
	//
	// This is the production case, not a hypothetical. Flux resolves
	// spec.serviceAccountName in the namespace of the Flux object itself
	// (kustomize-controller passes obj.GetNamespace() to the impersonator). The
	// tenant's m2m ServiceAccount exists ONLY in t-caas-controllers, so a
	// Kustomization in a tenant namespace naming it impersonates
	// system:serviceaccount:<tenant-ns>:m2m-sa-t-caas-<tenant>, which does not
	// exist. Kubernetes performs no existence check when impersonating, so the
	// request proceeds as a phantom identity with no RoleBindings and every call is
	// refused. Flux's CanImpersonate() pre-check, which would surface this clearly,
	// runs only on the finalizer/delete path.
	//
	// These specs pin that it fails, so no future change can quietly make a
	// cross-namespace ServiceAccount reference appear to work.
	//--------------------------------------------------------------------------
	Context("Namespace resolution of spec.serviceAccountName", func() {
		It("does not resolve the m2m ServiceAccount from another namespace", func() {
			ksName := "e2e-cross-ns-sa"

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
    namespace: %s
  path: ./
  serviceAccountName: %s
`, ksName, fluxRBACForeignNS, fluxRBACForeignNS,
				fluxOCIRepoName, fluxRBACTenantNS, fluxRBACServiceAcct)

			Expect(utils.ApplyManifest(manifest)).To(Succeed())
			DeferCleanup(func() {
				deleteFluxObject("kustomization", ksName, fluxRBACForeignNS)
			})

			By("Verifying the Kustomization never becomes Ready")
			// Consistently, not Eventually: proving a negative requires that it
			// stays not-Ready for the whole window rather than merely being
			// not-Ready at some instant.
			Consistently(func() string {
				status, err := utils.GetResourceField("kustomization", ksName, fluxRBACForeignNS,
					`{.status.conditions[?(@.type=="Ready")].status}`)
				if err != nil {
					return ""
				}
				return status
			}, 90*time.Second, 10*time.Second).ShouldNot(Equal("True"),
				"a Kustomization must not reconcile using a ServiceAccount from another namespace")

			By("Verifying the phantom identity was denied rather than silently permitted")
			msg, _ := utils.GetResourceField("kustomization", ksName, fluxRBACForeignNS,
				`{.status.conditions[?(@.type=="Ready")].message}`)
			_, _ = fmt.Fprintf(GinkgoWriter, "cross-namespace SA failure message: %s\n", msg)
			Expect(msg).NotTo(BeEmpty(),
				"expected a failure message explaining the denial")
		})

		It("confirms the phantom identity holds no permissions", func() {
			// Direct statement of why the above fails. The username is well-formed and
			// the apiserver accepts it for impersonation, but nothing is bound to it,
			// so every check is denied.
			phantom := saSubject(fluxRBACTenantNS, fluxRBACServiceAcct)
			_, _ = fmt.Fprintf(GinkgoWriter, "phantom identity under test: %s\n", phantom)

			for _, verb := range []string{"get", "create"} {
				allowed := saCanDo(fluxRBACTenantNS, verb, "configmaps", fluxRBACTenantNS)
				Expect(allowed).To(BeFalse(),
					"an m2m ServiceAccount name that does not exist in %s must hold "+
						"no permissions, even though the same name in %s is fully bound",
					fluxRBACTenantNS, fluxRBACControllersNS)
			}
		})

		It("resolves correctly for a Flux object co-located with the ServiceAccount", func() {
			// The contrast case: the same name, the same grants, but a Kustomization
			// in t-caas-controllers where the ServiceAccount actually exists. This is
			// what distinguishes a namespace-resolution problem from a missing grant,
			// and it is why the two must be diagnosed separately.
			allowed := saCanDo(fluxRBACControllersNS, "get", "configmaps", fluxRBACControllersNS)
			Expect(allowed).To(BeTrue(),
				"the m2m ServiceAccount in %s must be bound and usable",
				fluxRBACControllersNS)
		})
	})

	//--------------------------------------------------------------------------
	// Impersonation chaining. A tenant that can impersonate escapes every
	// boundary above, so this is the highest-value negative in the suite.
	//--------------------------------------------------------------------------
	Context("Impersonation privileges", func() {
		It("denies blanket impersonation of arbitrary serviceaccounts, users and groups", func() {
			// With the scoped fix applied the controller may impersonate exactly one
			// named ServiceAccount. Cluster-wide impersonation of any serviceaccount,
			// and impersonation of users or groups at all, must remain denied - those
			// would be a complete escape from tenant scoping.
			for _, resource := range []string{"serviceaccounts", "users", "groups"} {
				allowed := saCanDo(fluxRBACControllersNS, "impersonate", resource, "")
				Expect(allowed).To(BeFalse(),
					"tenant identity must not hold blanket impersonate on %s", resource)
			}
		})

		It("denies the constrained impersonation verbs introduced by KEP-5284", func() {
			// Kubernetes 1.36 added impersonate:<mode> and impersonate-on:<mode>:<verb>.
			// A tenant must hold none of them, and an authorization layer that does
			// not recognise the new verbs must not accidentally allow them.
			for _, verb := range []string{
				"impersonate:serviceaccount",
				"impersonate:user-info",
				"impersonate:associated-node",
				"impersonate:arbitrary-node",
			} {
				allowed := saCanDo(fluxRBACControllersNS, verb, "serviceaccounts", "")
				Expect(allowed).To(BeFalse(),
					"tenant must not hold the constrained impersonation verb %q", verb)
			}
		})

		It("denies RBAC self-elevation via escalate or bind", func() {
			for _, resource := range []string{"clusterroles", "roles"} {
				for _, verb := range []string{"escalate", "bind"} {
					allowed := saCanDo(fluxRBACControllersNS, verb, resource, "")
					Expect(allowed).To(BeFalse(),
						"tenant must not be able to %s %s", verb, resource)
				}
			}
		})
	})
})
