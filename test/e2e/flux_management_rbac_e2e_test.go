//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Flux RBAC in the management-cluster topology.
//
// The companion suites cover workload/tenant clusters. This one covers the other
// half of the flux function's $mode split, because the two topologies differ in
// exactly the places that caused the tenant failure, and a fix aimed at one must not
// silently change the other.
//
// From the flux function definition.yaml, management mode:
//
//   - sets extraObjects: [] via `{{- if eq $mode "management" }}`, so NONE of the
//     tenant RBAC is rendered: no t-caas-controllers-sa ClusterRole, no
//     ClusterRoleBinding, and no tenant m2m ServiceAccount subjects.
//   - runs each controller under its own locally created ServiceAccount
//     (helm-controller, source-controller, ...) with serviceAccount.create: true,
//     rather than under a shared m2m identity.
//   - has no m2m-sa-t-caas-<tenant> ServiceAccount at all. In flux-management the
//     m2m lines are commented out entirely.
//   - never prepends a "platform" shard; $shardNames stays empty for management,
//     whereas platform mode prepends "platform".
//
// The load-bearing consequence: a tenant-scoped discovery or impersonation grant
// must not appear on a management cluster. There is no tenant identity there to
// grant it to, and creating one would introduce a cluster-admin-adjacent identity
// where none is wanted.
//
// Run with `make test-e2e-flux-rbac-management`, which provisions the cluster via
// E2E_FLUX_MODE=management.

func skipUnlessManagementMode() {
	GinkgoHelper()
	if fluxRBACMode() != "management" {
		Skip(fmt.Sprintf("management-topology spec; E2E_FLUX_MODE=%s", fluxRBACMode()))
	}
}

var _ = Describe("Flux RBAC (management topology)", Ordered, Label("flux-rbac"), func() {
	BeforeAll(func() {
		setSuiteOutputDir("flux-management")
		skipUnlessManagementMode()

		By("Verifying Flux controllers are installed in " + fluxRBACControllersNS)
		for _, deploy := range []string{"source-controller", "kustomize-controller", "helm-controller"} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"deployment", deploy, "-n", fluxRBACControllersNS, "-o", "name")
			if _, err := utils.Run(cmd); err != nil {
				Skip(fmt.Sprintf(
					"Flux %s not installed. Run: make test-e2e-flux-rbac-management", deploy))
			}
		}
	})

	//--------------------------------------------------------------------------
	// Identity model: local per-controller ServiceAccounts, no m2m identity.
	//--------------------------------------------------------------------------
	Context("Controller identity", func() {
		It("runs each controller under its own local ServiceAccount", func() {
			// serviceAccount.create: true in management mode. Each controller has its
			// own identity rather than sharing a tenant m2m ServiceAccount.
			for _, deploy := range []string{"kustomize-controller", "helm-controller"} {
				sa, err := utils.GetResourceField("deployment", deploy, fluxRBACControllersNS,
					"{.spec.template.spec.serviceAccountName}")
				Expect(err).NotTo(HaveOccurred())

				name := strings.TrimSpace(sa)
				Expect(name).NotTo(BeEmpty(), "%s must declare a ServiceAccount", deploy)
				Expect(name).NotTo(HavePrefix("m2m-sa-t-caas-"),
					"%s must not run as a tenant m2m ServiceAccount in management mode, got %q",
					deploy, name)
			}
		})

		It("has no tenant m2m ServiceAccount anywhere in the cluster", func() {
			// Management clusters have no tenant identity. If one appears, either the
			// mode was misdetected or a tenant-scoped change leaked into this topology.
			out, err := utils.GetResourceField("serviceaccount", "", "",
				`{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}`)
			Expect(err).NotTo(HaveOccurred())

			for _, line := range utils.GetNonEmptyLines(out) {
				Expect(line).NotTo(ContainSubstring("m2m-sa-t-caas-"),
					"no m2m ServiceAccount may exist on a management cluster, found %q", line)
			}
		})
	})

	//--------------------------------------------------------------------------
	// Tenant RBAC must be absent: extraObjects is [] in management mode.
	//--------------------------------------------------------------------------
	Context("Tenant RBAC is not rendered", func() {
		It("does not create the t-caas-controllers-sa ClusterRole or binding", func() {
			for _, kind := range []string{"clusterrole", "clusterrolebinding"} {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					kind, "t-caas-controllers-sa", "-o", "name")
				_, err := utils.Run(cmd)
				Expect(err).To(HaveOccurred(),
					"%s/t-caas-controllers-sa must not exist in management mode "+
						"(extraObjects is [])", kind)
			}
		})

		It("does not carry a tenant-scoped discovery grant", func() {
			// The workload-topology fix binds a tenant m2m ServiceAccount to
			// system:discovery. That grant is meaningless here and must not be
			// rendered, since there is no tenant identity to bind.
			for _, name := range []string{
				"t-caas-controllers-sa-discovery",
				fluxRBACDiscoveryCRB,
			} {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"clusterrolebinding", name, "-o", "name")
				_, err := utils.Run(cmd)
				Expect(err).To(HaveOccurred(),
					"ClusterRoleBinding %s must not exist on a management cluster", name)
			}
		})

		It("does not carry a tenant-scoped impersonation grant", func() {
			for _, name := range []string{
				"cluster-reconciler-impersonator",
				fluxRBACImpersonateCR,
			} {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"clusterrole", name, "-o", "name")
				_, err := utils.Run(cmd)
				Expect(err).To(HaveOccurred(),
					"ClusterRole %s must not exist on a management cluster", name)
			}
		})

		It("creates no tenant namespaces", func() {
			for _, ns := range []string{fluxRBACTenantNS, fluxRBACForeignNS} {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"namespace", ns, "-o", "name")
				_, err := utils.Run(cmd)
				Expect(err).To(HaveOccurred(),
					"tenant namespace %s must not exist on a management cluster", ns)
			}
		})
	})

	//--------------------------------------------------------------------------
	// Discovery still has to work, via the identity the controllers actually use.
	//--------------------------------------------------------------------------
	Context("API discovery for the management controller identity", func() {
		It("allows discovery for the controllers' own ServiceAccounts", func() {
			// Whatever identity the controllers run as must be able to perform
			// discovery, otherwise management-cluster reconciliation hits the same
			// "failed to get server groups" failure as the tenant clusters did. Here
			// it works through the implicit system:discovery -> system:authenticated
			// binding, with the real ServiceAccount groups attached.
			for _, deploy := range []string{"kustomize-controller", "helm-controller"} {
				sa, err := utils.GetResourceField("deployment", deploy, fluxRBACControllersNS,
					"{.spec.template.spec.serviceAccountName}")
				Expect(err).NotTo(HaveOccurred())
				name := strings.TrimSpace(sa)

				for _, path := range fluxRBACDiscoveryPaths {
					allowed := namedSACanGetNonResourceURL(
						fluxRBACControllersNS, name, path, true)
					Expect(allowed).To(BeTrue(),
						"%s (ServiceAccount %s) must be able to GET %s",
						deploy, name, path)
				}
			}
		})
	})
})

// namedSACanGetNonResourceURL reports whether an arbitrary named ServiceAccount may
// GET a non-resource path.
//
// The workload helpers are hardcoded to the tenant m2m ServiceAccount because that
// is the only identity there; management mode has one identity per controller, so
// the name has to be a parameter.
func namedSACanGetNonResourceURL(saNamespace, saName, path string, withGroups bool) bool {
	GinkgoHelper()

	args := []string{"auth", "can-i", "get", path,
		"--as", saSubject(saNamespace, saName)}
	if withGroups {
		args = append(args,
			"--as-group", "system:serviceaccounts",
			"--as-group", fmt.Sprintf("system:serviceaccounts:%s", saNamespace),
			"--as-group", "system:authenticated",
		)
	}

	return kubectlAuthCanI(args)
}
