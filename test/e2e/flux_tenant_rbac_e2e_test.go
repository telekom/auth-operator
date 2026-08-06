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

// Flux tenant RBAC, as the T-CaaS `flux` function actually deploys it.
//
// Reported failure, from a TDG t5g workload cluster (bundle
// bm4x-workload-36.2.0-rc.3, flux-0.4.0-dev.5, auth-operator-0.6.0-rc.27). A Flux
// Kustomization in namespace schiff-tenant with
// spec.serviceAccountName: m2m-sa-t-caas-t5g failed every dry-run with:
//
//	ConfigMap/schiff-tenant/t5g-namespaces-values dry-run failed (Forbidden): failed to get server groups: unknown
//	HelmRelease/schiff-tenant/t5g-namespaces dry-run failed (Forbidden): failed to get server groups: unknown
//
// The topology these specs encode, read from the function's definition.yaml rather
// than assumed:
//
//   - Every controller sets serviceAccount.create: false and
//     serviceAccount.name: m2m-sa-t-caas-<tenant>, so the controller Deployments
//     RUN AS the m2m ServiceAccount. It is their own pod identity.
//   - m2m-sa-t-caas-<tenant> exists ONLY in t-caas-controllers, created by the
//     auth-operator BindDefinition controller. No platform function creates a
//     ServiceAccount in a tenant namespace, so the only ServiceAccount present in
//     schiff-tenant is the one Kubernetes auto-creates: `default`.
//   - multitenancy.enabled: false and multitenancy.privileged: true, so the
//     chart's cluster-reconciler-impersonator ClusterRole (gated on
//     `multitenancy.enabled AND NOT privileged`) never renders. NOTHING grants the
//     m2m ServiceAccount the `impersonate` verb.
//   - The cluster-reconciler binding grants cluster-admin to ServiceAccounts named
//     kustomize-controller / helm-controller, which the Deployments never use.
//
// Two independent defects follow, both pinned below:
//
//	Defect A: the controller identity cannot impersonate at all. Any Flux object
//	setting spec.serviceAccountName is refused, and because discovery is the first
//	call the impersonated client makes, the error surfaces as the opaque
//	"failed to get server groups".
//
//	Defect B: even granted impersonation, the target identity would need API
//	discovery, which is authorized via nonResourceURLs (/api, /apis, /apis/*).
//	A namespaced Role cannot express nonResourceURLs, so the tenant RoleBindings
//	the auth-operator creates cannot convey it, and neither can the resource-only
//	t-caas-controllers-sa ClusterRole.
//
// On the error text: "failed to get server groups" is controller-runtime's lazy
// RESTMapper (apiutil/restmapper.go), "(Forbidden)" is prepended by
// fluxcd/pkg/ssa/errors, and ": unknown" is a client-go artifact -
// rest.Request substitutes the literal string "unknown" for any non-text/* body and
// discovery reads via .Raw(), which skips Status decoding. The word carries no
// diagnostic content, so these specs assert on the stable "server groups" fragment
// and never on "unknown".
//
// Provisioned by hack/ci/setup-kind-flux.sh. Run with `make test-e2e-flux-rbac`
// (workload topology) or `make test-e2e-flux-rbac-management`.

const (
	fluxRBACControllersNS = "t-caas-controllers"
	fluxRBACTenantNS      = "schiff-tenant"
	fluxRBACForeignNS     = "other-tenant"
	fluxRBACUnlabelledNS  = "unlabelled-tenant"
	fluxRBACTenant        = "t5g"

	// The controllers' own pod identity, and the only ServiceAccount the platform
	// creates for Flux. It exists in fluxRBACControllersNS and nowhere else.
	fluxRBACServiceAcct = "m2m-sa-t-caas-t5g"

	// Names of the RBAC objects the specs create and tear down. Both are candidate
	// fixes, applied only inside the specs that assert their effect.
	fluxRBACImpersonateCR  = "e2e-tenant-flux-impersonator"
	fluxRBACImpersonateCRB = "e2e-tenant-flux-impersonator"
	fluxRBACDiscoveryCRB   = "e2e-tenant-flux-discovery"

	// In-node address of the local registry started by the setup script.
	fluxRBACRegistry = "kind-registry:5000"

	fluxRBACReconcileTimeout = 3 * time.Minute
	fluxRBACPollInterval     = 5 * time.Second
)

// fluxRBACDiscoveryPaths are the nonResourceURLs a discovery client requests.
var fluxRBACDiscoveryPaths = []string{"/api", "/apis", "/version"}

// fluxRBACMode reports which topology the cluster was provisioned with. It mirrors
// the flux function's own $mode: "workload" for tenant clusters, "management" for
// management clusters.
func fluxRBACMode() string {
	return getEnvOrDefault("E2E_FLUX_MODE", "workload")
}

func skipUnlessWorkloadMode() {
	GinkgoHelper()
	if fluxRBACMode() != "workload" {
		Skip(fmt.Sprintf("workload-topology spec; E2E_FLUX_MODE=%s", fluxRBACMode()))
	}
}

var _ = Describe("Flux tenant RBAC (workload topology)", Ordered, Label("flux-rbac"), func() {
	BeforeAll(func() {
		setSuiteOutputDir("flux-rbac")
		skipUnlessWorkloadMode()

		By("Verifying Flux controllers are installed in " + fluxRBACControllersNS)
		for _, deploy := range []string{"source-controller", "kustomize-controller", "helm-controller"} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"deployment", deploy, "-n", fluxRBACControllersNS, "-o", "name")
			if _, err := utils.Run(cmd); err != nil {
				Skip(fmt.Sprintf(
					"Flux %s not installed in %s. Run: make test-e2e-flux-rbac",
					deploy, fluxRBACControllersNS))
			}
		}

		By("Verifying the m2m ServiceAccount exists in " + fluxRBACControllersNS)
		cmd := utils.CommandContext(context.Background(), "kubectl", "get",
			"serviceaccount", fluxRBACServiceAcct, "-n", fluxRBACControllersNS, "-o", "name")
		if _, err := utils.Run(cmd); err != nil {
			Skip(fmt.Sprintf("ServiceAccount %s/%s missing; run hack/ci/setup-kind-flux.sh",
				fluxRBACControllersNS, fluxRBACServiceAcct))
		}

		By("Ensuring no candidate fix is present, so the failures are observable")
		removeFluxRBACImpersonateGrant()
		removeFluxRBACDiscoveryGrant()
	})

	AfterAll(func() {
		removeFluxRBACImpersonateGrant()
		removeFluxRBACDiscoveryGrant()
	})

	//--------------------------------------------------------------------------
	// The deployed topology. If these drift, the rest of the suite is testing
	// something other than production.
	//--------------------------------------------------------------------------
	Context("Deployed topology matches the flux function", func() {
		It("runs kustomize-controller and helm-controller as the m2m ServiceAccount", func() {
			// serviceAccount.create: false + serviceAccount.name: m2m-sa-t-caas-<tenant>.
			// The m2m SA is the controllers' own identity, not just an impersonation
			// target, which is why its permissions matter twice over.
			for _, deploy := range []string{"kustomize-controller", "helm-controller"} {
				sa, err := utils.GetResourceField("deployment", deploy, fluxRBACControllersNS,
					"{.spec.template.spec.serviceAccountName}")
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.TrimSpace(sa)).To(Equal(fluxRBACServiceAcct),
					"%s must run as the tenant m2m ServiceAccount", deploy)
			}
		})

		It("has no m2m ServiceAccount in the tenant namespace", func() {
			// Deliberately asserted. No platform function creates a ServiceAccount in
			// a tenant namespace, so a fix must not assume one is there, and the
			// fixtures must not invent one.
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"serviceaccount", fluxRBACServiceAcct, "-n", fluxRBACTenantNS, "-o", "name")
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(),
				"no m2m ServiceAccount may exist in %s; only the auto-created default",
				fluxRBACTenantNS)
		})

		It("has only the auto-created default ServiceAccount in the tenant namespace", func() {
			out, err := utils.GetResourceField("serviceaccount", "", fluxRBACTenantNS,
				"{.items[*].metadata.name}")
			Expect(err).NotTo(HaveOccurred())
			names := strings.Fields(out)
			Expect(names).To(ConsistOf("default"),
				"tenant namespace %s must contain only the default ServiceAccount, found %v",
				fluxRBACTenantNS, names)
		})

		It("does not render the cluster-reconciler-impersonator ClusterRole", func() {
			// Gated on `multitenancy.enabled AND NOT privileged`; the function sets
			// enabled=false and privileged=true, so it never renders. This is the
			// upstream reason the m2m SA holds no impersonate verb.
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"clusterrole", "cluster-reconciler-impersonator", "-o", "name")
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(),
				"cluster-reconciler-impersonator must not exist with multitenancy.enabled=false")
		})

		It("sets --default-service-account=default on the reconcilers", func() {
			// multitenancy.defaultServiceAccount: "default". Flux resolves this name
			// in the namespace of the Flux object, so a Flux object in a tenant
			// namespace with no spec.serviceAccountName impersonates that
			// namespace's default ServiceAccount, which holds no permissions.
			for _, deploy := range []string{"kustomize-controller", "helm-controller"} {
				args, err := utils.GetResourceField("deployment", deploy, fluxRBACControllersNS,
					"{.spec.template.spec.containers[0].args}")
				Expect(err).NotTo(HaveOccurred())
				Expect(args).To(ContainSubstring("--default-service-account=default"),
					"%s must carry the function's default-service-account flag", deploy)
			}
		})
	})

	//--------------------------------------------------------------------------
	// Defect A: the controller identity cannot impersonate.
	//--------------------------------------------------------------------------
	Context("Defect A: the m2m ServiceAccount cannot impersonate", func() {
		It("holds no impersonate verb on serviceaccounts", func() {
			// The proximate cause. Tenant Flux objects set spec.serviceAccountName,
			// which requires the *controller* identity to impersonate. Nothing in the
			// function grants it.
			allowed := saCanDo(fluxRBACControllersNS, "impersonate", "serviceaccounts", "")
			Expect(allowed).To(BeFalse(),
				"documents the defect: the controller identity cannot impersonate, "+
					"so every spec.serviceAccountName reconcile is refused")
		})

		It("holds no constrained impersonation verbs either", func() {
			// Kubernetes 1.36 enables ConstrainedImpersonation (KEP-5284) by default.
			// Its verbs are an alternative route to the same capability, so their
			// absence is asserted too.
			for _, verb := range []string{
				"impersonate:serviceaccount",
				"impersonate:user-info",
			} {
				allowed := saCanDo(fluxRBACControllersNS, verb, "serviceaccounts", "")
				Expect(allowed).To(BeFalse(),
					"controller identity must not hold %q either", verb)
			}
		})

		It("can impersonate once granted, scoped to the tenant ServiceAccount", func() {
			// The least-privilege shape of a fix for Defect A: the impersonate verb
			// restricted by resourceNames to the tenant's own ServiceAccount, rather
			// than the chart's blanket grant on all serviceaccounts.
			applyFluxRBACImpersonateGrant()
			DeferCleanup(removeFluxRBACImpersonateGrant)

			Eventually(func() bool {
				return saCanDoNamed(fluxRBACControllersNS, "impersonate", "serviceaccounts",
					fluxRBACServiceAcct, fluxRBACControllersNS)
			}, 30*time.Second, 2*time.Second).Should(BeTrue(),
				"the grant must permit impersonating the tenant ServiceAccount")
		})

		It("still cannot impersonate an arbitrary ServiceAccount after the grant", func() {
			// The resourceNames restriction is the whole point: a blanket
			// impersonate grant would let the controller assume any identity in the
			// cluster, including privileged platform ServiceAccounts.
			applyFluxRBACImpersonateGrant()
			DeferCleanup(removeFluxRBACImpersonateGrant)

			for _, target := range []string{"default", "kustomize-controller", "some-platform-sa"} {
				if target == fluxRBACServiceAcct {
					continue
				}
				allowed := saCanDoNamed(fluxRBACControllersNS, "impersonate", "serviceaccounts",
					target, fluxRBACControllersNS)
				Expect(allowed).To(BeFalse(),
					"the scoped grant must not permit impersonating %q", target)
			}
		})

		It("cannot impersonate users or groups even after the grant", func() {
			// Impersonating a user or group would be a total escape from tenant
			// scoping, so the grant must cover serviceaccounts only.
			applyFluxRBACImpersonateGrant()
			DeferCleanup(removeFluxRBACImpersonateGrant)

			for _, resource := range []string{"users", "groups"} {
				allowed := saCanDo(fluxRBACControllersNS, "impersonate", resource, "")
				Expect(allowed).To(BeFalse(),
					"the grant must not permit impersonating %s", resource)
			}
		})
	})

	//--------------------------------------------------------------------------
	// Defect B: the impersonated identity cannot perform API discovery.
	//--------------------------------------------------------------------------
	Context("Defect B: API discovery for the impersonated identity", func() {
		It("denies discovery to an identity holding only namespaced resource RBAC", func() {
			// Discovery is authorized through nonResourceURLs, which a namespaced
			// Role cannot express, so the tenant RoleBindings cannot convey it.
			// Checked without the implicit ServiceAccount groups to isolate the RBAC
			// bound to the identity itself.
			for _, path := range fluxRBACDiscoveryPaths {
				allowed := saCanGetNonResourceURL(fluxRBACControllersNS, path, false)
				Expect(allowed).To(BeFalse(),
					"expected discovery on %s to be denied without an explicit "+
						"nonResourceURLs grant or system:authenticated", path)
			}
		})

		It("allows discovery once bound to the built-in system:discovery ClusterRole", func() {
			applyFluxRBACDiscoveryGrant()
			DeferCleanup(removeFluxRBACDiscoveryGrant)

			for _, path := range fluxRBACDiscoveryPaths {
				Eventually(func() bool {
					return saCanGetNonResourceURL(fluxRBACControllersNS, path, false)
				}, 30*time.Second, 2*time.Second).Should(BeTrue(),
					"expected discovery on %s to be allowed after the binding", path)
			}
		})

		It("confirms discovery otherwise depends on the implicit system:authenticated binding", func() {
			// Same identity, no explicit grant, but carrying the groups a real
			// impersonated ServiceAccount receives. It succeeds only because
			// kube-apiserver binds system:discovery to system:authenticated. This is
			// why the production failure looked arbitrary, and it guards against
			// anyone "fixing" the suite by deleting that bootstrap binding.
			for _, path := range fluxRBACDiscoveryPaths {
				allowed := saCanGetNonResourceURL(fluxRBACControllersNS, path, true)
				Expect(allowed).To(BeTrue(),
					"expected discovery on %s to be allowed for a system:authenticated identity", path)
			}
		})
	})

	//--------------------------------------------------------------------------
	// Escalation boundary. Both candidate fixes must be provably non-escalating.
	//--------------------------------------------------------------------------
	Context("The candidate fixes escalate nothing", func() {
		BeforeAll(func() {
			applyFluxRBACImpersonateGrant()
			applyFluxRBACDiscoveryGrant()
		})

		AfterAll(func() {
			removeFluxRBACImpersonateGrant()
			removeFluxRBACDiscoveryGrant()
		})

		It("binds the unmodified built-in system:discovery ClusterRole", func() {
			// Binding a builtin rather than a hand-rolled role is what makes the
			// no-escalation claim checkable: system:discovery is the very role the
			// default binding already grants to system:authenticated.
			roleRef, err := utils.GetResourceField(
				"clusterrolebinding", fluxRBACDiscoveryCRB, "", "{.roleRef.name}")
			Expect(err).NotTo(HaveOccurred())
			Expect(roleRef).To(Equal("system:discovery"))
		})

		It("keeps system:discovery read-only and free of resource rules", func() {
			rules, err := utils.GetResourceField("clusterrole", "system:discovery", "", "{.rules}")
			Expect(err).NotTo(HaveOccurred())

			Expect(rules).NotTo(ContainSubstring("\"resources\""),
				"system:discovery must not carry resource rules")
			Expect(rules).To(ContainSubstring("nonResourceURLs"))
			for _, verb := range []string{"create", "update", "patch", "delete", "*"} {
				Expect(rules).NotTo(ContainSubstring(fmt.Sprintf("%q", verb)),
					"system:discovery must not grant the %q verb", verb)
			}
		})

		It("grants no resource access the tenant identity lacked before", func() {
			type probe struct{ verb, resource, namespace string }
			for _, p := range []probe{
				{"get", "secrets", ""},
				{"list", "secrets", ""},
				{"get", "nodes", ""},
				{"create", "clusterroles", ""},
				{"create", "clusterrolebindings", ""},
				{"escalate", "clusterroles", ""},
				{"bind", "clusterroles", ""},
				{"get", "configmaps", fluxRBACForeignNS},
				{"create", "configmaps", fluxRBACForeignNS},
			} {
				allowed := saCanDo(fluxRBACControllersNS, p.verb, p.resource, p.namespace)
				Expect(allowed).To(BeFalse(),
					"the fixes must not permit %s %s in namespace %q",
					p.verb, p.resource, p.namespace)
			}
		})

		It("grants no write access to non-resource URLs", func() {
			for _, verb := range []string{"post", "put", "patch", "delete"} {
				allowed := saCanDoNonResourceURL(fluxRBACControllersNS, verb, "/apis")
				Expect(allowed).To(BeFalse(),
					"the fixes must not permit %s on /apis", verb)
			}
		})
	})
})

//------------------------------------------------------------------------------
// Candidate fixes, applied only within the specs that assert their effect.
//------------------------------------------------------------------------------

// applyFluxRBACImpersonateGrant grants the controller identity the impersonate
// verb, restricted by resourceNames to the tenant's own ServiceAccount.
//
// The chart's own cluster-reconciler-impersonator grants `impersonate` on all
// serviceaccounts cluster-wide; scoping to resourceNames is strictly tighter and
// is what a production fix should look like.
func applyFluxRBACImpersonateGrant() {
	GinkgoHelper()

	manifest := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    resourceNames: ["%s"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s
subjects:
  - kind: ServiceAccount
    name: %s
    namespace: %s
`, fluxRBACImpersonateCR, fluxRBACServiceAcct,
		fluxRBACImpersonateCRB, fluxRBACImpersonateCR,
		fluxRBACServiceAcct, fluxRBACControllersNS)

	Expect(utils.ApplyManifest(manifest)).To(Succeed(),
		"failed to apply the scoped impersonation grant")
}

func removeFluxRBACImpersonateGrant() {
	for _, arg := range []struct{ kind, name string }{
		{"clusterrolebinding", fluxRBACImpersonateCRB},
		{"clusterrole", fluxRBACImpersonateCR},
	} {
		cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
			arg.kind, arg.name, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	}
}

// applyFluxRBACDiscoveryGrant binds the controller identity to the built-in
// system:discovery ClusterRole.
//
// Only the ServiceAccount in fluxRBACControllersNS is bound, because that is the
// only namespace where it exists. Nothing here creates a ServiceAccount.
func applyFluxRBACDiscoveryGrant() {
	GinkgoHelper()

	manifest := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:discovery
subjects:
  - kind: ServiceAccount
    name: %s
    namespace: %s
`, fluxRBACDiscoveryCRB, fluxRBACServiceAcct, fluxRBACControllersNS)

	Expect(utils.ApplyManifest(manifest)).To(Succeed(),
		"failed to apply the system:discovery ClusterRoleBinding")
}

func removeFluxRBACDiscoveryGrant() {
	cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
		"clusterrolebinding", fluxRBACDiscoveryCRB, "--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}

//------------------------------------------------------------------------------
// Authorization probes
//------------------------------------------------------------------------------

// saSubject renders the canonical impersonation username for a ServiceAccount.
func saSubject(namespace, name string) string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)
}

// saCanGetNonResourceURL reports whether the m2m ServiceAccount may GET a
// non-resource path.
//
// withServiceAccountGroups controls whether the check includes the groups the
// apiserver attaches to a real ServiceAccount identity (system:serviceaccounts,
// system:serviceaccounts:<ns>, system:authenticated). False isolates the RBAC bound
// explicitly to the identity; true reproduces a real request, where the implicit
// system:discovery -> system:authenticated binding applies.
func saCanGetNonResourceURL(saNamespace, path string, withServiceAccountGroups bool) bool {
	GinkgoHelper()
	return saCanDoNonResourceURLWithGroups(saNamespace, "get", path, withServiceAccountGroups)
}

func saCanDoNonResourceURL(saNamespace, verb, path string) bool {
	GinkgoHelper()
	return saCanDoNonResourceURLWithGroups(saNamespace, verb, path, false)
}

func saCanDoNonResourceURLWithGroups(saNamespace, verb, path string, withGroups bool) bool {
	GinkgoHelper()

	args := []string{"auth", "can-i", verb, path,
		"--as", saSubject(saNamespace, fluxRBACServiceAcct)}
	if withGroups {
		args = append(args,
			"--as-group", "system:serviceaccounts",
			"--as-group", fmt.Sprintf("system:serviceaccounts:%s", saNamespace),
			"--as-group", "system:authenticated",
		)
	}

	return kubectlAuthCanI(args)
}

// saCanDo reports whether the m2m ServiceAccount in saNamespace may perform verb on
// resource. An empty namespace means a cluster-scoped check.
func saCanDo(saNamespace, verb, resource, namespace string) bool {
	GinkgoHelper()

	args := []string{"auth", "can-i", verb, resource,
		"--as", saSubject(saNamespace, fluxRBACServiceAcct)}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "--all-namespaces")
	}

	return kubectlAuthCanI(args)
}

// saCanDoNamed is saCanDo narrowed to a single named object, which is how a
// resourceNames-scoped grant must be probed.
func saCanDoNamed(saNamespace, verb, resource, objectName, objectNamespace string) bool {
	GinkgoHelper()

	args := []string{"auth", "can-i", verb,
		fmt.Sprintf("%s/%s", resource, objectName),
		"--as", saSubject(saNamespace, fluxRBACServiceAcct),
		"-n", objectNamespace,
	}

	return kubectlAuthCanI(args)
}

// kubectlAuthCanI runs `kubectl auth can-i` and interprets the verdict.
//
// The command exits non-zero on "no", so a non-nil error is not a failure. Only
// stdout is authoritative: it prints exactly "yes" or "no". Anything else means the
// probe itself broke and must fail loudly rather than be read as a denial.
func kubectlAuthCanI(args []string) bool {
	GinkgoHelper()

	cmd := utils.CommandContext(context.Background(), "kubectl", args...)
	output, err := utils.Run(cmd)
	verdict := strings.TrimSpace(string(output))

	switch {
	case strings.HasPrefix(verdict, "yes"):
		return true
	case strings.HasPrefix(verdict, "no"):
		return false
	default:
		Fail(fmt.Sprintf(
			"kubectl auth can-i %s produced an unparseable verdict (err=%v): %q",
			strings.Join(args, " "), err, verdict))
		return false
	}
}
