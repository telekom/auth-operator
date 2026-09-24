//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
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

// This suite must run only in the cluster bootstrapped by run-authorization-chain.sh.
var _ = Describe("API server authorization chain", Ordered, Label("authorization-chain"), func() {
	const (
		release   = "auth-operator-chain"
		target    = "chain-tenant"
		ready     = "chain-ready"
		other     = "chain-other"
		protected = "chain-protected"
		binding   = "chain-opt-in"
		role      = "chain-namespace-resources"
		sa        = "system:serviceaccount:auth-operator-chain:chain-client"
	)
	run := func(args ...string) (string, error) {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
		return string(out), err
	}
	apply := func(manifest string, args ...string) (string, error) {
		cmd := utils.CommandContext(context.Background(), "kubectl", append([]string{"apply", "--server-side", "-f", "-"}, args...)...)
		cmd.Stdin = strings.NewReader(manifest)
		out, err := utils.Run(cmd)
		return string(out), err
	}
	can := func(user string, args ...string) string {
		out, err := run(append([]string{"auth", "can-i"}, append(args, "--as="+user)...)...)
		lines := strings.Fields(strings.TrimSpace(out))
		Expect(lines).NotTo(BeEmpty(), "%v", err)
		// kubectl exits 1 for "no"; the API server adds a reason and kubectl
		// may prepend a warning for cluster-scoped resources.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "yes") || strings.HasPrefix(line, "no") {
				return strings.Fields(line)[0]
			}
		}
		Fail(fmt.Sprintf("unexpected can-i response: %s (%v)", out, err))
		return ""
	}
	forbidden := func(out string, err error) {
		ExpectWithOffset(1, err).To(HaveOccurred(), "unexpected allow: %s", out)
		ExpectWithOffset(1, strings.ToLower(out)).To(ContainSubstring("forbidden"), "expected API-server authorization denial: %s", out)
	}

	BeforeAll(func() {
		Expect(kindClusterName).To(HavePrefix("auth-operator-chain-"), "use run-authorization-chain.sh")
		By("Confirming RBAC still authorizes the administrative client")
		Expect(can("system:serviceaccount:"+release+":chain-client", "create", "namespaces")).To(Equal("no"))
		out, err := run("create", "serviceaccount", "chain-client", "-n", release)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		out, err = apply(fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chain-create-namespace
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: chain-create-namespace
roleRef:
  kind: ClusterRole
  name: chain-create-namespace
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: chain-client
  namespace: %s
`, role, release))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(can(sa, "create", "namespaces")).To(Equal("yes"), "RBAC path must work without the webhook")
		Expect(can(sa, "create", "secrets", "-n", release)).To(Equal("no"), "RBAC must not grant secret creation")

		By("Checking a normal WebhookAuthorizer through the same API server")
		out, err = apply(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: chain-webhook-rule
spec:
  allowedPrincipals:
  - user: chain-webhook-user
  resourceRules:
  - verbs: ["get"]
    apiGroups: [""]
    resources: ["pods"]
`)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Eventually(func() string {
			return can("chain-webhook-user", "get", "pods", "-n", release)
		}, time.Minute, time.Second).Should(Equal("yes"))
		Expect(can("chain-unmatched-user", "get", "pods", "-n", release)).To(Equal("no"))

		By("Pausing only the reconciler; /authorize stays available")
		out, err = run("scale", "deployment", release+"-controller-manager", "-n", release, "--replicas=0")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Eventually(func() string {
			result, _ := run("get", "pods", "-n", release, "-l", "control-plane=controller-manager", "-o", "jsonpath={.items[*].metadata.name}")
			return strings.TrimSpace(result)
		}, 2*time.Minute, time.Second).Should(BeEmpty())
		out, err = apply(fmt.Sprintf(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s
spec:
  targetName: %s
  subjects:
  - kind: ServiceAccount
    name: chain-client
    namespace: %s
  roleBindings:
  - clusterRoleRefs: ["%s"]
    namespaceSelector:
    - matchLabels:
        example.com/tenant: alpha
      matchExpressions:
      - key: example.com/protected
        operator: DoesNotExist
    authorizeBeforeBinding: true
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: chain-opt-out
spec:
  targetName: chain-opt-out
  subjects:
  - kind: ServiceAccount
    name: chain-opt-out
    namespace: %s
  roleBindings:
  - clusterRoleRefs: ["%s"]
    namespaceSelector:
    - matchLabels:
        example.com/tenant: alpha
    authorizeBeforeBinding: false
`, binding, binding, release, role, release, role))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		out, err = apply(fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    example.com/tenant: alpha\n", ready))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Eventually(func() string {
			return can(sa, "patch", "secrets", "-n", ready)
		}, time.Minute, time.Second).Should(Equal("yes"), "wait for the BindDefinition candidate index before the single-attempt apply")
		out, err = run("get", "rolebindings", "-n", ready, "-o", "name")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "bridge warm-up must not use RBAC")
	})

	AfterAll(func() {
		_, _ = run("delete", "binddefinition", binding, "chain-opt-out", "--ignore-not-found", "--wait=false")
		_, _ = run("delete", "webhookauthorizer", "chain-webhook-rule", "--ignore-not-found", "--wait=false")
		_, _ = run("delete", "clusterrolebinding", "chain-create-namespace", "--ignore-not-found")
		_, _ = run("delete", "clusterrole", role, "chain-create-namespace", "--ignore-not-found")
		for _, ns := range []string{target, ready, other, protected} {
			_, _ = run("delete", "namespace", ns, "--ignore-not-found", "--wait=false")
		}
	})

	It("authorizes an ordered server-side apply before any RoleBinding exists", func() {
		By("Checking the webhook can be reached, without polling the first apply")
		out, err := run("get", "endpoints", release+"-webhook-service", "-n", release, "-o", "jsonpath={.subsets[0].addresses[0].ip}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(strings.TrimSpace(out)).NotTo(BeEmpty())
		out, err = run("get", "rolebindings", "-n", release, "-o", "name")
		Expect(err).NotTo(HaveOccurred(), "%s", out)

		manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    example.com/tenant: alpha
---
apiVersion: v1
kind: Secret
metadata:
  name: chain-secret
  namespace: %s
type: Opaque
stringData:
  key: value
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: chain-config
  namespace: %s
data:
  key: value
`, target, target, target)
		out, err = apply(manifest, "--as="+sa)
		Expect(err).NotTo(HaveOccurred(), "single first attempt failed: %s", out)
		Expect(out).To(And(ContainSubstring("namespace/"+target), ContainSubstring("secret/chain-secret"), ContainSubstring("configmap/chain-config")))
		out, err = run("get", "rolebindings", "-n", target, "-o", "name")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "bridge must not rely on a reconciled binding")
		Expect(can("chain-webhook-user", "get", "pods", "-n", release)).To(Equal("yes"), "webhook must remain running")
		Expect(can(sa, "create", "secrets", "-n", target)).To(Equal("yes"))
		Expect(can(sa, "create", "configmaps", "-n", target)).To(Equal("yes"))
	})

	It("denies other tenants, protected namespaces, principals, privileged verbs and cluster scope", func() {
		for _, ns := range []struct{ name, labels string }{
			{other, "example.com/tenant: beta"},
			{protected, "example.com/tenant: alpha\n    example.com/protected: \"true\""},
		} {
			out, err := apply(fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    %s\n", ns.name, ns.labels))
			Expect(err).NotTo(HaveOccurred(), "%s", out)
			Expect(can(sa, "create", "secrets", "-n", ns.name)).To(Equal("no"))
			out, err = run("create", "secret", "generic", "blocked", "-n", ns.name, "--from-literal=x=y", "--as="+sa)
			forbidden(out, err)
		}
		Expect(can("system:serviceaccount:"+release+":somebody-else", "create", "secrets", "-n", target)).To(Equal("no"))
		Expect(can("system:serviceaccount:"+release+":chain-opt-out", "create", "secrets", "-n", target)).To(Equal("no"))
		out, err := run("create", "secret", "generic", "opt-out-blocked", "-n", target, "--from-literal=x=y", "--as=system:serviceaccount:"+release+":chain-opt-out")
		forbidden(out, err)
		for _, args := range [][]string{
			{"bind", "clusterroles", "-n", target},
			{"escalate", "clusterroles", "-n", target},
			{"impersonate", "serviceaccounts", "-n", target},
			{"create", "clusterroles"},
			{"create", "secrets", "--all-namespaces"},
		} {
			Expect(can(sa, args...)).To(Equal("no"), "unexpected grant for %v", args)
		}
		out, err = run("create", "secret", "generic", "blocked", "-n", target, "--from-literal=x=y", "--as=system:serviceaccount:"+release+":somebody-else")
		forbidden(out, err)
	})

	It("stops authorizing immediately while deleting and after deletion", func() {
		out, err := run("patch", "binddefinition", binding, "--type=merge", "-p", `{"metadata":{"finalizers":["example.com/hold"]}}`)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		out, err = run("delete", "binddefinition", binding, "--wait=false")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		out, err = run("get", "binddefinition", binding, "-o", "jsonpath={.metadata.deletionTimestamp}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(strings.TrimSpace(out)).NotTo(BeEmpty(), "must test a terminating BindDefinition")
		// Give the webhook informer time to observe deletion before checking
		// the terminating object; unlike the first apply this is not a race test.
		Eventually(func() string {
			return can(sa, "create", "secrets", "-n", target)
		}, 15*time.Second, time.Second).Should(Equal("no"))
		out, err = run("patch", "binddefinition", binding, "--type=merge", "-p", `{"metadata":{"finalizers":[]}}`)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Eventually(func() string {
			out, err := run("get", "binddefinition", binding, "--ignore-not-found", "-o", "name")
			Expect(err).NotTo(HaveOccurred(), "%s", out)
			return strings.TrimSpace(out)
		}, 30*time.Second, time.Second).Should(BeEmpty(), "must test after the BindDefinition is actually deleted")
		Eventually(func() string {
			return can(sa, "create", "secrets", "-n", target)
		}, 30*time.Second, time.Second).Should(Equal("no"))
		out, err = run("create", "secret", "generic", "after-delete", "-n", target, "--from-literal=x=y", "--as="+sa)
		forbidden(out, err)
	})
})
