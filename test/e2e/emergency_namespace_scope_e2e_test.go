//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// Emergency namespace authorization is limited to the cluster's own tenant;
// the transitional cross-tenant opt-out restores the cluster-wide scope.
// cluster-admin satisfies the emergency review through its wildcard rule,
// which is how the cross-tenant regression surfaced. The specs are ordered:
// the last one upgrades the release to flip the opt-out.
var _ = Describe("Emergency namespace tenant scope", Ordered, Label("helm", "emergency-namespace"), func() {
	const (
		release   = "auth-operator-emergency-e2e"
		emergency = "emergency-e2e-admin"
		plain     = "emergency-e2e-plain"
		ownNS     = release + "-own"
		otherNS   = release + "-other"
	)

	run := func(args ...string) (string, error) {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
		return string(out), err
	}
	apply := func(manifest string) {
		cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(manifest)
		out, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
	}
	tenantNS := func(name, tenant string) string {
		return fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n"+
			"    t-caas.telekom.com/owner: tenant\n    t-caas.telekom.com/tenant: %s\n", name, tenant)
	}
	// operations server-side dry-runs a namespace CREATE, UPDATE and DELETE as user.
	operations := func(user, name, tenant string) map[string]func() (string, error) {
		as := "--as=" + user
		return map[string]func() (string, error){
			"create": func() (string, error) {
				cmd := utils.CommandContext(context.Background(), "kubectl", "create", "-f", "-", "--dry-run=server", as)
				cmd.Stdin = strings.NewReader(tenantNS(name+"-new", tenant))
				out, err := utils.Run(cmd)
				return string(out), err
			},
			"update": func() (string, error) {
				return run("patch", "namespace", name, "--type=merge", "--dry-run=server", as,
					"-p", `{"metadata":{"annotations":{"e2e.example.com/emergency":"yes"}}}`)
			},
			"delete": func() (string, error) {
				return run("delete", "namespace", name, "--dry-run=server", as)
			},
		}
	}
	allowed := func(user, name, tenant string) {
		GinkgoHelper()
		for op, do := range operations(user, name, tenant) {
			out, err := do()
			Expect(err).NotTo(HaveOccurred(), "%s %s %s: %s", user, op, name, out)
		}
	}
	denied := func(user, name, tenant string) {
		GinkgoHelper()
		for op, do := range operations(user, name, tenant) {
			out, err := do()
			Expect(err).To(HaveOccurred(), "%s %s %s unexpectedly succeeded: %s", user, op, name, out)
			Expect(out).To(ContainSubstring("denied the request"), "must fail in namespace admission: %s", out)
		}
	}
	webhookArgs := func() string {
		out, err := run("get", "deployment", release+"-webhook-server", "-n", release,
			"-o", "jsonpath={.spec.template.spec.containers[0].args}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		return out
	}
	upgrade := func(set ...string) {
		args := append([]string{"upgrade", release, "chart/auth-operator", "-n", release, "--reuse-values", "--wait", "--timeout", "5m"}, set...)
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		// helm --wait does not wait for the old pod to terminate; until it is
		// gone the Service may still route admission requests to it.
		Eventually(func() ([]string, error) {
			out, err := run("get", "pods", "-n", release, "-l", "control-plane=webhook-server", "-o", "name")
			return strings.Fields(out), err
		}, deployTimeout, pollingInterval).Should(HaveLen(1))
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())
	}

	BeforeAll(func() {
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())
		args := append([]string{"upgrade", "--install", release, "chart/auth-operator", "-n", release, "--create-namespace"}, imageSetArgs()...)
		args = append(args, "--set", "controller.replicas=1", "--set", "webhookServer.replicas=1",
			"--set", "namespaceAdmission.enabled=true", "--set", "webhookServer.emergencyNamespaceTenant=team-a",
			"--wait", "--timeout", "5m")
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		// emergency holds cluster-admin, which includes use on
		// escalationguards/platform-emergency; plain holds the same namespace
		// verbs without it. Neither is a BindDefinition subject.
		apply(fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %[2]s
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[2]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[2]s
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: %[2]s
`, emergency, plain))
		apply(tenantNS(ownNS, "team-a") + "---\n" + tenantNS(otherNS, "team-b"))
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() {
			utils.CollectOperatorLogs(release, 200)
		}
		var errs []error
		step := func(out string, err error) {
			if err != nil {
				errs = append(errs, fmt.Errorf("%w: %s", err, out))
			}
		}
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", "uninstall", release, "-n", release, "--wait", "--timeout", "2m"))
		step(string(out), err)
		step(run("delete", "clusterrolebinding", emergency, plain, "--ignore-not-found"))
		step(run("delete", "clusterrole", plain, "--ignore-not-found"))
		for _, ns := range []string{ownNS, otherNS, release} {
			utils.CleanupNamespace(ns)
		}
		Expect(errors.Join(errs...)).NotTo(HaveOccurred())
	})

	It("limits emergency namespace authority to the cluster's own tenant by default", func() {
		args := webhookArgs()
		Expect(args).To(ContainSubstring("--emergency-namespace-tenant=team-a"))
		Expect(args).To(ContainSubstring("--emergency-namespace-cross-tenant=false"))

		By("admitting own-tenant namespace operations for the emergency identity")
		allowed(emergency, ownNS, "team-a")
		By("denying other tenants' namespace operations for the emergency identity")
		denied(emergency, otherNS, "team-b")
		By("denying an identity without the emergency permission")
		denied(plain, ownNS, "team-a")
	})

	It("restores cross-tenant emergency authority with the transitional opt-out", func() {
		upgrade("--set", "webhookServer.emergencyNamespaceCrossTenant=true")
		Expect(webhookArgs()).To(ContainSubstring("--emergency-namespace-cross-tenant=true"))

		allowed(emergency, otherNS, "team-b")
		allowed(emergency, ownNS, "team-a")
		denied(plain, otherNS, "team-b")
	})
})
