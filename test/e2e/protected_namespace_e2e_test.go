//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
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

// Use a separate release because namespace admission is cluster-wide. Always
// remove it before sibling Helm suites run, even when retaining the Kind cluster.
var _ = Describe("Protected namespace access classification", Ordered, Label("helm", "protected-namespaces"), func() {
	const release = "auth-operator-protected-e2e"
	const ordinaryNS = "e2e-protected-ordinary"
	const protectedNS = "e2e-protected-sensitive"
	const wrongNS = "e2e-protected-other-tenant"

	run := func(args ...string) (string, error) {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
		return string(out), err
	}
	apply := func(manifest string, args ...string) (string, error) {
		cmd := utils.CommandContext(context.Background(), "kubectl", append([]string{"create", "-f", "-"}, args...)...)
		cmd.Stdin = strings.NewReader(manifest)
		out, err := utils.Run(cmd)
		return string(out), err
	}
	namespace := func(name, marker string) string {
		labels := ""
		if marker != "" {
			labels = "    t-caas.telekom.com/protected: " + marker + "\n"
		}
		return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: protected-e2e
%s`, name, labels)
	}
	deny := func(output string, err error) {
		Expect(err).To(HaveOccurred(), "request unexpectedly succeeded: %s", output)
		Expect(output).To(ContainSubstring("denied the request"), "must fail in admission, not RBAC or transport: %s", output)
	}

	BeforeAll(func() {
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())
		args := append([]string{"upgrade", "--install", release, "chart/auth-operator", "-n", release, "--create-namespace"}, imageSetArgs()...)
		args = append(args, "--set", "controller.replicas=1", "--set", "webhookServer.replicas=1",
			"--set", "namespaceAdmission.enabled=true",
			"--set", "webhookServer.bindDefinitionNamespaceSelectorLabelGroups[0]=example.com",
			"--wait", "--timeout", "5m")
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		out, err = utils.Run(utils.CommandContext(context.Background(), "kubectl", "create", "clusterrole", release,
			"--verb=get,list,create,update,patch,delete", "--resource=namespaces"))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		for _, persona := range []string{"ordinary", "protected"} {
			selector := "    matchExpressions:\n    - key: t-caas.telekom.com/protected\n      operator: DoesNotExist\n"
			if persona == "protected" {
				selector = "      t-caas.telekom.com/protected: protected-e2e\n"
			}
			manifest := fmt.Sprintf(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %s-%s
spec:
  targetName: %s-%s
  subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: protected-e2e-%s
  roleBindings:
  - clusterRoleRefs: ["view"]
    namespaceSelector:
    - matchLabels:
        t-caas.telekom.com/owner: tenant
        t-caas.telekom.com/tenant: protected-e2e
%s`, release, persona, release, persona, persona, "  "+strings.ReplaceAll(strings.TrimSuffix(selector, "\n"), "\n", "\n  ")+"\n")
			output, createErr := apply(manifest)
			Expect(createErr).NotTo(HaveOccurred(), "protected selectors must be admitted with a custom domain: %s", output)
			// Namespace lifecycle authorization needs separate cluster-scoped RBAC.
			output, createErr = run("create", "clusterrolebinding", release+"-"+persona, "--clusterrole="+release, "--group=protected-e2e-"+persona)
			Expect(createErr).NotTo(HaveOccurred(), "%s", output)
		}
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() {
			utils.CollectOperatorLogs(release, 200)
		}
		// Keep the controller alive until BindDefinition finalizers have run.
		for _, persona := range []string{"ordinary", "protected"} {
			_, err := run("delete", "binddefinition,clusterrolebinding", release+"-"+persona, "--ignore-not-found", "--timeout=60s")
			Expect(err).NotTo(HaveOccurred())
		}
		_, err := utils.Run(utils.CommandContext(context.Background(), "helm", "uninstall", release, "-n", release, "--wait", "--timeout", "2m"))
		Expect(err).NotTo(HaveOccurred())
		_, err = run("delete", "clusterrole", release, "--ignore-not-found")
		Expect(err).NotTo(HaveOccurred())
		for _, ns := range []string{ordinaryNS, protectedNS, wrongNS, release} {
			utils.CleanupNamespace(ns)
		}
	})

	It("enforces the submitted classification through namespace admission", func() {
		output, err := apply(namespace(ordinaryNS, ""), "--as=protected-test", "--as-group=protected-e2e-ordinary")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = apply(namespace(protectedNS, "protected-e2e"), "--as=protected-test", "--as-group=protected-e2e-ordinary")
		deny(output, err)
		output, err = apply(namespace(protectedNS, "protected-e2e"), "--as=protected-test", "--as-group=protected-e2e-protected")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = apply(namespace(wrongNS, "other-tenant"), "--as=protected-test", "--as-group=protected-e2e-protected")
		deny(output, err)
	})

	It("reconciles isolated namespaced permissions and revokes stale bindings", func() {
		for _, persona := range []string{"ordinary", "protected"} {
			for _, ns := range []string{ordinaryNS, protectedNS} {
				want := "no"
				if (persona == "ordinary") == (ns == ordinaryNS) {
					want = "yes"
				}
				Eventually(func() string {
					out, _ := run("auth", "can-i", "get", "pods", "-n", ns, "--as=protected-test", "--as-group=protected-e2e-"+persona)
					return strings.TrimSpace(out)
				}, reconcileTimeout, pollingInterval).Should(Equal(want))
			}
		}
		By("Reclassifying through the administrator bypass and checking stale binding removal")
		output, err := run("label", "namespace", ordinaryNS, "t-caas.telekom.com/protected=protected-e2e")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Eventually(func() string {
			out, _ := run("auth", "can-i", "get", "pods", "-n", ordinaryNS, "--as=protected-test", "--as-group=protected-e2e-ordinary")
			return strings.TrimSpace(out)
		}, reconcileTimeout, pollingInterval).Should(Equal("no"))
	})

	It("blocks classification changes and ordinary deletion at admission", func() {
		for _, marker := range []string{"t-caas.telekom.com/protected-", "t-caas.telekom.com/protected=other-tenant"} {
			output, err := run("label", "namespace", protectedNS, marker, "--overwrite", "--as=protected-test", "--as-group=protected-e2e-protected")
			deny(output, err)
		}
		output, err := run("delete", "namespace", protectedNS, "--wait=false", "--as=protected-test", "--as-group=protected-e2e-ordinary")
		deny(output, err)
		output, err = run("delete", "namespace", protectedNS, "--wait=false", "--as=protected-test", "--as-group=protected-e2e-protected")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
	})
})
