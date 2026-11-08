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

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/test/utils"
)

// Strict ServiceAccount namespace ownership, its two transitional opt-outs and
// the ValidatingAdmissionPolicy that guards the per-ServiceAccount opt-out.
// The specs are ordered: the later ones upgrade the release to change flags.
var _ = Describe("ServiceAccount namespace ownership", Ordered, Label("helm", "sa-namespace-ownership"), func() {
	const (
		release   = "auth-operator-sa-ownership-e2e"
		source    = release + "-controllers"
		granted   = "granted"
		named     = "named"
		unbound   = "unbound"
		annotator = "sa-ownership-annotator"
		namedNS   = release + "-named"
		guardMsg  = "only kubernetes-admin or system:masters may set, change or remove"
	)
	annotation := authorizationv1alpha1.AnnotationKeyInheritHostingNamespaceOwnership
	guard := release + "-serviceaccount-ownership-annotation-guard"

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
	// probe server-side dry-runs a Namespace CREATE as a ServiceAccount from source.
	probe := func(sa, name, owner string) (string, error) {
		labels := "    t-caas.telekom.com/owner: " + owner + "\n"
		if owner != "platform" {
			labels += "    t-caas.telekom.com/" + owner + ": team-a\n"
		}
		cmd := utils.CommandContext(context.Background(), "kubectl", "create", "-f", "-", "--dry-run=server",
			"--as=system:serviceaccount:"+source+":"+sa)
		cmd.Stdin = strings.NewReader(fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n%s", name, labels))
		out, err := utils.Run(cmd)
		return string(out), err
	}
	allowed := func(sa, name, owner string) {
		GinkgoHelper()
		output, err := probe(sa, name, owner)
		Expect(err).NotTo(HaveOccurred(), "%s -> %s (%s): %s", sa, name, owner, output)
	}
	denied := func(sa, name, owner string) {
		GinkgoHelper()
		output, err := probe(sa, name, owner)
		Expect(err).To(HaveOccurred(), "%s -> %s (%s) unexpectedly succeeded: %s", sa, name, owner, output)
		Expect(output).To(ContainSubstring("denied the request"), "must fail in namespace admission: %s", output)
	}
	annotate := func(value string, as ...string) (string, error) {
		return run(append([]string{"annotate", "serviceaccount", granted, "-n", source, "--overwrite", annotation + value}, as...)...)
	}
	asAnnotator := "--as=" + annotator
	// createAnnotated dry-runs a CREATE of a ServiceAccount carrying the
	// annotation as the RBAC-authorized non-admin, so retries never persist it.
	createAnnotated := func() (string, error) {
		cmd := utils.CommandContext(context.Background(), "kubectl", "create", "-f", "-", "--dry-run=server", asAnnotator)
		cmd.Stdin = strings.NewReader(fmt.Sprintf("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: annotated\n  namespace: %s\n"+
			"  annotations:\n    %s: \"true\"\n", source, annotation))
		out, err := utils.Run(cmd)
		return string(out), err
	}
	upgrade := func(set ...string) {
		args := append([]string{"upgrade", release, "chart/auth-operator", "-n", release, "--reuse-values", "--wait", "--timeout", "5m"}, set...)
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())
	}

	BeforeAll(func() {
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())
		args := append([]string{"upgrade", "--install", release, "chart/auth-operator", "-n", release, "--create-namespace"}, imageSetArgs()...)
		args = append(args, "--set", "controller.replicas=1", "--set", "webhookServer.replicas=1",
			"--set", "namespaceAdmission.enabled=true", "--wait", "--timeout", "5m")
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		// The hosting namespace is platform-owned, so inheritance would widen
		// every ServiceAccount in it to platform namespaces.
		apply(fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    t-caas.telekom.com/owner: platform
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %[2]s
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %[3]s
  namespace: %[1]s
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %[3]s
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %[3]s
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: %[3]s
`, source, release, annotator))
		for _, sa := range []string{granted, named, unbound} {
			apply(fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[3]s-%[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[3]s
subjects:
- kind: ServiceAccount
  name: %[1]s
  namespace: %[2]s
`, sa, source, release))
		}
		// granted owns tenant team-a namespaces; named owns exactly one name.
		apply(fmt.Sprintf(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %[1]s-%[2]s
spec:
  targetName: %[1]s-%[2]s
  subjects:
  - kind: ServiceAccount
    name: %[2]s
    namespace: %[4]s
  roleBindings:
  - clusterRoleRefs: ["view"]
    namespaceSelector:
    - matchLabels:
        t-caas.telekom.com/owner: tenant
        t-caas.telekom.com/tenant: team-a
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %[1]s-%[3]s
spec:
  targetName: %[1]s-%[3]s
  subjects:
  - kind: ServiceAccount
    name: %[3]s
    namespace: %[4]s
  roleBindings:
  - clusterRoleRefs: ["view"]
    namespaceSelector:
    - matchLabels:
        kubernetes.io/metadata.name: %[5]s
`, release, granted, named, source, namedNS))
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() {
			utils.CollectOperatorLogs(release, 200)
		}
		// Keep the controller alive until BindDefinition finalizers have run.
		for _, sa := range []string{granted, named} {
			_, err := run("delete", "binddefinition", release+"-"+sa, "--ignore-not-found", "--timeout=60s")
			Expect(err).NotTo(HaveOccurred())
		}
		_, err := utils.Run(utils.CommandContext(context.Background(), "helm", "uninstall", release, "-n", release, "--wait", "--timeout", "2m"))
		Expect(err).NotTo(HaveOccurred())
		for _, sa := range []string{granted, named, unbound} {
			_, err = run("delete", "clusterrolebinding", release+"-"+sa, "--ignore-not-found")
			Expect(err).NotTo(HaveOccurred())
		}
		_, err = run("delete", "clusterrole", release, "--ignore-not-found")
		Expect(err).NotTo(HaveOccurred())
		// Deletion protection guards platform namespaces when the webhook is up.
		_, _ = run("annotate", "namespace", source, authorizationv1alpha1.AnnotationKeyAllowDeletion+"=true", "--overwrite")
		for _, ns := range []string{source, release} {
			utils.CleanupNamespace(ns)
		}
	})

	It("limits ServiceAccount namespace CREATE to explicit grants by default", func() {
		out, err := run("get", "deployment", release+"-webhook-server", "-n", release,
			"-o", "jsonpath={.spec.template.spec.containers[0].args}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(out).To(ContainSubstring("--strict-sa-namespace-ownership=true"))

		By("allowing namespaces the ServiceAccount's grants cover")
		allowed(granted, release+"-tenant", "tenant")
		By("denying namespaces only the hosting namespace's ownership would cover")
		denied(granted, release+"-platform", "platform")
		denied(granted, release+"-thirdparty", "thirdparty")
		By("treating a label-free name selector as a grant for exactly that name")
		allowed(named, namedNS, "platform")
		allowed(named, namedNS, "tenant")
		denied(named, release+"-other", "platform")
		By("keeping hosting-namespace inheritance for ServiceAccounts without any grant")
		allowed(unbound, release+"-platform", "platform")
		denied(unbound, release+"-tenant", "tenant")
	})

	It("lets an annotated ServiceAccount inherit its hosting namespace ownership", func() {
		out, err := annotate("=true")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		DeferCleanup(func() { _, _ = annotate("-") })
		// The annotation is read live, so it takes effect immediately.
		allowed(granted, release+"-platform", "platform")
		allowed(granted, release+"-tenant", "tenant")
		denied(granted, release+"-thirdparty", "thirdparty")

		By("ignoring values other than true")
		out, err = annotate("=yes")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		denied(granted, release+"-platform", "platform")

		By("restoring strict ownership once the annotation is removed")
		out, err = annotate("-")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		denied(granted, release+"-platform", "platform")
	})

	It("only lets privileged identities set, change or remove the annotation", func() {
		_, err := run("get", "validatingadmissionpolicy", guard)
		Expect(err).NotTo(HaveOccurred(), "auto must render the guard on a cluster that serves the VAP API")

		By("denying an RBAC-authorized non-admin on CREATE and UPDATE")
		out, err := createAnnotated()
		Expect(err).To(HaveOccurred(), "%s", out)
		Expect(out).To(ContainSubstring(guardMsg))
		out, err = annotate("=true", asAnnotator)
		Expect(err).To(HaveOccurred(), "%s", out)
		Expect(out).To(ContainSubstring(guardMsg))

		By("leaving other ServiceAccount changes to RBAC")
		out, err = run("annotate", "serviceaccount", granted, "-n", source, "--overwrite", "e2e.example.com/unrelated=1", asAnnotator)
		Expect(err).NotTo(HaveOccurred(), "%s", out)

		By("allowing the cluster administrator")
		out, err = annotate("=true")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		DeferCleanup(func() { _, _ = annotate("-") })

		By("denying a non-admin change or removal of an existing annotation")
		for _, value := range []string{"=false", "-"} {
			out, err = annotate(value, asAnnotator)
			Expect(err).To(HaveOccurred(), "%s", out)
			Expect(out).To(ContainSubstring(guardMsg))
		}
	})

	It("drops and restores the annotation guard with its toggle", func() {
		upgrade("--set", "webhookServer.inheritHostingNamespaceOwnershipGuard=disabled")
		out, err := run("get", "validatingadmissionpolicy,validatingadmissionpolicybinding", guard, "--ignore-not-found", "-o", "name")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "disabled must not render the guard")
		// The API server drops and loads policies asynchronously.
		Eventually(func() error {
			out, err := createAnnotated()
			if err != nil {
				return fmt.Errorf("%w: %s", err, out)
			}
			return nil
		}, reconcileTimeout, pollingInterval).Should(Succeed())

		upgrade("--set", "webhookServer.inheritHostingNamespaceOwnershipGuard=enabled")
		Eventually(func() string {
			out, _ := createAnnotated()
			return out
		}, reconcileTimeout, pollingInterval).Should(ContainSubstring(guardMsg))
	})

	It("restores hosting-namespace inheritance for every ServiceAccount when strict ownership is off", func() {
		upgrade("--set", "webhookServer.strictSANamespaceOwnership=false")
		out, err := run("get", "deployment", release+"-webhook-server", "-n", release,
			"-o", "jsonpath={.spec.template.spec.containers[0].args}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		Expect(out).To(ContainSubstring("--strict-sa-namespace-ownership=false"))

		// Old strict webhook pods may still answer until the rollout settles.
		Eventually(func() error {
			out, err := probe(granted, release+"-platform", "platform")
			if err != nil {
				return fmt.Errorf("%w: %s", err, out)
			}
			return nil
		}, reconcileTimeout, pollingInterval).Should(Succeed())
		allowed(named, release+"-other", "platform")
		allowed(granted, release+"-tenant", "tenant")
		denied(granted, release+"-thirdparty", "thirdparty")
	})
})
