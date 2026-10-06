//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/test/utils"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Own the release because namespace admission and migration flags are cluster-wide.
var _ = Describe("Add-on namespace ownership", Ordered, Label("helm", "addon-namespaces"), func() {
	const (
		release = "auth-operator-addon-e2e"
		nsA     = "t-addon-a"
		nsB     = "t-addon-b"
		childNS = "t-addon-inherited"
		moveNS  = "t-addon-migration"
		platNS  = "t-addon-platform"
		owner   = authorizationv1alpha1.LabelKeyOwner
		addon   = authorizationv1alpha1.LabelKeyAddon
		tenant  = authorizationv1alpha1.LabelKeyTenant
		third   = authorizationv1alpha1.LabelKeyThirdParty
	)
	user := []string{"--as=addon-e2e-user"}
	shapeUser := []string{"--as=addon-e2e-shape-user"}
	serviceAccount := []string{"--as=system:serviceaccount:" + nsA + ":fallback"}
	migration := []string{"--as=system:serviceaccount:flux-system:helm-controller"}
	allNamespaces := []string{nsA, nsB, childNS, moveNS, platNS, "t-addon-invalid",
		"t-addon-delete", "t-thirdparty-delete", release}

	run := func(args ...string) (string, error) {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
		return string(out), err
	}
	create := func(object any, args ...string) (string, error) {
		data, err := json.Marshal(object)
		Expect(err).NotTo(HaveOccurred())
		cmd := utils.CommandContext(context.Background(), "kubectl", append([]string{"create", "-f", "-"}, args...)...)
		cmd.Stdin = strings.NewReader(string(data))
		out, err := utils.Run(cmd)
		return string(out), err
	}
	namespace := func(name string, labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}
	bindDefinition := func(name string, selector metav1.LabelSelector) *authorizationv1alpha1.BindDefinition {
		return &authorizationv1alpha1.BindDefinition{
			TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: name,
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "addon-e2e-user"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
					ClusterRoleRefs: []string{"view"}, NamespaceSelector: []metav1.LabelSelector{selector},
				}},
			},
		}
	}
	deny := func(output string, err error) {
		Expect(err).To(HaveOccurred(), "request unexpectedly succeeded: %s", output)
		Expect(output).To(ContainSubstring("denied the request"), "must fail in admission, not RBAC or transport: %s", output)
	}
	patch := func(name, data string, principal []string) (string, error) {
		return run(append([]string{"patch", "namespace", name, "--type=merge", "-p", data}, principal...)...)
	}
	readNamespace := func(name string) corev1.Namespace {
		output, err := run("get", "namespace", name, "-o", "json")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		var ns corev1.Namespace
		Expect(json.Unmarshal([]byte(output), &ns)).To(Succeed())
		return ns
	}

	BeforeAll(func() {
		setSuiteOutputDir("addon-namespaces")
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())
		args := append([]string{"upgrade", "--install", release, "chart/auth-operator", "-n", release, "--create-namespace"}, imageSetArgs()...)
		args = append(args, "--set", "controller.replicas=1", "--set", "webhookServer.replicas=1",
			"--set", "namespaceAdmission.enabled=true", "--set", "webhookServer.tdgMigration=true",
			"--wait", "--timeout", "5m")
		output, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		out, err := run("create", "clusterrole", release,
			"--verb=get,list,create,update,patch,delete", "--resource=namespaces")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		binding := &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"},
			ObjectMeta: metav1.ObjectMeta{Name: release},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: release},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "addon-e2e-user"},
				{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "addon-e2e-shape-user"},
				{Kind: rbacv1.ServiceAccountKind, Namespace: nsA, Name: "fallback"},
				{Kind: rbacv1.ServiceAccountKind, Namespace: "flux-system", Name: "helm-controller"},
			},
		}
		out, err = create(binding)
		Expect(err).NotTo(HaveOccurred(), "%s", out)

		// Explicit names exercise shape validation without selector-derived labels.
		explicit := bindDefinition(release+"-explicit", metav1.LabelSelector{})
		explicit.Spec.Subjects[0].Name = "addon-e2e-shape-user"
		explicit.Spec.RoleBindings = nil
		for _, name := range []string{"t-addon-invalid", "t-addon-delete", "t-thirdparty-delete"} {
			explicit.Spec.RoleBindings = append(explicit.Spec.RoleBindings, authorizationv1alpha1.NamespaceBinding{
				ClusterRoleRefs: []string{"view"}, Namespace: name,
			})
		}
		out, err = create(explicit)
		Expect(err).NotTo(HaveOccurred(), "%s", out)
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() {
			utils.CollectOperatorLogs(release, 200)
		}
		// Keep the controller running until binding finalizers have completed.
		for _, name := range []string{release, release + "-explicit"} {
			output, err := run("delete", "binddefinition", name, "--ignore-not-found", "--timeout=60s")
			Expect(err).NotTo(HaveOccurred(), "%s", output)
		}
		output, err := utils.Run(utils.CommandContext(context.Background(), "helm", "uninstall", release, "-n", release, "--wait", "--timeout", "2m"))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		_, err = run("delete", "clusterrole,clusterrolebinding", release, "--ignore-not-found")
		Expect(err).NotTo(HaveOccurred())
		for _, name := range allNamespaces {
			utils.CleanupNamespace(name)
		}
	})

	It("admits a single add-on pin and rejects broad selector grants", func() {
		broad := bindDefinition(release+"-invalid", metav1.LabelSelector{MatchLabels: map[string]string{owner: "addon"}})
		Eventually(func() string {
			output, _ := create(broad, "--dry-run=server")
			return output
		}, deployTimeout, pollingInterval).Should(ContainSubstring("selectors targeting add-on namespaces must pin"))
		for _, selector := range []metav1.LabelSelector{
			{MatchLabels: map[string]string{owner: "addon"}},
			{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: addon, Operator: metav1.LabelSelectorOpExists}}},
			{MatchLabels: map[string]string{owner: "addon"}, MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: addon, Operator: metav1.LabelSelectorOpIn, Values: []string{"addon-a", "addon-b"}},
			}},
			{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: owner, Operator: metav1.LabelSelectorOpIn, Values: []string{"tenant", "addon"}},
			}},
		} {
			output, err := create(bindDefinition(release+"-invalid", selector), "--dry-run=server")
			Expect(err).To(HaveOccurred(), "broad selector unexpectedly admitted: %s", output)
			Expect(output).To(ContainSubstring("selectors targeting add-on namespaces must pin"))
		}
		pinned := metav1.LabelSelector{MatchLabels: map[string]string{owner: "addon"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: addon, Operator: metav1.LabelSelectorOpIn, Values: []string{"addon-a"}}}}
		output, err := create(bindDefinition(release, pinned))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
	})

	It("isolates namespace CREATE, UPDATE and reconciled RBAC per add-on", func() {
		output, err := create(namespace(nsA, map[string]string{owner: "addon", addon: "addon-a"}), user...)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = create(namespace(nsB, map[string]string{owner: "addon", addon: "addon-b"}), user...)
		deny(output, err)
		output, err = create(namespace(nsB, map[string]string{owner: "addon", addon: "addon-b"}))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		for _, name := range []string{nsA, nsB} {
			output, err = patch(name, `{"metadata":{"annotations":{"e2e.telekom.com/updated":"true"}}}`, user)
			if name == nsA {
				Expect(err).NotTo(HaveOccurred(), "%s", output)
				Expect(readNamespace(name).Annotations).To(HaveKeyWithValue("e2e.telekom.com/updated", "true"))
			} else {
				deny(output, err)
				Expect(readNamespace(name).Annotations).NotTo(HaveKey("e2e.telekom.com/updated"))
			}
			want := "no"
			if name == nsA {
				want = "yes"
			}
			Eventually(func() string {
				out, _ := run("auth", "can-i", "get", "pods", "-n", name, user[0])
				return strings.TrimSpace(out)
			}, reconcileTimeout, pollingInterval).Should(Equal(want))
		}
		bindingName := helpers.BuildBindingName(release, "view")
		Eventually(func() string {
			out, _ := run("get", "binddefinition", release, "-o",
				"jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
			return out
		}, reconcileTimeout, pollingInterval).Should(Equal("True"))
		output, err = run("get", "rolebinding", bindingName, "-n", nsA, "-o", "jsonpath={.subjects[0].name}")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Expect(output).To(Equal("addon-e2e-user"))
		output, err = run("get", "rolebinding", bindingName, "-n", nsB, "--ignore-not-found", "-o", "name")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Expect(output).To(BeEmpty())
	})

	It("inherits exact add-on ownership through ServiceAccount fallback", func() {
		output, err := run("create", "serviceaccount", "fallback", "-n", nsA)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = create(namespace(childNS, nil), serviceAccount...)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		labels := readNamespace(childNS).Labels
		Expect(labels).To(HaveKeyWithValue(owner, "addon"))
		Expect(labels).To(HaveKeyWithValue(addon, "addon-a"))
		Expect(labels).NotTo(HaveKey(tenant))
		Expect(labels).NotTo(HaveKey(third))
		output, err = patch(childNS, `{"metadata":{"annotations":{"e2e.telekom.com/fallback":"true"}}}`, serviceAccount)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = create(namespace("t-addon-invalid", map[string]string{owner: "addon", addon: "addon-b"}), serviceAccount...)
		deny(output, err)
		output, err = patch(childNS, fmt.Sprintf(`{"metadata":{"labels":{"%s":"addon-b"}}}`, addon), serviceAccount)
		deny(output, err)
	})

	It("rejects malformed label shapes and ordinary ownership changes", func() {
		for _, labels := range []map[string]string{
			{owner: "addon"},
			{owner: "addon", addon: "addon-a", tenant: "team"},
			{owner: "addon", addon: "addon-a", third: "vendor"},
		} {
			output, err := create(namespace("t-addon-invalid", labels), append(shapeUser, "--dry-run=server")...)
			deny(output, err)
		}
		for _, value := range []any{"addon-b", nil} {
			data, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{addon: value}}})
			Expect(err).NotTo(HaveOccurred())
			output, err := patch(nsA, string(data), user)
			deny(output, err)
		}
		Expect(readNamespace(nsA).Labels).To(HaveKeyWithValue(addon, "addon-a"))
	})

	It("allows gated migration among non-platform owners only for migration principals", func() {
		output, err := create(namespace(moveNS, map[string]string{owner: "tenant", tenant: "team"}))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		toAddon := fmt.Sprintf(`{"metadata":{"labels":{"%s":"addon","%s":"addon-a","%s":null}}}`, owner, addon, tenant)
		output, err = patch(moveNS, toAddon, user)
		deny(output, err)
		output, err = patch(moveNS, toAddon, migration)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Expect(readNamespace(moveNS).Labels).To(HaveKeyWithValue(addon, "addon-a"))
		Expect(readNamespace(moveNS).Labels).NotTo(HaveKey(tenant))

		toPlatform := fmt.Sprintf(`{"metadata":{"labels":{"%s":"platform","%s":null}}}`, owner, addon)
		output, err = patch(moveNS, toPlatform, migration)
		deny(output, err)
		output, err = create(namespace(platNS, map[string]string{owner: "platform"}))
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		// Unlock deletion protection so the denial proves owner immutability,
		// rather than the earlier VAP protection-label guard.
		output, err = run("annotate", "namespace", platNS, authorizationv1alpha1.AnnotationKeyAllowDeletion+"=true")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		output, err = patch(platNS, toAddon, migration)
		deny(output, err)

		toThirdParty := fmt.Sprintf(`{"metadata":{"labels":{"%s":"thirdparty","%s":null,"%s":"vendor"}}}`, owner, addon, third)
		output, err = patch(moveNS, toThirdParty, user)
		deny(output, err)
		output, err = patch(moveNS, toThirdParty, migration)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		Expect(readNamespace(moveNS).Labels).To(HaveKeyWithValue(owner, "thirdparty"))
		Expect(readNamespace(moveNS).Labels).To(HaveKeyWithValue(third, "vendor"))
		Expect(readNamespace(moveNS).Labels).NotTo(HaveKey(addon))
	})

	DescribeTable("retains third-party deletion semantics",
		func(category, identityKey, name string) {
			labels := map[string]string{owner: category, identityKey: "addon-a"}
			output, err := create(namespace(name, labels))
			Expect(err).NotTo(HaveOccurred(), "%s", output)
			output, err = run("delete", "namespace", name, "--dry-run=server", "--wait=false", shapeUser[0])
			Expect(err).NotTo(HaveOccurred(), "non-platform ownership must not imply deletion protection: %s", output)
			output, err = run("label", "namespace", name, authorizationv1alpha1.LabelKeyDeletionProtection+"=enabled", shapeUser[0])
			Expect(err).NotTo(HaveOccurred(), "%s", output)
			output, err = run("delete", "namespace", name, "--wait=false", shapeUser[0])
			// The VAP may reject before the webhook; both are admission, not RBAC.
			Expect(err).To(HaveOccurred())
			Expect(output).To(ContainSubstring("deletion-protected"))
			Expect(readNamespace(name).DeletionTimestamp).To(BeNil())
			output, err = run("annotate", "namespace", name, authorizationv1alpha1.AnnotationKeyAllowDeletion+"=true", shapeUser[0])
			Expect(err).NotTo(HaveOccurred(), "%s", output)
			output, err = run("delete", "namespace", name, "--wait=false", shapeUser[0])
			Expect(err).NotTo(HaveOccurred(), "%s", output)
			// Keep the operator alive while its RoleBinding termination
			// finalizers drain the namespace.
			Eventually(func() string {
				out, getErr := run("get", "namespace", name, "--ignore-not-found", "-o", "name")
				if getErr != nil {
					return getErr.Error()
				}
				return out
			}, reconcileTimeout, pollingInterval).Should(BeEmpty())
		},
		Entry("add-on", "addon", addon, "t-addon-delete"),
		Entry("third-party", "thirdparty", third, "t-thirdparty-delete"),
	)
})
