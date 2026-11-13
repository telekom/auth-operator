// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPodDeletionGuardRendering pins the scoping of the pod deletion guard:
// off by default, Fail only behind matchConditions, never unscoped.
func TestPodDeletionGuardRendering(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	defaultRender := helmTemplate(t)
	assertNotContains(t, defaultRender, "pod-deletion-guard")

	on := []string{
		"--set", "podDeletionGuard.enabled=true",
		"--set", "podDeletionGuard.configMap.name=recovery-target",
	}
	scoped := helmTemplate(t, append(on,
		"--set", "podDeletionGuard.groups={team-a,team-b}",
		"--set", "podDeletionGuard.usernames={alice}",
		"--set", "podDeletionGuard.matchConditions[0].name=holds-marker",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=authorizer.group('example.com').resource('markers').check('use').allowed()",
		"--set", "podDeletionGuard.namespaceSelector.matchLabels.team=a",
		"--set", "podDeletionGuard.objectSelector.matchLabels.app=web",
		"--set", "podDeletionGuard.timeoutSeconds=3",
	)...)
	guard := renderedDocument(t, scoped, "kind: ValidatingWebhookConfiguration", "name: auth-operator-pod-deletion-guard")
	for _, want := range []string{
		"path: /validate-v1-pod-deletion-guard",
		"failurePolicy: Fail",
		"- name: delegated-identity",
		`expression: "request.userInfo.username in [\"alice\"] || request.userInfo.groups.exists(g, g in [\"team-a\",\"team-b\"])"`,
		`- name: "holds-marker"`,
		`expression: "authorizer.group('example.com').resource('markers').check('use').allowed()"`,
		"namespaceSelector:\n    matchLabels:\n      team: a",
		"objectSelector:\n    matchLabels:\n      app: web",
		"operations:\n    - DELETE\n    resources:\n    - pods",
		"timeoutSeconds: 3",
	} {
		assertContains(t, guard, want)
	}
	role := renderedDocument(t, scoped, "kind: Role\n", "name: auth-operator-pod-deletion-guard")
	assertContains(t, role, "namespace: kube-system")
	assertContains(t, role, "resourceNames:\n  - recovery-target")
	assertContains(t, role, "verbs:\n  - get\n")
	assertNotContains(t, role, "- list")
	assertNotContains(t, role, "- update")
	// The cert rotator injects the CA bundle into the guard webhook configuration.
	webhookRole := renderedDocument(t, scoped, "kind: ClusterRole\n", "name: auth-operator-webhook-server")
	assertContains(t, webhookRole, "- auth-operator-pod-deletion-guard\n")
	assertNotContains(t, renderedDocument(t, defaultRender, "kind: ClusterRole\n", "name: auth-operator-webhook-server"), "pod-deletion-guard")
	for _, arg := range []string{
		"--cert-rotation-validating-webhook=auth-operator-pod-deletion-guard",
		"--pod-deletion-guard=true",
		"--pod-deletion-guard-configmap-namespace=kube-system",
		"--pod-deletion-guard-configmap-name=recovery-target",
		"--pod-deletion-guard-node-key=node",
		"--pod-deletion-guard-user-key=user",
	} {
		assertContains(t, scoped, arg)
	}

	// Only extra conditions: no delegated-identity condition.
	onlyCEL := helmTemplate(t, append(on,
		"--set", "podDeletionGuard.matchConditions[0].name=c",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=request.userInfo.username == 'bob'",
	)...)
	assertNotContains(t, onlyCEL, "delegated-identity")
	assertContains(t, onlyCEL, `expression: "request.userInfo.username == 'bob'"`)

	// Fail closed at render time: no unscoped guard, no guard without a target.
	assertHelmTemplateFails(t, "an unscoped guard would deny every Pod delete", on...)
	// Invalid names would make the API server reject the generated Role and RoleBinding.
	for _, bad := range []string{"podDeletionGuard.configMap.namespace=Kube_System", "podDeletionGuard.configMap.name=Bad_Name", "podDeletionGuard.configMap.nodeKey=a/b"} {
		assertHelmTemplateFails(t, "podDeletionGuard/configMap", append(on, "--set", "podDeletionGuard.groups={a}", "--set", bad)...)
	}
	// The API server rejects a webhook with duplicate matchCondition names.
	assertHelmTemplateFails(t, `duplicate name "delegated-identity"`, append(on, "--set", "podDeletionGuard.groups={a}",
		"--set", "podDeletionGuard.matchConditions[0].name=delegated-identity",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=true")...)
	assertHelmTemplateFails(t, "podDeletionGuard/matchConditions/0/name", append(on,
		"--set", "podDeletionGuard.matchConditions[0].name=not a name",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=true")...)
	// An API server without webhook matchConditions would prune them and leave the guard unscoped.
	assertHelmTemplateFails(t, "podDeletionGuard needs Kubernetes >= 1.30",
		append(on, "--set", "podDeletionGuard.groups={a}", "--kube-version", "1.29.0")...)
	assertHelmTemplateFails(t, "podDeletionGuard.configMap.name is required",
		"--set", "podDeletionGuard.enabled=true", "--set", "podDeletionGuard.groups={a}")
}

// TestPodDeletionGuardReuseValues renders the guard as `helm upgrade
// --reuse-values` does after an upgrade from a release without
// podDeletionGuard: the new defaults are absent, only --set values exist.
func TestPodDeletionGuardReuseValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}
	chartCopy := filepath.Join(t.TempDir(), "auth-operator")
	if err := os.CopyFS(chartCopy, os.DirFS(".")); err != nil {
		t.Fatalf("copy chart: %v", err)
	}
	previousValues, err := os.ReadFile("testdata/values-before-creator-tracking.yaml")
	if err != nil {
		t.Fatalf("read previous values: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chartCopy, "values.yaml"), previousValues, 0o600); err != nil {
		t.Fatalf("replace copied values.yaml: %v", err)
	}
	render := func(args ...string) (string, error) {
		allArgs := append([]string{"template", "auth-operator", chartCopy, "--namespace", "auth-operator-system"}, args...)
		out, err := exec.CommandContext(t.Context(), "helm", allArgs...).CombinedOutput() // #nosec G204
		return string(out), err
	}

	// Only enabled=true: a clear render error, never empty flags that crash the webhook server.
	out, err := render("--set", "podDeletionGuard.enabled=true")
	if err == nil || !strings.Contains(out, "podDeletionGuard.configMap.name is required") {
		t.Fatalf("enabled=true alone: want the required-name error, got err=%v\n%s", err, out)
	}

	out, err = render("--set", "podDeletionGuard.enabled=true",
		"--set", "podDeletionGuard.configMap.name=recovery-target",
		"--set", "podDeletionGuard.groups={team-a}")
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"--pod-deletion-guard-configmap-namespace=kube-system\n",
		"--pod-deletion-guard-configmap-name=recovery-target\n",
		"--pod-deletion-guard-node-key=node\n",
		"--pod-deletion-guard-user-key=user\n",
		"timeoutSeconds: 5\n",
		"namespace: kube-system\n",
	} {
		assertContains(t, out, want)
	}
	assertNotContains(t, out, "timeoutSeconds: <nil>")
	assertNotContains(t, out, "--pod-deletion-guard-node-key=\n")
}

func renderedDocument(t *testing.T, render string, markers ...string) string {
	t.Helper()
	for _, doc := range strings.Split(render, "\n---\n") {
		found := true
		for _, m := range markers {
			if !strings.Contains(doc, m) {
				found = false
				break
			}
		}
		if found {
			return doc
		}
	}
	t.Fatalf("no rendered document contains %q", markers)
	return ""
}
