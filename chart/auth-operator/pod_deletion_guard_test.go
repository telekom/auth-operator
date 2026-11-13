// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os/exec"
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
	assertHelmTemplateFails(t, "podDeletionGuard.configMap.name is required",
		"--set", "podDeletionGuard.enabled=true", "--set", "podDeletionGuard.groups={a}")
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
