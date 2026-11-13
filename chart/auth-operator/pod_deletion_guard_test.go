// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
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
	guard := renderedDocument(t, scoped, "kind: ValidatingWebhookConfiguration", `name: "auth-operator-pod-deletion-guard"`)
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
	role := renderedDocument(t, scoped, "kind: Role\n", `name: "auth-operator-pod-deletion-guard"`)
	assertContains(t, role, `namespace: "kube-system"`)
	assertContains(t, role, "resourceNames:\n  - \"recovery-target\"")
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
	// Prefixed qualified names are valid matchCondition names.
	prefixed := helmTemplate(t, append(on, "--set", "podDeletionGuard.matchConditions[0].name=example.com/holds-marker",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=true")...)
	assertContains(t, prefixed, `- name: "example.com/holds-marker"`)
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
		`namespace: "kube-system"`,
	} {
		assertContains(t, out, want)
	}
	assertNotContains(t, out, "timeoutSeconds: <nil>")
	assertNotContains(t, out, "--pod-deletion-guard-node-key=\n")
}

// TestPodDeletionGuardNumericNames: valid but numeric-looking names must stay
// YAML strings, or the API server rejects the Role and RoleBinding.
func TestPodDeletionGuardNumericNames(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}
	out := helmTemplate(t, "--set", "podDeletionGuard.enabled=true",
		"--set-string", "podDeletionGuard.configMap.name=123",
		"--set-string", "podDeletionGuard.configMap.namespace=456",
		"--set-string", "podDeletionGuard.configMap.nodeKey=1",
		"--set-string", "podDeletionGuard.configMap.userKey=2",
		"--set-string", "podDeletionGuard.groups[0]=789",
		"--set-string", "podDeletionGuard.usernames[0]=1e3",
		"--set-string", "podDeletionGuard.matchConditions[0].name=10",
		"--set-string", "podDeletionGuard.matchConditions[0].expression=true")
	for _, kind := range []string{"kind: Role\n", "kind: RoleBinding\n"} {
		doc := renderedDocument(t, out, kind, `name: "auth-operator-pod-deletion-guard"`)
		var obj struct {
			Metadata struct {
				Namespace any `json:"namespace"`
			} `json:"metadata"`
			Rules []struct {
				ResourceNames []any `json:"resourceNames"`
			} `json:"rules"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("parse %s: %v", kind, err)
		}
		if ns, ok := obj.Metadata.Namespace.(string); !ok || ns != "456" {
			t.Fatalf("%s namespace = %#v, want string \"456\"", kind, obj.Metadata.Namespace)
		}
		for _, rule := range obj.Rules {
			for _, name := range rule.ResourceNames {
				if s, ok := name.(string); !ok || s != "123" {
					t.Fatalf("%s resourceNames = %#v, want string \"123\"", kind, rule.ResourceNames)
				}
			}
		}
	}
	webhook := renderedDocument(t, out, "kind: ValidatingWebhookConfiguration", `name: "auth-operator-pod-deletion-guard"`)
	var vwc struct {
		Webhooks []struct {
			MatchConditions []struct {
				Name       any `json:"name"`
				Expression any `json:"expression"`
			} `json:"matchConditions"`
		} `json:"webhooks"`
	}
	if err := yaml.Unmarshal([]byte(webhook), &vwc); err != nil {
		t.Fatalf("parse webhook configuration: %v", err)
	}
	for _, c := range vwc.Webhooks[0].MatchConditions {
		if _, ok := c.Name.(string); !ok {
			t.Fatalf("matchCondition name %#v is not a string", c.Name)
		}
		if _, ok := c.Expression.(string); !ok {
			t.Fatalf("matchCondition expression %#v is not a string", c.Expression)
		}
	}
	assertContains(t, out, `request.userInfo.username in [\"1e3\"] || request.userInfo.groups.exists(g, g in [\"789\"])`)
	for _, arg := range []string{"--pod-deletion-guard-configmap-name=123\n", "--pod-deletion-guard-configmap-namespace=456\n",
		"--pod-deletion-guard-node-key=1\n", "--pod-deletion-guard-user-key=2\n"} {
		assertContains(t, out, arg)
	}
}

// guardConfigCase is a row of testdata/pod-deletion-guard-config-cases.json,
// shared with cmd's TestPodDeletionGuardConfigCases: every configuration the
// chart renders must pass the webhook server's flag validation, or the server
// crashloops and takes every auth-operator webhook down.
type guardConfigCase struct {
	Name      string  `json:"name"`
	Namespace *string `json:"namespace"`
	ConfigMap *string `json:"configMap"`
	NodeKey   *string `json:"nodeKey"`
	UserKey   *string `json:"userKey"`
	Valid     bool    `json:"valid"`
}

func TestPodDeletionGuardConfigCases(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}
	raw, err := os.ReadFile("testdata/pod-deletion-guard-config-cases.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []guardConfigCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			args := []string{"template", "auth-operator", ".", "--namespace", "auth-operator-system",
				"--set", "podDeletionGuard.enabled=true", "--set", "podDeletionGuard.groups={a}",
				"--set-string", "podDeletionGuard.configMap.name=target"}
			for key, value := range map[string]*string{"namespace": c.Namespace, "name": c.ConfigMap, "nodeKey": c.NodeKey, "userKey": c.UserKey} {
				if value != nil {
					args = append(args, "--set-string", "podDeletionGuard.configMap."+key+"="+*value)
				}
			}
			out, err := exec.CommandContext(t.Context(), "helm", args...).CombinedOutput() // #nosec G204
			if (err == nil) != c.Valid {
				t.Fatalf("helm template succeeded=%v, want %v (the webhook server accepts it: %v)\n%s", err == nil, c.Valid, c.Valid, out)
			}
		})
	}
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
