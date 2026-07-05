// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestValuesSchemaDocumentsSecureAuthorizeDefault(t *testing.T) {
	data, err := os.ReadFile("values.schema.json")
	if err != nil {
		t.Fatalf("read values schema: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse values schema: %v", err)
	}

	prop := nestedMap(t, schema, "properties", "webhookServer", "properties", "allowUnauthenticatedAuthorize")
	if got := prop["type"]; got != "boolean" {
		t.Fatalf("allowUnauthenticatedAuthorize type = %v, want boolean", got)
	}
	defaultValue, ok := prop["default"].(bool)
	if !ok || defaultValue {
		t.Fatalf("allowUnauthenticatedAuthorize default = %v, want false", prop["default"])
	}
	description, ok := prop["description"].(string)
	if !ok || !strings.Contains(description, "insecure opt-out") {
		t.Fatalf("allowUnauthenticatedAuthorize description should document the insecure opt-out, got %q", description)
	}
}

func TestWebhookDeploymentAuthorizeAuthRendering(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	defaultRender := helmTemplate(t)
	assertContains(t, defaultRender, "--allow-unauthenticated-authorize=false")
	assertNotContains(t, defaultRender, "--authorize-auth-token-file")

	optOutRender := helmTemplate(t, "--set", "webhookServer.allowUnauthenticatedAuthorize=true")
	assertContains(t, optOutRender, "--allow-unauthenticated-authorize=true")
	assertNotContains(t, optOutRender, "--authorize-auth-token-file")

	tokenRender := helmTemplate(t, "--set", "webhookServer.authorizeAuth.tokenSecretName=authorize-token")
	assertContains(t, tokenRender, "--allow-unauthenticated-authorize=false")
	assertContains(t, tokenRender, "--authorize-auth-token-file=/var/run/auth-operator/authorize-auth/token")
}

func helmTemplate(t *testing.T, args ...string) string {
	t.Helper()
	allArgs := append([]string{"template", "auth-operator", ".", "--namespace", "auth-operator-system"}, args...)
	cmd := exec.CommandContext(t.Context(), "helm", allArgs...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, string(output))
	}
	return string(output)
}

func nestedMap(t *testing.T, values map[string]any, path ...string) map[string]any {
	t.Helper()
	current := values
	for _, key := range path {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("schema path %q is not an object", strings.Join(path, "."))
		}
		current = next
	}
	return current
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected rendered chart to contain %q", needle)
	}
}

func assertNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("expected rendered chart not to contain %q", needle)
	}
}
