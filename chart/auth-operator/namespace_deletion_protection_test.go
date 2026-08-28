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

const vapAPIVersionsFlag = "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy"

func TestNamespaceDeletionProtectionSchemaDefaults(t *testing.T) {
	raw, err := os.ReadFile("values.schema.json")
	if err != nil {
		t.Fatalf("read values schema: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parse values schema: %v", err)
	}

	enabled := nestedMap(t, data, "properties", "namespaceDeletionProtection", "properties", "enabled")
	if got, ok := enabled["default"].(bool); !ok || !got {
		t.Fatalf("namespaceDeletionProtection.enabled default = %v, want true", enabled["default"])
	}

	vap := nestedMap(t, data, "properties", "namespaceDeletionProtection", "properties", "vap")
	if got := vap["default"]; got != "auto" {
		t.Fatalf("namespaceDeletionProtection.vap default = %v, want auto", got)
	}
	enumValues, ok := vap["enum"].([]any)
	if !ok || len(enumValues) != 3 {
		t.Fatalf("namespaceDeletionProtection.vap enum = %v, want [auto enabled disabled]", vap["enum"])
	}
}

// TestNamespaceDeletionProtectionVAPRendering pins the security-critical VAP
// rendering matrix: every vap mode with and without cluster VAP support, the
// feature kill switch, and both optional expression branches (extra protected
// namespaces and the legacy TDG labels). The CEL duplicates Go logic in
// internal/webhook/authorization/namespace_deletion_protection.go, so drift
// must be caught here.
func TestNamespaceDeletionProtectionVAPRendering(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	// auto without VAP support: no VAP, webhook flag still on by default.
	defaultRender := helmTemplate(t)
	assertNotContains(t, defaultRender, "kind: ValidatingAdmissionPolicy")
	assertContains(t, defaultRender, "--namespace-deletion-protection=true")
	assertNotContains(t, defaultRender, "--protected-namespaces")

	// auto with VAP support: policy + binding rendered with all three rules.
	autoRender := helmTemplate(t, "--api-versions", vapAPIVersionsFlag)
	assertContains(t, autoRender, "kind: ValidatingAdmissionPolicy")
	assertContains(t, autoRender, "kind: ValidatingAdmissionPolicyBinding")
	assertContains(t, autoRender, `validationActions: ["Deny"]`)
	assertContains(t, autoRender, `operations: ["DELETE", "UPDATE"]`)
	assertContains(t, autoRender, `["kube-system","kube-public","kube-node-lease","default"]`)
	assertContains(t, autoRender, "protected system namespace and cannot be deleted")
	assertContains(t, autoRender, "retry to confirm deletion")
	assertContains(t, autoRender, "removing protection labels requires")
	assertNotContains(t, autoRender, "schiff.telekom.de/owner")

	// enabled forces rendering even without cluster VAP support.
	enabledRender := helmTemplate(t, "--set", "namespaceDeletionProtection.vap=enabled")
	assertContains(t, enabledRender, "kind: ValidatingAdmissionPolicy")

	// disabled suppresses rendering even with cluster VAP support.
	disabledRender := helmTemplate(t, "--api-versions", vapAPIVersionsFlag,
		"--set", "namespaceDeletionProtection.vap=disabled")
	assertNotContains(t, disabledRender, "kind: ValidatingAdmissionPolicy")

	// Feature kill switch suppresses the VAP and turns the webhook flag off.
	offRender := helmTemplate(t, "--api-versions", vapAPIVersionsFlag,
		"--set", "namespaceDeletionProtection.enabled=false")
	assertNotContains(t, offRender, "kind: ValidatingAdmissionPolicy")
	assertContains(t, offRender, "--namespace-deletion-protection=false")

	// Extra protected namespaces are JSON-serialized into the CEL list, so
	// arbitrary values (including quotes) cannot break or alter the policy.
	extraRender := helmTemplate(t, "--api-versions", vapAPIVersionsFlag,
		"--set", `namespaceDeletionProtection.extraProtectedNamespaces={monitoring,we'ird}`)
	assertContains(t, extraRender, `["kube-system","kube-public","kube-node-lease","default","monitoring","we'ird"]`)
	assertContains(t, extraRender, "--protected-namespaces=monitoring,we'ird")

	// TDG migration adds the legacy label clause to both the oldProtected and
	// newProtected variables; each clause references the key twice (membership
	// guard + index), so 4 occurrences in total.
	tdgRender := helmTemplate(t, "--api-versions", vapAPIVersionsFlag,
		"--set", "webhookServer.tdgMigration=true")
	if got := strings.Count(tdgRender, "schiff.telekom.de/owner"); got != 4 {
		t.Fatalf("expected the legacy label clause in oldProtected and newProtected (4 occurrences), got %d", got)
	}

	// Invalid vap mode fails the render instead of silently disabling
	// protection (the values schema enum rejects it before the template's own
	// fail-guard even runs).
	assertHelmTemplateFails(t, "value must be one of 'auto', 'enabled', 'disabled'",
		"--set", "namespaceDeletionProtection.vap=sometimes")
}

func assertHelmTemplateFails(t *testing.T, wantErrPart string, args ...string) {
	t.Helper()
	allArgs := append([]string{"template", "auth-operator", ".", "--namespace", "auth-operator-system"}, args...)
	cmd := exec.CommandContext(t.Context(), "helm", allArgs...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected helm template to fail with %q, but it succeeded", wantErrPart)
	}
	if !strings.Contains(string(output), wantErrPart) {
		t.Fatalf("expected helm template failure to contain %q, got: %s", wantErrPart, string(output))
	}
}
