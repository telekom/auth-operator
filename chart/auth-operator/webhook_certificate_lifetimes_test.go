// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os/exec"
	"testing"
)

// TestWebhookCertificateLifetimes checks that each webhookServer.certificates
// value renders its flag only when set and that the schema rejects values
// that are not Go durations.
func TestWebhookCertificateLifetimes(t *testing.T) {
	requireHelm(t)

	flags := map[string]string{
		"caValidity":    "--webhook-ca-validity",
		"certValidity":  "--webhook-cert-validity",
		"renewBefore":   "--webhook-cert-renew-before",
		"checkInterval": "--webhook-cert-check-interval",
	}

	defaults := helmTemplate(t)
	for _, flag := range flags {
		assertNotContains(t, defaults, flag)
	}

	for value, flag := range flags {
		t.Run(value, func(t *testing.T) {
			out := helmTemplate(t, "--set", "webhookServer.certificates."+value+"=1h30m")
			assertContains(t, out, "- "+flag+"=1h30m\n")
			for _, other := range flags {
				if other != flag {
					assertNotContains(t, out, other)
				}
			}

			for _, bad := range []string{"30d", "-1h", "1"} {
				cmd := exec.CommandContext(t.Context(), "helm", "template", "auth-operator", ".", // #nosec G204
					"--set-string", "webhookServer.certificates."+value+"="+bad)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Errorf("schema must reject %s=%s, got:\n%s", value, bad, out)
				}
			}
		})
	}
}
