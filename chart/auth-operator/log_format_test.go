// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDeploymentsRenderLogValues checks that global.logFormat and
// global.logLevel reach both Deployments and that the schema rejects unknown
// values.
func TestDeploymentsRenderLogValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want []string
		not  string
	}{
		{"defaults", nil, []string{"--log-format=text", "--verbosity=2"}, "--log-level"},
		{"json", []string{"--set", "global.logFormat=json"}, []string{"--log-format=json", "--verbosity=2"}, "--log-level"},
		{"verbosity", []string{"--set", "global.logLevel=4"}, []string{"--verbosity=4"}, "--log-level"},
		{"named level", []string{"--set", "global.logLevel=debug"}, []string{"--log-level=debug"}, "--verbosity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := helmTemplate(t, tc.args...)
			for _, want := range tc.want {
				// One for the controller and one for the webhook server.
				if got := strings.Count(out, want); got != 2 {
					t.Errorf("%s appears %d times, want 2", want, got)
				}
			}
			assertNotContains(t, out, tc.not)
		})
	}

	for _, bad := range []string{"global.logFormat=xml", "global.logLevel=trace", "global.logLevel=10"} {
		cmd := exec.CommandContext(t.Context(), "helm", "template", "auth-operator", ".", "--set", bad) // #nosec G204
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("schema must reject %s, got:\n%s", bad, out)
		}
	}
}
