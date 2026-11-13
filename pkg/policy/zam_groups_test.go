// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// Group limits compare ZAM role groups byte for byte: no case folding and no
// separator normalization, with or without the apiserver groups prefix.
func TestCheckNameMatchLimitsZAMGroups(t *testing.T) {
	const longest = "dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted"
	limits := &authorizationv1alpha1.NameMatchLimits{
		AllowedPrefixes:   []string{"dttcaas-ZAM-Tenant.123_", "oidc:dttcaas-ZAM-Tenant.123_"},
		ForbiddenSuffixes: []string{"_appowner"},
	}
	tests := []struct {
		name  string
		group string
		ok    bool
	}{
		{name: "longest", group: longest, ok: true},
		{name: "prefixed", group: "oidc:" + longest, ok: true},
		{name: "shard scope", group: "dttcaas-ZAM-Tenant.123_bm4x-fra-1_poweruser", ok: true},
		{name: "case differs", group: "dttcaas-zam-tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted"},
		{name: "hyphen instead of underscore", group: "dttcaas-ZAM-Tenant.123-tcaas-mgmt-nord-1.prd.b_reader-restricted"},
		{name: "forbidden suffix", group: "dttcaas-ZAM-Tenant.123_appowner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := checkNameMatchLimits(limits, tt.group, "spec.subjects[0].name")
			if got := len(violations) == 0; got != tt.ok {
				t.Fatalf("group %q: allowed=%v, want %v (violations: %v)", tt.group, got, tt.ok, violations)
			}
		})
	}
}
