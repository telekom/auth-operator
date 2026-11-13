// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ZAM role groups as the kube-apiserver presents them from the OIDC groups
// claim: "dttcaas-" + {tenant}_{scope}_{privilege} (LDAP CN at most 64
// characters, [A-Za-z0-9_.-]), optionally behind an --oidc-groups-prefix.
var zamGroupNames = []string{
	"dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted",      // longest (64)
	"oidc:dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted", // prefixed (69)
	"dttcaas-multi-idp-tenant_bm4x-fra-1_poweruser",
	"dttcaas-Tenant-A_Cluster.01_poweruser",
	"dttcaas-platform_poweruser",
	"dttcaas-first-line_fixed-core",
}

func TestValidateBindDefinitionSubjectsAcceptsZAMGroups(t *testing.T) {
	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind}
	for _, group := range zamGroupNames {
		t.Run(group, func(t *testing.T) {
			subjects := []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: group}}
			if err := validateBindDefinitionSubjects(kind, "zam", subjects); err != nil {
				t.Fatalf("ZAM group %q rejected: %v", group, err)
			}
		})
	}
}
