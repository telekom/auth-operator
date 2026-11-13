// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Admission must accept production ZAM role groups ("dttcaas-" +
// {tenant}_{scope}_{privilege}, LDAP CN at most 64 characters, [A-Za-z0-9_.-])
// in the form the apiserver presents them, with or without the
// --oidc-groups-prefix, through the full create path of both binding kinds.
// The empty-name control proves the same path still rejects invalid subjects.
func TestBindDefinitionAdmissionZAMGroups(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		group   string
		wantErr string
	}{
		{name: "longest", group: "dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted"},
		{name: "oidc prefixed", group: "oidc:dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted"},
		{name: "shard scope", group: "dttcaas-multi-idp-tenant_bm4x-fra-1_poweruser"},
		{name: "mixed case", group: "dttcaas-Tenant-A_Cluster.01_poweruser"},
		{name: "platform", group: "dttcaas-platform_poweruser"},
		{name: "empty name control", group: "", wantErr: "subject name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(scheme).Build()
			subjects := []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: tt.group}}
			bd := bindDefinitionForSubjectValidation("zam-groups", subjects)
			_, bdErr := (&BindDefinitionValidator{Client: c}).ValidateCreate(context.Background(), bd)
			rbd := &RestrictedBindDefinition{ObjectMeta: bd.ObjectMeta, Spec: RestrictedBindDefinitionSpec{
				TargetName: "zam-groups", Subjects: subjects, ClusterRoleBindings: &bd.Spec.ClusterRoleBindings,
			}}
			rbdErr := (&RestrictedBindDefinitionValidator{Client: c}).validateRestrictedBindDefinitionSpec(context.Background(), rbd)
			for kind, err := range map[string]error{"BindDefinition": bdErr, "RestrictedBindDefinition": rbdErr} {
				if tt.wantErr == "" && err != nil {
					t.Fatalf("%s rejected ZAM group %q: %v", kind, tt.group, err)
				}
				if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
					t.Fatalf("%s: want error containing %q, got %v", kind, tt.wantErr, err)
				}
			}
		})
	}
}
