// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"testing"

	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
)

func TestLowerCamel(t *testing.T) {
	for kind, want := range map[string]string{
		"ClusterRole":        "clusterRole",
		"ClusterRoleBinding": "clusterRoleBinding",
		"ServiceAccount":     "serviceAccount",
		"RBACPolicy":         "rbacPolicy",
		"RoleDefinition":     "roleDefinition",
		"ABC":                "abc",
		"":                   "",
	} {
		if got := lowerCamel(kind); got != want {
			t.Errorf("lowerCamel(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestHasApplyPreconditions(t *testing.T) {
	tests := map[string]struct {
		ac   any
		want bool
	}{
		"none":                  {ac: rbacv1ac.Role("r", "ns"), want: false},
		"uid":                   {ac: rbacv1ac.Role("r", "ns").WithUID("u"), want: true},
		"resourceVersion":       {ac: rbacv1ac.Role("r", "ns").WithResourceVersion("1"), want: true},
		"empty resourceVersion": {ac: rbacv1ac.Role("r", "ns").WithResourceVersion(""), want: true},
		"no metadata":           {ac: &rbacv1ac.RoleApplyConfiguration{}, want: false},
		"unmarshalable":         {ac: func() {}, want: true},
	}
	for name, tt := range tests {
		if got := hasApplyPreconditions(tt.ac); got != tt.want {
			t.Errorf("%s: hasApplyPreconditions() = %v, want %v", name, got, tt.want)
		}
	}
}

func TestIsNil(t *testing.T) {
	var role *rbacv1ac.RoleApplyConfiguration
	if !isNil(nil) || !isNil(role) || isNil(rbacv1ac.Role("r", "ns")) {
		t.Fatal("isNil returned an unexpected result")
	}
}
