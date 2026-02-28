// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetMissingRolePolicy(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        MissingRolePolicy
	}{
		{
			name:        "no annotation defaults to warn",
			annotations: nil,
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "empty annotation defaults to warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: ""},
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "explicit warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: "warn"},
			want:        MissingRolePolicyWarn,
		},
		{
			name:        "error policy",
			annotations: map[string]string{MissingRolePolicyAnnotation: "error"},
			want:        MissingRolePolicyError,
		},
		{
			name:        "ignore policy",
			annotations: map[string]string{MissingRolePolicyAnnotation: "ignore"},
			want:        MissingRolePolicyIgnore,
		},
		{
			name:        "unknown value defaults to warn",
			annotations: map[string]string{MissingRolePolicyAnnotation: "invalid"},
			want:        MissingRolePolicyWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bd := &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-bd",
					Annotations: tt.annotations,
				},
			}
			got := bd.GetMissingRolePolicy()
			if got != tt.want {
				t.Errorf("GetMissingRolePolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}
