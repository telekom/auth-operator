// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestIsNamespaceTerminating(t *testing.T) {
	tests := []struct {
		name string
		ns   *corev1.Namespace
		want bool
	}{
		{
			name: "nil namespace",
			ns:   nil,
			want: false,
		},
		{
			name: "active namespace",
			ns: &corev1.Namespace{
				Status: corev1.NamespaceStatus{
					Phase: corev1.NamespaceActive,
				},
			},
			want: false,
		},
		{
			name: "terminating namespace",
			ns: &corev1.Namespace{
				Status: corev1.NamespaceStatus{
					Phase: corev1.NamespaceTerminating,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNamespaceTerminating(tt.ns)
			if got != tt.want {
				t.Errorf("IsNamespaceTerminating() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNamespaceActive(t *testing.T) {
	tests := []struct {
		name string
		ns   *corev1.Namespace
		want bool
	}{
		{
			name: "nil namespace",
			ns:   nil,
			want: false,
		},
		{
			name: "active namespace",
			ns: &corev1.Namespace{
				Status: corev1.NamespaceStatus{
					Phase: corev1.NamespaceActive,
				},
			},
			want: true,
		},
		{
			name: "terminating namespace",
			ns: &corev1.Namespace{
				Status: corev1.NamespaceStatus{
					Phase: corev1.NamespaceTerminating,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNamespaceActive(tt.ns)
			if got != tt.want {
				t.Errorf("IsNamespaceActive() = %v, want %v", got, tt.want)
			}
		})
	}
}
