package webhooks

import (
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsHardProtectedNamespace(t *testing.T) {
	tests := []struct {
		name     string
		nsName   string
		extra    []string
		expected bool
	}{
		{name: "kube-system is hard protected", nsName: "kube-system", expected: true},
		{name: "kube-public is hard protected", nsName: "kube-public", expected: true},
		{name: "kube-node-lease is hard protected", nsName: "kube-node-lease", expected: true},
		{name: "default is hard protected", nsName: "default", expected: true},
		{name: "regular namespace is not hard protected", nsName: "tenant-ns", expected: false},
		{name: "extra namespace is hard protected", nsName: "monitoring", extra: []string{"monitoring"}, expected: true},
		{name: "namespace not in extra list is not hard protected", nsName: "tenant-ns", extra: []string{"monitoring"}, expected: false},
		{name: "prefix of a protected name is not protected", nsName: "kube-sys", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHardProtectedNamespace(tt.nsName, tt.extra); got != tt.expected {
				t.Errorf("isHardProtectedNamespace(%q, %v) = %v, expected %v", tt.nsName, tt.extra, got, tt.expected)
			}
		})
	}
}

func TestIsDeletionProtected(t *testing.T) {
	tests := []struct {
		name         string
		labels       map[string]string
		tdgMigration bool
		expected     bool
	}{
		{
			name:     "platform owner label protects",
			labels:   map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform},
			expected: true,
		},
		{
			name:     "tenant owner label does not protect",
			labels:   map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerTenant},
			expected: false,
		},
		{
			name:     "opt-in label protects",
			labels:   map[string]string{authorizationv1alpha1.LabelKeyDeletionProtection: authorizationv1alpha1.DeletionProtectionEnabled},
			expected: true,
		},
		{
			name:     "opt-in label with other value does not protect",
			labels:   map[string]string{authorizationv1alpha1.LabelKeyDeletionProtection: "true"},
			expected: false,
		},
		{
			name:     "no labels does not protect",
			expected: false,
		},
		{
			name:         "legacy platform label protects with TDG migration",
			labels:       map[string]string{legacyOwnerLabel: "platform"},
			tdgMigration: true,
			expected:     true,
		},
		{
			name:         "legacy schiff label protects with TDG migration",
			labels:       map[string]string{legacyOwnerLabel: "schiff"},
			tdgMigration: true,
			expected:     true,
		},
		{
			name:     "legacy schiff label does not protect without TDG migration",
			labels:   map[string]string{legacyOwnerLabel: "schiff"},
			expected: false,
		},
		{
			name:         "legacy non-platform value does not protect with TDG migration",
			labels:       map[string]string{legacyOwnerLabel: "tenant"},
			tdgMigration: true,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-ns",
					Labels: tt.labels,
				},
			}
			if got := isDeletionProtected(ns, tt.tdgMigration); got != tt.expected {
				t.Errorf("isDeletionProtected(labels=%v, tdgMigration=%v) = %v, expected %v", tt.labels, tt.tdgMigration, got, tt.expected)
			}
		})
	}
}
