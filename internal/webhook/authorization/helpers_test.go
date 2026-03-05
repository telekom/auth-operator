package webhooks

import (
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     ServiceAccountInfo
	}{
		{
			name:     "valid service account",
			username: "system:serviceaccount:kube-system:default",
			want:     ServiceAccountInfo{Namespace: "kube-system", Name: "default", IsServiceAccount: true},
		},
		{
			name:     "valid service account with hyphenated name",
			username: "system:serviceaccount:flux-system:helm-controller",
			want:     ServiceAccountInfo{Namespace: "flux-system", Name: "helm-controller", IsServiceAccount: true},
		},
		{
			name:     "regular user",
			username: "kubernetes-admin",
			want:     ServiceAccountInfo{IsServiceAccount: false},
		},
		{
			name:     "oidc user",
			username: "oidc:user@example.com",
			want:     ServiceAccountInfo{IsServiceAccount: false},
		},
		{
			name:     "malformed service account - too few parts",
			username: "system:serviceaccount:kube-system",
			want:     ServiceAccountInfo{IsServiceAccount: false},
		},
		{
			name:     "malformed service account - wrong prefix",
			username: "other:serviceaccount:kube-system:default",
			want:     ServiceAccountInfo{IsServiceAccount: false},
		},
		{
			name:     "empty string",
			username: "",
			want:     ServiceAccountInfo{IsServiceAccount: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseServiceAccount(tt.username)
			if got.IsServiceAccount != tt.want.IsServiceAccount {
				t.Errorf("ParseServiceAccount(%q).IsServiceAccount = %v, want %v",
					tt.username, got.IsServiceAccount, tt.want.IsServiceAccount)
			}
			if got.IsServiceAccount {
				if got.Namespace != tt.want.Namespace {
					t.Errorf("ParseServiceAccount(%q).Namespace = %q, want %q",
						tt.username, got.Namespace, tt.want.Namespace)
				}
				if got.Name != tt.want.Name {
					t.Errorf("ParseServiceAccount(%q).Name = %q, want %q",
						tt.username, got.Name, tt.want.Name)
				}
			}
		})
	}
}

func TestCheckMutatorBypass(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		operation    admissionv1.Operation
		namespace    string
		tdgMigration bool
		wantBypass   bool
		wantReason   string
	}{
		{
			name:       "kubernetes-admin always bypasses",
			username:   "kubernetes-admin",
			operation:  admissionv1.Create,
			namespace:  "test-ns",
			wantBypass: true,
			wantReason: "kubernetes-admin",
		},
		{
			name:       "trident-operator for t-caas-storage update",
			username:   "system:serviceaccount:t-caas-storage:trident-operator",
			operation:  admissionv1.Update,
			namespace:  "t-caas-storage",
			wantBypass: true,
			wantReason: "trident-operator for t-caas-storage",
		},
		{
			name:       "trident-operator for different namespace",
			username:   "system:serviceaccount:t-caas-storage:trident-operator",
			operation:  admissionv1.Update,
			namespace:  "other-ns",
			wantBypass: false,
		},
		{
			name:       "trident-operator create does not bypass",
			username:   "system:serviceaccount:t-caas-storage:trident-operator",
			operation:  admissionv1.Create,
			namespace:  "t-caas-storage",
			wantBypass: false,
		},
		{
			name:       "capi-operator-manager for update",
			username:   "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:  admissionv1.Update,
			namespace:  "any-ns",
			wantBypass: true,
			wantReason: "capi-operator-manager",
		},
		{
			name:       "capi-operator-manager for create",
			username:   "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:  admissionv1.Create,
			namespace:  "any-ns",
			wantBypass: false,
		},
		{
			name:         "helm-controller with tdgMigration",
			username:     "system:serviceaccount:flux-system:helm-controller",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "helm-controller (tdgMigration)",
		},
		{
			name:         "helm-controller without tdgMigration",
			username:     "system:serviceaccount:flux-system:helm-controller",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: false,
			wantBypass:   false,
		},
		{
			name:         "kustomize-controller with tdgMigration",
			username:     "system:serviceaccount:flux-system:kustomize-controller",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "kustomize-controller (tdgMigration)",
		},
		{
			name:         "schiff-tenant m2m-sa with tdgMigration",
			username:     "system:serviceaccount:schiff-tenant:m2m-sa",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "schiff-tenant m2m-sa (tdgMigration)",
		},
		{
			name:         "schiff-system m2m-sa with tdgMigration",
			username:     "system:serviceaccount:schiff-system:m2m-sa",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "schiff-system m2m-sa (tdgMigration)",
		},
		{
			name:         "capi-operator-manager with tdgMigration bypasses",
			username:     "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:    admissionv1.Create,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "capi-operator-manager (tdgMigration)",
		},
		{
			name:         "trident-operator-system with tdgMigration for trident-system update",
			username:     "system:serviceaccount:trident-system:trident-operator",
			operation:    admissionv1.Update,
			namespace:    "trident-system",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "trident-operator for trident-system (tdgMigration)",
		},
		{
			name:         "trident-operator-system with tdgMigration for wrong namespace",
			username:     "system:serviceaccount:trident-system:trident-operator",
			operation:    admissionv1.Update,
			namespace:    "other-ns",
			tdgMigration: true,
			wantBypass:   false,
		},
		{
			name:         "trident-operator-system with tdgMigration for create",
			username:     "system:serviceaccount:trident-system:trident-operator",
			operation:    admissionv1.Create,
			namespace:    "trident-system",
			tdgMigration: true,
			wantBypass:   false,
		},
		{
			name:       "regular user does not bypass",
			username:   "user@example.com",
			operation:  admissionv1.Create,
			namespace:  "test-ns",
			wantBypass: false,
		},
		{
			name:         "unknown SA with tdgMigration does not bypass",
			username:     "system:serviceaccount:unknown:unknown-sa",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckMutatorBypass(tt.username, tt.operation, tt.namespace, tt.tdgMigration)
			if result.ShouldBypass != tt.wantBypass {
				t.Errorf("CheckMutatorBypass() ShouldBypass = %v, want %v", result.ShouldBypass, tt.wantBypass)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("CheckMutatorBypass() Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestCheckValidatorBypass(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		operation    admissionv1.Operation
		namespace    string
		tdgMigration bool
		wantBypass   bool
		wantReason   string
	}{
		{
			name:       "kubernetes-admin always bypasses",
			username:   "kubernetes-admin",
			operation:  admissionv1.Create,
			namespace:  "test-ns",
			wantBypass: true,
			wantReason: "kubernetes-admin",
		},
		{
			name:       "trident-operator for t-caas-storage update",
			username:   "system:serviceaccount:t-caas-storage:trident-operator",
			operation:  admissionv1.Update,
			namespace:  "t-caas-storage",
			wantBypass: true,
			wantReason: "trident-operator for t-caas-storage",
		},
		{
			name:       "trident-operator for different namespace",
			username:   "system:serviceaccount:t-caas-storage:trident-operator",
			operation:  admissionv1.Update,
			namespace:  "other-ns",
			wantBypass: false,
		},
		{
			name:       "capi-operator-manager for update",
			username:   "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:  admissionv1.Update,
			namespace:  "any-ns",
			wantBypass: true,
			wantReason: "capi-operator-manager",
		},
		{
			name:       "capi-operator-manager for create without tdgMigration",
			username:   "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:  admissionv1.Create,
			namespace:  "any-ns",
			wantBypass: false,
		},
		{
			name:         "helm-controller with tdgMigration",
			username:     "system:serviceaccount:flux-system:helm-controller",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "helm-controller (tdgMigration)",
		},
		{
			name:         "kustomize-controller with tdgMigration",
			username:     "system:serviceaccount:flux-system:kustomize-controller",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "kustomize-controller (tdgMigration)",
		},
		{
			name:         "schiff-tenant m2m-sa with tdgMigration",
			username:     "system:serviceaccount:schiff-tenant:m2m-sa",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "schiff-tenant m2m-sa (tdgMigration)",
		},
		{
			name:         "schiff-system m2m-sa with tdgMigration",
			username:     "system:serviceaccount:schiff-system:m2m-sa",
			operation:    admissionv1.Update,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "schiff-system m2m-sa (tdgMigration)",
		},
		{
			name:         "capi-operator-manager with tdgMigration",
			username:     "system:serviceaccount:capi-operator-system:capi-operator-manager",
			operation:    admissionv1.Create,
			namespace:    "any-ns",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "capi-operator-manager (tdgMigration)",
		},
		{
			name:         "trident-operator-system with tdgMigration for trident-system update",
			username:     "system:serviceaccount:trident-system:trident-operator",
			operation:    admissionv1.Update,
			namespace:    "trident-system",
			tdgMigration: true,
			wantBypass:   true,
			wantReason:   "trident-operator for trident-system (tdgMigration)",
		},
		{
			name:         "trident-operator-system with tdgMigration for wrong namespace",
			username:     "system:serviceaccount:trident-system:trident-operator",
			operation:    admissionv1.Update,
			namespace:    "other-ns",
			tdgMigration: true,
			wantBypass:   false,
		},
		{
			name:       "regular user does not bypass",
			username:   "user@example.com",
			operation:  admissionv1.Create,
			namespace:  "test-ns",
			wantBypass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckValidatorBypass(tt.username, tt.operation, tt.namespace, tt.tdgMigration)
			if result.ShouldBypass != tt.wantBypass {
				t.Errorf("CheckValidatorBypass() ShouldBypass = %v, want %v", result.ShouldBypass, tt.wantBypass)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("CheckValidatorBypass() Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestMatchesSubjects(t *testing.T) {
	tests := []struct {
		name       string
		userGroups []string
		saInfo     ServiceAccountInfo
		subjects   []rbacv1.Subject
		want       bool
	}{
		{
			name:       "matches group",
			userGroups: []string{"oidc:admin", "oidc:developer"},
			saInfo:     ServiceAccountInfo{IsServiceAccount: false},
			subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "oidc:admin"},
			},
			want: true,
		},
		{
			name:       "does not match group",
			userGroups: []string{"oidc:viewer"},
			saInfo:     ServiceAccountInfo{IsServiceAccount: false},
			subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "oidc:admin"},
			},
			want: false,
		},
		{
			name:       "matches service account",
			userGroups: []string{},
			saInfo:     ServiceAccountInfo{Namespace: "kube-system", Name: "default", IsServiceAccount: true},
			subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"},
			},
			want: true,
		},
		{
			name:       "service account namespace mismatch",
			userGroups: []string{},
			saInfo:     ServiceAccountInfo{Namespace: "other-ns", Name: "default", IsServiceAccount: true},
			subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"},
			},
			want: false,
		},
		{
			name:       "service account name mismatch",
			userGroups: []string{},
			saInfo:     ServiceAccountInfo{Namespace: "kube-system", Name: "other", IsServiceAccount: true},
			subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"},
			},
			want: false,
		},
		{
			name:       "empty subjects returns false",
			userGroups: []string{"oidc:admin"},
			saInfo:     ServiceAccountInfo{IsServiceAccount: false},
			subjects:   []rbacv1.Subject{},
			want:       false,
		},
		{
			name:       "multiple subjects - matches second",
			userGroups: []string{"oidc:developer"},
			saInfo:     ServiceAccountInfo{IsServiceAccount: false},
			subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "oidc:admin"},
				{Kind: "Group", Name: "oidc:developer"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesSubjects(tt.userGroups, tt.saInfo, tt.subjects)
			if got != tt.want {
				t.Errorf("MatchesSubjects() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRestrictedBindDefinition(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"platform-namespaced-reader-restricted", true},
		{"tenant-namespaced-reader-restricted", true},
		{"platform-namespaced-poweruser", false},
		{"namespaced-reader-restricted-extra", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRestrictedBindDefinition(tt.name); got != tt.want {
				t.Errorf("IsRestrictedBindDefinition(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsFieldIndexError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"index does not exist", fmt.Errorf("Index with name %s does not exist", "foo"), true},
		{"wrapped index error", fmt.Errorf("list failed: %w", fmt.Errorf("Index with name %s does not exist", "bar")), true},
		{"RBAC forbidden", fmt.Errorf("forbidden: User cannot list resource"), false},
		{"network error", fmt.Errorf("dial tcp: connection refused"), false},
		{"generic error", fmt.Errorf("something went wrong"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFieldIndexError(tt.err); got != tt.want {
				t.Errorf("isFieldIndexError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
