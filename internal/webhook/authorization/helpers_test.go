package webhooks

import (
	"context"
	"fmt"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

func TestCheckBypass(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		groups       []string
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
			name:       "system:masters group always bypasses",
			username:   "cluster-admin-user",
			groups:     []string{"system:masters"},
			operation:  admissionv1.Update,
			namespace:  "test-ns",
			wantBypass: true,
			wantReason: "system:masters",
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
			result := CheckBypass(tt.username, tt.groups, tt.operation, tt.namespace, tt.tdgMigration)
			if result.ShouldBypass != tt.wantBypass {
				t.Errorf("CheckBypass() ShouldBypass = %v, want %v", result.ShouldBypass, tt.wantBypass)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("CheckBypass() Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestCheckBypassValidatorCases(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		groups       []string
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
			name:       "system:masters group always bypasses",
			username:   "cluster-admin-user",
			groups:     []string{"system:masters"},
			operation:  admissionv1.Update,
			namespace:  "test-ns",
			wantBypass: true,
			wantReason: "system:masters",
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
			result := CheckBypass(tt.username, tt.groups, tt.operation, tt.namespace, tt.tdgMigration)
			if result.ShouldBypass != tt.wantBypass {
				t.Errorf("CheckBypass() ShouldBypass = %v, want %v", result.ShouldBypass, tt.wantBypass)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("CheckBypass() Reason = %q, want %q", result.Reason, tt.wantReason)
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

func TestGetSANamespaceTrackedLabels(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	tests := []struct {
		name       string
		saInfo     ServiceAccountInfo
		namespaces []corev1.Namespace
		wantLabels map[string]string
		wantErr    bool
	}{
		{
			name:       "not a service account",
			saInfo:     ServiceAccountInfo{IsServiceAccount: false},
			wantLabels: nil,
		},
		{
			name:       "SA namespace does not exist",
			saInfo:     ServiceAccountInfo{Namespace: "nonexistent", Name: "sa", IsServiceAccount: true},
			wantLabels: nil,
		},
		{
			name:   "SA namespace has no tracked labels",
			saInfo: ServiceAccountInfo{Namespace: "my-ns", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "my-ns", Labels: map[string]string{"unrelated": "label"}}},
			},
			wantLabels: nil,
		},
		{
			name:   "SA namespace has owner+tenant labels",
			saInfo: ServiceAccountInfo{Namespace: "tenant-ns", Name: "operator-sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "tenant-ns", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:  "tenant",
					authorizationv1alpha1.LabelKeyTenant: "team-alpha",
				}}},
			},
			wantLabels: map[string]string{
				authorizationv1alpha1.LabelKeyOwner:  "tenant",
				authorizationv1alpha1.LabelKeyTenant: "team-alpha",
			},
		},
		{
			name:   "SA namespace has thirdparty labels",
			saInfo: ServiceAccountInfo{Namespace: "3p-ns", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "3p-ns", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "thirdparty",
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
				}}},
			},
			wantLabels: map[string]string{
				authorizationv1alpha1.LabelKeyOwner:      "thirdparty",
				authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
			},
		},
		{
			name:   "SA namespace has platform label only",
			saInfo: ServiceAccountInfo{Namespace: "platform-ns", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "platform-ns", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "platform",
				}}},
			},
			wantLabels: map[string]string{
				authorizationv1alpha1.LabelKeyOwner: "platform",
			},
		},
		{
			name:   "SA namespace has no labels at all",
			saInfo: ServiceAccountInfo{Namespace: "bare-ns", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "bare-ns"}},
			},
			wantLabels: nil,
		},
		{
			name:   "tenant owner without tenant identifying label - incomplete, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "bad-ns", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "bad-ns", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "tenant",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "thirdparty owner without thirdparty identifying label - incomplete, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "bad-3p", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "bad-3p", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "thirdparty",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "tenant label present without owner label - no owner, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "no-owner", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "no-owner", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyTenant: "team-x",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "platform owner with tenant label - ambiguous, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "ambig-1", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ambig-1", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:  "platform",
					authorizationv1alpha1.LabelKeyTenant: "team-x",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "platform owner with thirdparty label - ambiguous, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "ambig-2", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ambig-2", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "platform",
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "tenant owner with thirdparty label - ambiguous, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "ambig-3", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ambig-3", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "tenant",
					authorizationv1alpha1.LabelKeyTenant:     "team-x",
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "thirdparty owner with tenant label - ambiguous, returns nil",
			saInfo: ServiceAccountInfo{Namespace: "ambig-4", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ambig-4", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "thirdparty",
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
					authorizationv1alpha1.LabelKeyTenant:     "team-x",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "unknown owner value - returns nil",
			saInfo: ServiceAccountInfo{Namespace: "unknown-owner", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "unknown-owner", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "custom-value",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "owner label with empty value - returns nil",
			saInfo: ServiceAccountInfo{Namespace: "empty-owner", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "empty-owner", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "tenant owner with empty tenant value - returns nil",
			saInfo: ServiceAccountInfo{Namespace: "empty-tenant", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "empty-tenant", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:  "tenant",
					authorizationv1alpha1.LabelKeyTenant: "",
				}}},
			},
			wantLabels: nil,
		},
		{
			name:   "thirdparty owner with empty thirdparty value - returns nil",
			saInfo: ServiceAccountInfo{Namespace: "empty-tp", Name: "sa", IsServiceAccount: true},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "empty-tp", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "thirdparty",
					authorizationv1alpha1.LabelKeyThirdParty: "",
				}}},
			},
			wantLabels: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for i := range tt.namespaces {
				builder = builder.WithObjects(&tt.namespaces[i])
			}
			c := builder.Build()

			got, err := GetSANamespaceTrackedLabels(context.Background(), c, tt.saInfo)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantLabels == nil {
				if len(got) != 0 {
					t.Errorf("expected empty labels, got %v", got)
				}
				return
			}

			if len(got) != len(tt.wantLabels) {
				t.Errorf("expected %d labels, got %d: %v", len(tt.wantLabels), len(got), got)
				return
			}
			for k, v := range tt.wantLabels {
				if got[k] != v {
					t.Errorf("expected label %s=%s, got %s", k, v, got[k])
				}
			}
		})
	}
}

func TestGetSANamespaceTrackedLabels_ClientGetError(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	injectedErr := fmt.Errorf("transient API failure")
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return injectedErr
			},
		}).Build()

	saInfo := ServiceAccountInfo{Namespace: "some-ns", Name: "sa", IsServiceAccount: true}
	got, err := GetSANamespaceTrackedLabels(context.Background(), c, saInfo)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(got) != 0 {
		t.Errorf("expected empty labels on error, got %v", got)
	}
}

func TestFindExtraTrackedKey(t *testing.T) {
	tests := []struct {
		name         string
		targetLabels map[string]string
		inherited    map[string]string
		want         string
	}{
		{
			name:         "no extra keys",
			targetLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			inherited:    map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			want:         "",
		},
		{
			name:         "target has no tracked keys",
			targetLabels: map[string]string{"unrelated": "val"},
			inherited:    map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			want:         "",
		},
		{
			name:         "target has extra tenant key",
			targetLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform", authorizationv1alpha1.LabelKeyTenant: "team-x"},
			inherited:    map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			want:         authorizationv1alpha1.LabelKeyTenant,
		},
		{
			name:         "target has extra thirdparty key",
			targetLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform", authorizationv1alpha1.LabelKeyThirdParty: "vendor-x"},
			inherited:    map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			want:         authorizationv1alpha1.LabelKeyThirdParty,
		},
		{
			name:         "target has extra owner key",
			targetLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: "platform"},
			inherited:    map[string]string{authorizationv1alpha1.LabelKeyTenant: "team-x"},
			want:         authorizationv1alpha1.LabelKeyOwner,
		},
		{
			name:         "both empty",
			targetLabels: map[string]string{},
			inherited:    map[string]string{},
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindExtraTrackedKey(tt.targetLabels, tt.inherited)
			if got != tt.want {
				t.Errorf("FindExtraTrackedKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
