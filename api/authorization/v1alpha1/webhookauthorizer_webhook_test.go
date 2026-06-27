// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

var _ = Describe("WebhookAuthorizer CEL Validation", func() {

	validResourceRules := []authzv1.ResourceRule{
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
	}

	validAllowedPrincipals := []Principal{
		{User: "admin"},
	}

	Context("When creating WebhookAuthorizer under CEL validation", func() {

		It("Should admit a valid WebhookAuthorizer with resourceRules and allowedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules:     validResourceRules,
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("Should deny a WebhookAuthorizer without resourceRules or nonResourceRules", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-rules",
				},
				Spec: WebhookAuthorizerSpec{
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one resourceRules or nonResourceRules must be specified"))
		})

		It("Should deny a WebhookAuthorizer without allowedPrincipals or deniedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-no-principals",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules: validResourceRules,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one allowedPrincipals or deniedPrincipals must be specified"))
		})

		It("Should deny a WebhookAuthorizer with empty resourceRules and nonResourceRules slices", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-empty-rules",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules:     []authzv1.ResourceRule{},
					NonResourceRules:  []authzv1.NonResourceRule{},
					AllowedPrincipals: validAllowedPrincipals,
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one resourceRules or nonResourceRules must be specified"))
		})

		It("Should admit a WebhookAuthorizer with only nonResourceRules", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa-nonresource",
				},
				Spec: WebhookAuthorizerSpec{
					NonResourceRules: []authzv1.NonResourceRule{
						{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}},
					},
					DeniedPrincipals: []Principal{
						{User: "bad-actor"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("Should admit a WebhookAuthorizer with only deniedPrincipals", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-wa-denied",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules: validResourceRules,
					DeniedPrincipals: []Principal{
						{User: "blocked-user"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, wa)).To(Succeed())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, wa)).To(Succeed())
		})

		It("Should deny a WebhookAuthorizer with an empty principal item", func() {
			wa := &WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cel-empty-principal",
				},
				Spec: WebhookAuthorizerSpec{
					ResourceRules: validResourceRules,
					AllowedPrincipals: []Principal{
						{},
					},
				},
			}
			err := k8sClient.Create(ctx, wa)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("principal must specify user or at least one group"))
		})
	})
})

// --- WebhookAuthorizer validating webhook unit tests ---

func newTestWebhookAuthorizer(opts ...func(*WebhookAuthorizer)) *WebhookAuthorizer {
	wa := &WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-wa"},
		Spec: WebhookAuthorizerSpec{
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
			AllowedPrincipals: []Principal{{User: "alice"}},
		},
	}
	for _, opt := range opts {
		opt(wa)
	}
	return wa
}

func TestValidateCreate_ValidMinimal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer()
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateCreate_InvalidNamespaceSelector(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.NamespaceSelector = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: "InvalidOp", Values: []string{"v1"}},
			},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for invalid namespace selector")
	}
}

func TestValidateCreate_EmptyRules(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = nil
		wa.Spec.NonResourceRules = nil
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestValidateCreate_ResourceRuleNoVerbs(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = []authzv1.ResourceRule{
			{Verbs: []string{}, APIGroups: []string{""}, Resources: []string{"pods"}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for resource rule with no verbs")
	}
}

func TestValidateCreate_NonResourceRuleNoVerbs(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = nil
		wa.Spec.NonResourceRules = []authzv1.NonResourceRule{
			{Verbs: []string{}, NonResourceURLs: []string{"/healthz"}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for non-resource rule with no verbs")
	}
}

func TestValidateCreate_NonResourceRuleNoPaths(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = nil
		wa.Spec.NonResourceRules = []authzv1.NonResourceRule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for non-resource rule with no paths")
	}
}

func TestValidateCreate_RejectsNamespaceSelectorWithNonResourceRules(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.NonResourceRules = []authzv1.NonResourceRule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{"/logs"}},
		}
		wa.Spec.NamespaceSelector = metav1.LabelSelector{
			MatchLabels: map[string]string{"environment": "prod"},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for namespaceSelector with nonResourceRules")
	}
	if got := err.Error(); !containsAll(got, "namespaceSelector", "nonResourceRules", "no namespace") {
		t.Fatalf("expected namespaceSelector/nonResourceRules error, got %q", got)
	}
}

func TestValidateCreate_WarnsEmptyAllowedPrincipals(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = nil
		wa.Spec.DeniedPrincipals = []Principal{{User: "blocked-user"}}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning for empty allowedPrincipals")
	}
}

func TestValidateCreate_RejectsNoPrincipals(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = nil
		wa.Spec.DeniedPrincipals = nil
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for missing principals")
	}
	if got := err.Error(); !containsAll(got, "allowedPrincipals", "deniedPrincipals", "non-empty") {
		t.Fatalf("expected missing principals error, got %q", got)
	}
}

func TestValidateCreate_RejectsEmptyAllowedPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{}}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for empty allowed principal")
	}
	if got := err.Error(); !containsAll(got, "allowedPrincipals[0]", "user", "group") {
		t.Fatalf("expected empty principal error, got %q", got)
	}
}

func TestValidateCreate_RejectsEmptyDeniedPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = nil
		wa.Spec.DeniedPrincipals = []Principal{{}}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for empty denied principal")
	}
	if got := err.Error(); !containsAll(got, "deniedPrincipals[0]", "user", "group") {
		t.Fatalf("expected empty principal error, got %q", got)
	}
}

func TestValidateCreate_WarnsOverlappingPrincipals(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{User: "alice"}}
		wa.Spec.DeniedPrincipals = []Principal{{User: "alice"}}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning for overlapping principals")
	}
}

func TestValidateCreate_WarnsOverlappingGroups(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{Groups: []string{"admins"}}}
		wa.Spec.DeniedPrincipals = []Principal{{Groups: []string{"admins"}}}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning for overlapping groups")
	}
}

func TestValidateCreate_AllowsNamespacedServiceAccountPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{User: "deployer", Namespace: "team-a"}}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error for namespaced ServiceAccount principal, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateCreate_AllowsQualifiedNamespacedServiceAccountPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{
			User:      "system:serviceaccount:team-a:deployer",
			Namespace: "team-a",
		}}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error for qualified namespaced ServiceAccount principal, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateCreate_RejectsQualifiedServiceAccountNamespaceMismatch(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{
			User:      "system:serviceaccount:team-b:deployer",
			Namespace: "team-a",
		}}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for mismatched qualified ServiceAccount namespace")
	}
	if got := err.Error(); !containsAll(got, "allowedPrincipals[0]", "team-a", "team-b") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCreate_RejectsNamespaceOnlyPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{Namespace: "team-a"}}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for namespace-only principal")
	}
	if got := err.Error(); !containsAll(got, "allowedPrincipals[0]", "requires", "user") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCreate_RejectsNamespacedGroupPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.DeniedPrincipals = []Principal{{Groups: []string{"admins"}, Namespace: "team-a"}}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for namespaced group principal")
	}
	if got := err.Error(); !containsAll(got, "deniedPrincipals[0]", "cannot be combined", "groups") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUpdate_AlwaysValidates(t *testing.T) {
	// Kubernetes increments Generation after admission webhooks run, so
	// old and new generations are always equal during the admission call.
	// ValidateUpdate must always validate the new spec regardless.
	v := &WebhookAuthorizerValidator{}
	oldObj := newTestWebhookAuthorizer()
	oldObj.Generation = 1
	newObj := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = nil
		wa.Spec.NonResourceRules = nil
	})
	newObj.Generation = 1
	_, err := v.ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil {
		t.Fatal("expected error for invalid new spec even with same generation")
	}
}

func TestValidateUpdate_RejectsEmptyPrincipal(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	oldObj := newTestWebhookAuthorizer()
	newObj := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = []Principal{{}}
	})
	_, err := v.ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil {
		t.Fatal("expected update to reject empty principal")
	}
	if got := err.Error(); !containsAll(got, "allowedPrincipals[0]", "user", "group") {
		t.Fatalf("expected empty principal error, got %q", got)
	}
}

func TestValidateUpdate_ValidSpecPasses(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	oldObj := newTestWebhookAuthorizer()
	oldObj.Generation = 1
	newObj := newTestWebhookAuthorizer()
	newObj.Generation = 1
	_, err := v.ValidateUpdate(context.Background(), oldObj, newObj)
	if err != nil {
		t.Fatalf("expected no error for valid spec, got: %v", err)
	}
}

func TestValidateDelete_AlwaysAllows(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer()
	_, err := v.ValidateDelete(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error for delete, got: %v", err)
	}
}

func TestValidateCreate_ValidNonResourceRules(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = nil
		wa.Spec.NonResourceRules = []authzv1.NonResourceRule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz", "/metrics"}},
		}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
}

func TestValidateCreate_ValidNamespaceSelector(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.NamespaceSelector = metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
}

func TestFindPrincipalOverlaps_NoOverlap(t *testing.T) {
	result := findPrincipalOverlaps(
		[]Principal{{User: "alice"}},
		[]Principal{{User: "bob"}},
	)
	if len(result) != 0 {
		t.Errorf("expected no overlap, got: %v", result)
	}
}

func TestFindPrincipalOverlaps_Empty(t *testing.T) {
	result := findPrincipalOverlaps(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected no overlap, got: %v", result)
	}
}

func TestIsLabelSelectorEmpty_Nil(t *testing.T) {
	if !isLabelSelectorEmpty(nil) {
		t.Error("expected nil selector to be empty")
	}
}

func TestIsLabelSelectorEmpty_Empty(t *testing.T) {
	if !isLabelSelectorEmpty(&metav1.LabelSelector{}) {
		t.Error("expected empty selector to be empty")
	}
}

func TestIsLabelSelectorEmpty_NotEmpty(t *testing.T) {
	sel := &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "test"},
	}
	if isLabelSelectorEmpty(sel) {
		t.Error("expected non-empty selector to not be empty")
	}
}

func TestValidateCreate_WildcardVerb(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = []authzv1.ResourceRule{
			{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error for wildcard verb, got: %v", err)
	}
}

func TestFindNeverMatchingPrincipals(t *testing.T) {
	tests := []struct {
		name       string
		fieldName  string
		principals []Principal
		wantCount  int
	}{
		{
			name:      "nil principals",
			fieldName: "allowedPrincipals",
			wantCount: 0,
		},
		{
			name:       "user set, no warning",
			fieldName:  "allowedPrincipals",
			principals: []Principal{{User: "alice", Namespace: "ns-a"}},
			wantCount:  0,
		},
		{
			name:       "groups set, no warning",
			fieldName:  "deniedPrincipals",
			principals: []Principal{{Groups: []string{"devs"}, Namespace: "ns-a"}},
			wantCount:  0,
		},
		{
			name:       "namespace only, warns",
			fieldName:  "allowedPrincipals",
			principals: []Principal{{Namespace: "ns-a"}},
			wantCount:  1,
		},
		{
			name:      "multiple with mixed, warns for namespace-only",
			fieldName: "deniedPrincipals",
			principals: []Principal{
				{User: "alice", Namespace: "ns-a"},
				{Namespace: "ns-b"},
				{Namespace: "ns-c"},
			},
			wantCount: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := findNeverMatchingPrincipals(tt.fieldName, tt.principals)
			if len(warnings) != tt.wantCount {
				t.Errorf("expected %d warnings, got %d: %v", tt.wantCount, len(warnings), warnings)
			}
		})
	}
}

func TestFindPrincipalOverlaps_CrossNamespace(t *testing.T) {
	// Namespace-scoped principals represent ServiceAccounts, so the same
	// ServiceAccount name in different namespaces is not the same identity.
	overlaps := findPrincipalOverlaps(
		[]Principal{{User: "alice", Namespace: "ns-a"}},
		[]Principal{{User: "alice", Namespace: "ns-b"}},
	)
	if len(overlaps) != 0 {
		t.Errorf("expected no overlap, got: %v", overlaps)
	}
}

func TestFindPrincipalOverlaps_ServiceAccountSameNamespace(t *testing.T) {
	overlaps := findPrincipalOverlaps(
		[]Principal{{User: "deployer", Namespace: "team-a"}},
		[]Principal{{User: "deployer", Namespace: "team-a"}},
	)
	if len(overlaps) != 1 || overlaps[0] != "serviceaccount:team-a/deployer" {
		t.Errorf("expected overlap [serviceaccount:team-a/deployer], got: %v", overlaps)
	}
}

func TestFindPrincipalOverlaps_ServiceAccountShortAndQualified(t *testing.T) {
	overlaps := findPrincipalOverlaps(
		[]Principal{{User: "deployer", Namespace: "team-a"}},
		[]Principal{{User: "system:serviceaccount:team-a:deployer", Namespace: "team-a"}},
	)
	if len(overlaps) != 1 || overlaps[0] != "serviceaccount:team-a/deployer" {
		t.Errorf("expected overlap [serviceaccount:team-a/deployer], got: %v", overlaps)
	}
}

func TestValidateCreate_ResourceRuleNoAPIGroups(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = []authzv1.ResourceRule{
			{Verbs: []string{"get"}, APIGroups: []string{}, Resources: []string{"pods"}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for resource rule with no API groups")
	}
}

func TestValidateCreate_ResourceRuleNoResources(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.ResourceRules = []authzv1.ResourceRule{
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{}},
		}
	})
	_, err := v.ValidateCreate(context.Background(), wa)
	if err == nil {
		t.Fatal("expected error for resource rule with no resources")
	}
}

func TestFindPrincipalOverlaps_UserAndGroupDisambiguated(t *testing.T) {
	// A user "admins" and a group "admins" should produce distinct overlap entries.
	overlaps := findPrincipalOverlaps(
		[]Principal{{User: "admins", Groups: []string{"admins"}}},
		[]Principal{{User: "admins", Groups: []string{"admins"}}},
	)
	if len(overlaps) != 2 {
		t.Fatalf("expected 2 overlaps (user + group), got %d: %v", len(overlaps), overlaps)
	}
	hasUser, hasGroup := false, false
	for _, o := range overlaps {
		if o == "user:admins" {
			hasUser = true
		}
		if o == "group:admins" {
			hasGroup = true
		}
	}
	if !hasUser || !hasGroup {
		t.Errorf("expected [user:admins, group:admins], got: %v", overlaps)
	}
}
