// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

func TestValidateCreate_WarnsEmptyAllowedPrincipals(t *testing.T) {
	v := &WebhookAuthorizerValidator{}
	wa := newTestWebhookAuthorizer(func(wa *WebhookAuthorizer) {
		wa.Spec.AllowedPrincipals = nil
	})
	warnings, err := v.ValidateCreate(context.Background(), wa)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning for empty allowedPrincipals")
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
	// Regression: overlap must be detected when the same User appears in
	// allowed and denied with different Namespaces, because the runtime
	// principalMatches checks principal.User == user without namespace.
	overlaps := findPrincipalOverlaps(
		[]Principal{{User: "alice", Namespace: "ns-a"}},
		[]Principal{{User: "alice", Namespace: "ns-b"}},
	)
	if len(overlaps) != 1 || overlaps[0] != "alice" {
		t.Errorf("expected overlap [alice], got: %v", overlaps)
	}
}
