package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestCRDNameFromGVK(t *testing.T) {
	tests := []struct {
		name     string
		gvk      schema.GroupVersionKind
		expected string
	}{
		{
			name: "RoleDefinition",
			gvk: schema.GroupVersionKind{
				Group:   "authorization.t-caas.telekom.com",
				Version: "v1alpha1",
				Kind:    "RoleDefinition",
			},
			expected: "roledefinitions.authorization.t-caas.telekom.com",
		},
		{
			name: "BindDefinition",
			gvk: schema.GroupVersionKind{
				Group:   "authorization.t-caas.telekom.com",
				Version: "v1alpha1",
				Kind:    "BindDefinition",
			},
			expected: "binddefinitions.authorization.t-caas.telekom.com",
		},
		{
			name: "WebhookAuthorizer",
			gvk: schema.GroupVersionKind{
				Group:   "authorization.t-caas.telekom.com",
				Version: "v1alpha1",
				Kind:    "WebhookAuthorizer",
			},
			expected: "webhookauthorizers.authorization.t-caas.telekom.com",
		},
		{
			name: "Policy (ends with y)",
			gvk: schema.GroupVersionKind{
				Group:   "example.com",
				Version: "v1",
				Kind:    "Policy",
			},
			expected: "policies.example.com",
		},
		{
			name: "Address (ends with s)",
			gvk: schema.GroupVersionKind{
				Group:   "example.com",
				Version: "v1",
				Kind:    "Address",
			},
			expected: "addresses.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := crdNameFromGVK(tt.gvk)
			if result != tt.expected {
				t.Errorf("crdNameFromGVK(%v) = %q, want %q", tt.gvk, result, tt.expected)
			}
		})
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		kind     string
		expected string
	}{
		{"RoleDefinition", "roledefinitions"},
		{"Policy", "policies"},
		{"Address", "addresses"},
		{"Pod", "pods"},
		{"Deployment", "deployments"},
		{"Service", "services"},
		{"Ingress", "ingresses"},
		{"Gateway", "gateways"},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			result := pluralize(tt.kind)
			if result != tt.expected {
				t.Errorf("pluralize(%q) = %q, want %q", tt.kind, result, tt.expected)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"RoleDefinition", "roledefinition"},
		{"UPPER", "upper"},
		{"lower", "lower"},
		{"MixedCase", "mixedcase"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toLower(tt.input)
			if result != tt.expected {
				t.Errorf("toLower(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEndsWith(t *testing.T) {
	tests := []struct {
		s        string
		suffix   string
		expected bool
	}{
		{"hello", "lo", true},
		{"hello", "he", false},
		{"hello", "hello", true},
		{"hello", "hellox", false},
		{"", "", true},
		{"a", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.suffix, func(t *testing.T) {
			result := endsWith(tt.s, tt.suffix)
			if result != tt.expected {
				t.Errorf("endsWith(%q, %q) = %v, want %v", tt.s, tt.suffix, result, tt.expected)
			}
		})
	}
}

func TestCRDWaiter_WaitForCRDs_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add apiextensions to scheme: %v", err)
	}

	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "roledefinitions.authorization.t-caas.telekom.com",
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{
				{
					Type:   apiextensionsv1.Established,
					Status: apiextensionsv1.ConditionTrue,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(crd).
		Build()

	logger := zap.New(zap.UseDevMode(true))
	waiter := NewCRDWaiter(fakeClient, logger)

	gvks := []schema.GroupVersionKind{
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "RoleDefinition",
		},
	}

	ctx := context.Background()
	err := waiter.WaitForCRDs(ctx, gvks, 5*time.Second)
	if err != nil {
		t.Errorf("WaitForCRDs() error = %v, want nil", err)
	}
}

func TestCRDWaiter_WaitForCRDs_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add apiextensions to scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := zap.New(zap.UseDevMode(true))
	waiter := NewCRDWaiter(fakeClient, logger)

	gvks := []schema.GroupVersionKind{
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "RoleDefinition",
		},
	}

	ctx := context.Background()
	err := waiter.WaitForCRDs(ctx, gvks, 100*time.Millisecond)
	if err == nil {
		t.Error("WaitForCRDs() expected error for missing CRD, got nil")
	}
}

func TestCRDWaiter_WaitForCRDs_NotEstablished(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add apiextensions to scheme: %v", err)
	}

	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "roledefinitions.authorization.t-caas.telekom.com",
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{
				{
					Type:   apiextensionsv1.Established,
					Status: apiextensionsv1.ConditionFalse,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(crd).
		Build()

	logger := zap.New(zap.UseDevMode(true))
	waiter := NewCRDWaiter(fakeClient, logger)

	gvks := []schema.GroupVersionKind{
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "RoleDefinition",
		},
	}

	ctx := context.Background()
	err := waiter.WaitForCRDs(ctx, gvks, 100*time.Millisecond)
	if err == nil {
		t.Error("WaitForCRDs() expected error for non-established CRD, got nil")
	}
}

func TestCRDWaiter_WaitForCRDs_ContextCancelled(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add apiextensions to scheme: %v", err)
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	logger := logr.Discard()
	waiter := NewCRDWaiter(fakeClient, logger)

	gvks := []schema.GroupVersionKind{
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "RoleDefinition",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waiter.WaitForCRDs(ctx, gvks, 1*time.Minute)
	if err == nil {
		t.Error("WaitForCRDs() expected error for cancelled context, got nil")
	}
}

func TestCRDWaiter_WaitForMultipleCRDs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add apiextensions to scheme: %v", err)
	}

	crd1 := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "roledefinitions.authorization.t-caas.telekom.com",
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{
				{
					Type:   apiextensionsv1.Established,
					Status: apiextensionsv1.ConditionTrue,
				},
			},
		},
	}

	crd2 := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "binddefinitions.authorization.t-caas.telekom.com",
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{
				{
					Type:   apiextensionsv1.Established,
					Status: apiextensionsv1.ConditionTrue,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(crd1, crd2).
		Build()

	logger := zap.New(zap.UseDevMode(true))
	waiter := NewCRDWaiter(fakeClient, logger)

	gvks := []schema.GroupVersionKind{
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "RoleDefinition",
		},
		{
			Group:   "authorization.t-caas.telekom.com",
			Version: "v1alpha1",
			Kind:    "BindDefinition",
		},
	}

	ctx := context.Background()
	err := waiter.WaitForCRDs(ctx, gvks, 5*time.Second)
	if err != nil {
		t.Errorf("WaitForCRDs() error = %v, want nil", err)
	}
}
