// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// NOTE: TestMain is defined in this file and applies to ALL *_test.go files in
// package webhooks that use the standard testing package (not Ginkgo). It
// configures a discard logger to suppress log noise during unit tests.
// Do NOT define a second TestMain in this package — it will cause a compile error.
//
// These tests intentionally do NOT use t.Parallel() because they share global
// Prometheus metric state via metrics.WebhookRequestsTotal.

func TestMain(m *testing.M) {
	logf.SetLogger(zap.New(zap.WriteTo(io.Discard)))
	os.Exit(m.Run())
}

func mustMarshal(t *testing.T, obj runtime.Object) []byte {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	data, err := runtime.Encode(clientgoscheme.Codecs.LegacyCodec(corev1.SchemeGroupVersion), obj)
	if err != nil {
		t.Fatalf("failed to marshal object: %v", err)
	}
	return data
}

func newDecoder() admission.Decoder {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	return admission.NewDecoder(scheme)
}

func TestDecodeNamespaces_Create(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	nsData := mustMarshal(t, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
	})

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: nsData},
		},
	}

	ns, _, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		t.Fatalf("unexpected error response: %v", errResp.Result)
	}
	if ns.Name != "test-ns" {
		t.Errorf("expected namespace name 'test-ns', got %q", ns.Name)
	}
}

func TestDecodeNamespaces_Update(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	newNs := mustMarshal(t, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"new": "label"}},
	})
	oldNs := mustMarshal(t, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"old": "label"}},
	})

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: newNs},
			OldObject: runtime.RawExtension{Raw: oldNs},
		},
	}

	ns, old, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		t.Fatalf("unexpected error response: %v", errResp.Result)
	}
	if ns.Labels["new"] != "label" {
		t.Error("expected new namespace to have 'new: label'")
	}
	if old.Labels["old"] != "label" {
		t.Error("expected old namespace to have 'old: label'")
	}
}

func TestDecodeNamespaces_Delete(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	oldNs := mustMarshal(t, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "deleted-ns"},
	})

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			OldObject: runtime.RawExtension{Raw: oldNs},
		},
	}

	ns, _, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		t.Fatalf("unexpected error response: %v", errResp.Result)
	}
	if ns.Name != "deleted-ns" {
		t.Errorf("expected namespace name 'deleted-ns', got %q", ns.Name)
	}
}

func TestDecodeNamespaces_UnknownOperation(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Connect,
		},
	}

	_, _, errResp := v.decodeNamespaces(logger, req)
	if errResp == nil {
		t.Fatal("expected a response for unknown operation")
	}
	if !errResp.Allowed {
		t.Error("expected unknown operation to be allowed")
	}
}

func TestDecodeNamespaces_InvalidJSON(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: []byte("not-json")},
		},
	}

	_, _, errResp := v.decodeNamespaces(logger, req)
	if errResp == nil {
		t.Fatal("expected error response for invalid JSON")
	}
	if errResp.Allowed {
		t.Error("expected decode error to deny the request")
	}
}

func TestDetectOwnerReclassification(t *testing.T) {
	tests := []struct {
		name     string
		tdg      bool
		bypass   BypassCheckResult
		oldOwner string
		newOwner string
		expected bool
	}{
		{
			name:     "no TDG migration",
			tdg:      false,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "tenant",
			newOwner: "thirdparty",
			expected: false,
		},
		{
			name:     "not a bypass user",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: false},
			oldOwner: "tenant",
			newOwner: "thirdparty",
			expected: false,
		},
		{
			name:     "same owner - no reclassification",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "tenant",
			newOwner: "tenant",
			expected: false,
		},
		{
			name:     "platform to tenant - denied",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "platform",
			newOwner: "tenant",
			expected: false,
		},
		{
			name:     "tenant to platform - denied",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "tenant",
			newOwner: "platform",
			expected: false,
		},
		{
			name:     "empty old owner - denied",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "",
			newOwner: "tenant",
			expected: false,
		},
		{
			name:     "empty new owner - denied",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "tenant",
			newOwner: "",
			expected: false,
		},
		{
			name:     "tenant to thirdparty - allowed",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "tenant",
			newOwner: "thirdparty",
			expected: true,
		},
		{
			name:     "thirdparty to tenant - allowed",
			tdg:      true,
			bypass:   BypassCheckResult{ShouldBypass: true},
			oldOwner: "thirdparty",
			newOwner: "tenant",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &NamespaceValidator{TDGMigration: tt.tdg}
			logger := logf.FromContext(context.Background())
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: "test-ns"}}

			oldNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{authzv1alpha1.LabelKeyOwner: tt.oldOwner},
			}}
			newNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{authzv1alpha1.LabelKeyOwner: tt.newOwner},
			}}

			result := v.detectOwnerReclassification(logger, req, newNs, oldNs, tt.bypass)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateLabelImmutability(t *testing.T) {
	tests := []struct {
		name       string
		tdg        bool
		bypass     BypassCheckResult
		oldLabels  map[string]string
		newLabels  map[string]string
		expectDeny bool
		denySubstr string
	}{
		{
			name:       "no labels - allowed",
			oldLabels:  nil,
			newLabels:  nil,
			expectDeny: false,
		},
		{
			name:       "initial adoption - allowed",
			oldLabels:  map[string]string{},
			newLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectDeny: false,
		},
		{
			name:       "modify owner label - denied",
			oldLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			newLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "platform"},
			expectDeny: true,
			denySubstr: authzv1alpha1.LabelKeyOwner,
		},
		{
			name:       "remove tenant label - denied",
			oldLabels:  map[string]string{authzv1alpha1.LabelKeyTenant: "team-a"},
			newLabels:  map[string]string{},
			expectDeny: true,
			denySubstr: authzv1alpha1.LabelKeyTenant,
		},
		{
			name:       "unchanged labels - allowed",
			oldLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant", authzv1alpha1.LabelKeyTenant: "team-a"},
			newLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant", authzv1alpha1.LabelKeyTenant: "team-a"},
			expectDeny: false,
		},
		{
			name:       "non-managed label change - allowed",
			oldLabels:  map[string]string{"custom-label": "old"},
			newLabels:  map[string]string{"custom-label": "new"},
			expectDeny: false,
		},
		{
			name:   "bypass user legacy label removal with new owner - allowed",
			tdg:    true,
			bypass: BypassCheckResult{ShouldBypass: true},
			oldLabels: map[string]string{
				legacyOwnerLabel:             "tenant",
				authzv1alpha1.LabelKeyOwner:  "tenant",
				authzv1alpha1.LabelKeyTenant: "team-a",
			},
			newLabels: map[string]string{
				authzv1alpha1.LabelKeyOwner:  "tenant",
				authzv1alpha1.LabelKeyTenant: "team-a",
			},
			expectDeny: false,
		},
		{
			name:   "bypass user legacy label removal without new owner - denied",
			tdg:    true,
			bypass: BypassCheckResult{ShouldBypass: true},
			oldLabels: map[string]string{
				legacyOwnerLabel: "tenant",
			},
			newLabels:  map[string]string{},
			expectDeny: true,
			denySubstr: legacyOwnerLabel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &NamespaceValidator{TDGMigration: tt.tdg}
			logger := logf.FromContext(context.Background())
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Name:      "test-ns",
				Operation: admissionv1.Update,
			}}

			oldNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: tt.oldLabels}}
			newNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: tt.newLabels}}

			resp := v.validateLabelImmutability(logger, req, newNs, oldNs, tt.bypass)
			if tt.expectDeny {
				if resp == nil {
					t.Fatal("expected denial response, got nil")
				}
				if resp.Allowed {
					t.Error("expected response to deny, but it allowed")
				}
				if tt.denySubstr != "" && resp.Result != nil {
					msg := resp.Result.Message
					if !strings.Contains(msg, tt.denySubstr) {
						t.Errorf("expected denial message to contain %q, got %q", tt.denySubstr, msg)
					}
				}
			} else {
				if resp != nil {
					t.Errorf("expected nil (pass), got response: allowed=%v", resp.Allowed)
				}
			}
		})
	}
}

func TestCrossValidateLegacyLabels(t *testing.T) {
	tests := []struct {
		name       string
		tdg        bool
		oldLabels  map[string]string
		newLabels  map[string]string
		expectDeny bool
	}{
		{
			name:       "TDG disabled - always passes",
			tdg:        false,
			oldLabels:  map[string]string{legacyOwnerLabel: "platform"},
			newLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectDeny: false,
		},
		{
			name:       "no legacy label - passes",
			tdg:        true,
			oldLabels:  map[string]string{},
			newLabels:  map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectDeny: false,
		},
		{
			name:       "old owner already exists - skip validation",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "platform", authzv1alpha1.LabelKeyOwner: "platform"},
			newLabels:  map[string]string{legacyOwnerLabel: "platform", authzv1alpha1.LabelKeyOwner: "platform"},
			expectDeny: false,
		},
		{
			name:       "legacy platform to new platform - allowed",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "platform"},
			newLabels:  map[string]string{legacyOwnerLabel: "platform", authzv1alpha1.LabelKeyOwner: "platform"},
			expectDeny: false,
		},
		{
			name:       "legacy schiff to new platform - allowed",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "schiff"},
			newLabels:  map[string]string{legacyOwnerLabel: "schiff", authzv1alpha1.LabelKeyOwner: "platform"},
			expectDeny: false,
		},
		{
			name:       "legacy platform to new tenant - denied",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "platform"},
			newLabels:  map[string]string{legacyOwnerLabel: "platform", authzv1alpha1.LabelKeyOwner: "tenant"},
			expectDeny: true,
		},
		{
			name:       "legacy tenant to new platform - denied",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "tenant"},
			newLabels:  map[string]string{legacyOwnerLabel: "tenant", authzv1alpha1.LabelKeyOwner: "platform"},
			expectDeny: true,
		},
		{
			name:       "legacy tenant to new tenant - allowed",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "tenant"},
			newLabels:  map[string]string{legacyOwnerLabel: "tenant", authzv1alpha1.LabelKeyOwner: "tenant"},
			expectDeny: false,
		},
		{
			name:       "legacy tenant to new thirdparty - allowed",
			tdg:        true,
			oldLabels:  map[string]string{legacyOwnerLabel: "tenant"},
			newLabels:  map[string]string{legacyOwnerLabel: "tenant", authzv1alpha1.LabelKeyOwner: "thirdparty"},
			expectDeny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &NamespaceValidator{TDGMigration: tt.tdg}
			logger := logf.FromContext(context.Background())
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Name:      "test-ns",
				Operation: admissionv1.Update,
			}}

			oldNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: tt.oldLabels}}
			newNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: tt.newLabels}}

			resp := v.crossValidateLegacyLabels(logger, req, newNs, oldNs)
			if tt.expectDeny {
				if resp == nil {
					t.Fatal("expected denial response, got nil")
				}
				if resp.Allowed {
					t.Error("expected denial, got allowed")
				}
			} else {
				if resp != nil {
					t.Errorf("expected nil (pass), got denial: %v", resp.Result)
				}
			}
		})
	}
}

func TestAuthorizeViaBindDefinitions(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	bd := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bd"},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "allowed-group"},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{MatchLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"}},
				},
			}},
		},
	}

	tests := []struct {
		name     string
		bindDefs []authzv1alpha1.BindDefinition
		username string
		groups   []string
		nsLabels map[string]string
		expectOK bool
	}{
		{
			name:     "authorized group member",
			bindDefs: []authzv1alpha1.BindDefinition{bd},
			username: "user1",
			groups:   []string{"allowed-group"},
			nsLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectOK: true,
		},
		{
			name:     "unauthorized user - no matching group",
			bindDefs: []authzv1alpha1.BindDefinition{bd},
			username: "user2",
			groups:   []string{"other-group"},
			nsLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectOK: false,
		},
		{
			name:     "authorized group but namespace labels don't match",
			bindDefs: []authzv1alpha1.BindDefinition{bd},
			username: "user1",
			groups:   []string{"allowed-group"},
			nsLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "platform"},
			expectOK: false,
		},
		{
			name:     "no BindDefinitions - denied",
			bindDefs: []authzv1alpha1.BindDefinition{},
			username: "user1",
			groups:   []string{"allowed-group"},
			nsLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectOK: false,
		},
		{
			name: "service account match",
			bindDefs: []authzv1alpha1.BindDefinition{{
				ObjectMeta: metav1.ObjectMeta{Name: "sa-bd"},
				Spec: authzv1alpha1.BindDefinitionSpec{
					TargetName: "sa-target",
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "my-sa", Namespace: "my-ns"},
					},
					RoleBindings: []authzv1alpha1.NamespaceBinding{{
						ClusterRoleRefs: []string{"admin"},
						NamespaceSelector: []metav1.LabelSelector{
							{MatchLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"}},
						},
					}},
				},
			}},
			username: "system:serviceaccount:my-ns:my-sa",
			groups:   []string{},
			nsLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
			expectOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]runtime.Object, len(tt.bindDefs))
			for i := range tt.bindDefs {
				objs[i] = &tt.bindDefs[i]
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

			v := &NamespaceValidator{Client: fakeClient}
			logger := logf.FromContext(context.Background())
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-ns",
				Labels: tt.nsLabels,
			}}

			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Name:      "test-ns",
				Operation: admissionv1.Create,
				UserInfo: authenticationv1.UserInfo{
					Username: tt.username,
					Groups:   tt.groups,
				},
			}}

			resp := v.authorizeViaBindDefinitions(context.Background(), logger, req, ns)
			if tt.expectOK && !resp.Allowed {
				t.Errorf("expected allowed, got denied: %v", resp.Result)
			}
			if !tt.expectOK && resp.Allowed {
				t.Error("expected denied, got allowed")
			}
		})
	}
}

func TestAuthorizeViaBindDefinitions_SkipsRestricted(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	// Create a BindDefinition with a restricted name that should be skipped.
	// The user would match this BD's subjects, but it should be ignored.
	restrictedBD := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "test-namespaced-reader-restricted"},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "restricted-target",
			Subjects: []rbacv1.Subject{
				{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "test-group"},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{MatchLabels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"}},
				},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithRuntimeObjects(&restrictedBD).Build()

	v := &NamespaceValidator{Client: fakeClient}
	logger := logf.FromContext(context.Background())
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "test-ns",
		Labels: map[string]string{authzv1alpha1.LabelKeyOwner: "tenant"},
	}}

	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Name:      "test-ns",
		Operation: admissionv1.Create,
		UserInfo: authenticationv1.UserInfo{
			Username: "user1",
			Groups:   []string{"test-group"},
		},
	}}

	resp := v.authorizeViaBindDefinitions(context.Background(), logger, req, ns)
	if resp.Allowed {
		t.Error("expected denied because the only matching BD is restricted, but got allowed")
	}
}

func TestDecodeNamespaces_InvalidOldObject(t *testing.T) {
	v := &NamespaceValidator{Decoder: newDecoder()}
	logger := logf.FromContext(context.Background())

	validNs := mustMarshal(t, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
	})

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: validNs},
			OldObject: runtime.RawExtension{Raw: []byte("invalid-json")},
		},
	}

	_, _, errResp := v.decodeNamespaces(logger, req)
	if errResp == nil {
		t.Fatal("expected error response for invalid old object JSON")
	}
	if errResp.Allowed {
		t.Error("expected denial for invalid old object")
	}
}

func TestAuthorizeViaBindDefinitions_ListError(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// Intentionally NOT registering authzv1alpha1 so that List fails

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	v := &NamespaceValidator{Client: fakeClient}
	logger := logf.FromContext(context.Background())
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns"}}

	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Name:      "test-ns",
		Operation: admissionv1.Create,
		UserInfo:  authenticationv1.UserInfo{Username: "user1"},
	}}

	resp := v.authorizeViaBindDefinitions(context.Background(), logger, req, ns)
	if resp.Allowed {
		t.Error("expected error response when List fails, got allowed")
	}
}
