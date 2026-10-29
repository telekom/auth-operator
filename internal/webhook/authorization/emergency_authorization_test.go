// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	api "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestEmergencyTenantAdmission(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, api.AddToScheme, authorizationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	identity := authenticationv1.UserInfo{Username: "oidc:alice", UID: "user-123", Groups: []string{"oidc:platform-poweruser", "system:authenticated"}, Extra: map[string]authenticationv1.ExtraValue{"example.com/claim": {"original"}}}
	for _, tc := range []struct {
		name    string
		modify  func(*corev1.Namespace)
		status  authorizationv1.SubjectAccessReviewStatus
		err     error
		allowed bool
		calls   bool
	}{
		{name: "approved", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}, allowed: true, calls: true},
		{name: "protected approved", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyProtected] = "tenant-a" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}, allowed: true, calls: true},
		{name: "cluster-wide tenant scope", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyTenant] = "tenant-b" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}, allowed: true, calls: true},
		{name: "empty tenant", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyTenant] = "" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "empty protected", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyProtected] = "" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "expired", calls: true},
		{name: "revoked", status: authorizationv1.SubjectAccessReviewStatus{Denied: true}, calls: true},
		{name: "contradictory", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}, calls: true},
		{name: "evaluation error", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, EvaluationError: "backend unavailable"}, calls: true},
		{name: "transport error", err: errors.New("unavailable"), calls: true},
		{name: "wrong protected identity", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyProtected] = "tenant-b" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "platform", modify: func(n *corev1.Namespace) { n.Labels = map[string]string{api.LabelKeyOwner: api.OwnerPlatform} }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "addon", modify: func(n *corev1.Namespace) {
			n.Labels = map[string]string{api.LabelKeyOwner: api.OwnerAddon, api.LabelKeyAddon: "demo"}
		}, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "thirdparty", modify: func(n *corev1.Namespace) {
			n.Labels = map[string]string{api.LabelKeyOwner: api.OwnerThirdParty, api.LabelKeyThirdParty: "demo"}
		}, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "missing ownership", modify: func(n *corev1.Namespace) { n.Labels = nil }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "ambiguous ownership", modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyAddon] = "demo" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "system", modify: func(n *corev1.Namespace) { n.Name = "kube-system" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
		{name: "default", modify: func(n *corev1.Namespace) { n.Name = "default" }, status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				review, ok := obj.(*authorizationv1.SubjectAccessReview)
				if !ok {
					t.Fatalf("unexpected create %T", obj)
				}
				calls++
				if review.Spec.User != identity.Username || review.Spec.UID != identity.UID || !reflect.DeepEqual(review.Spec.Groups, identity.Groups) || !reflect.DeepEqual(review.Spec.Extra, map[string]authorizationv1.ExtraValue{"example.com/claim": {"original"}}) {
					t.Fatalf("identity changed: %#v", review.Spec)
				}
				expected := &authorizationv1.ResourceAttributes{Group: "breakglass.t-caas.telekom.com", Resource: "escalationguards", Name: "platform-emergency", Verb: "use"}
				if !reflect.DeepEqual(review.Spec.ResourceAttributes, expected) || review.Spec.NonResourceAttributes != nil {
					t.Fatalf("incorrect permission: %#v", review.Spec)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("missing request deadline")
				}
				review.Status = tc.status
				return tc.err
			}}).Build()
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-test", Labels: map[string]string{api.LabelKeyOwner: api.OwnerTenant, api.LabelKeyTenant: "tenant-a"}}}
			if tc.modify != nil {
				tc.modify(ns)
			}
			raw, _ := json.Marshal(ns)
			for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete} {
				req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: ns.Name, Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Operation: op, Object: runtime.RawExtension{Raw: raw}, OldObject: runtime.RawExtension{Raw: raw}, UserInfo: identity}}
				v := NamespaceValidator{Client: c, Decoder: admission.NewDecoder(scheme), DeletionProtection: true}
				if r := v.Handle(context.Background(), req); r.Allowed != tc.allowed {
					t.Errorf("%s validator allowed=%v want %v: %v", op, r.Allowed, tc.allowed, r.Result)
				}
				if op != admissionv1.Delete {
					m := NamespaceMutator{Client: c, Decoder: admission.NewDecoder(scheme)}
					if r := m.Handle(context.Background(), req); r.Allowed != tc.allowed {
						t.Errorf("%s mutator allowed=%v want %v: %v", op, r.Allowed, tc.allowed, r.Result)
					}
				}
			}
			if (calls > 0) != tc.calls {
				t.Fatalf("SAR calls=%d expected any=%v", calls, tc.calls)
			}
		})
	}
}

func TestEmergencyPreservesDeletionAndOwnershipGuards(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	_ = authorizationv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
		obj.(*authorizationv1.SubjectAccessReview).Status.Allowed = true
		return nil
	}}).Build()
	original := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-test", Labels: map[string]string{api.LabelKeyOwner: api.OwnerTenant, api.LabelKeyTenant: "tenant-a", api.LabelKeyDeletionProtection: "enabled"}}}
	for _, tc := range []struct {
		name    string
		op      admissionv1.Operation
		modify  func(*corev1.Namespace)
		allowed bool
	}{
		{name: "delete denied", op: admissionv1.Delete},
		{name: "confirmed delete", op: admissionv1.Delete, modify: func(n *corev1.Namespace) { n.Annotations = map[string]string{api.AnnotationKeyAllowDeletion: "true"} }, allowed: true},
		{name: "strip deletion protection", op: admissionv1.Update, modify: func(n *corev1.Namespace) { delete(n.Labels, api.LabelKeyDeletionProtection) }},
		{name: "transfer tenant", op: admissionv1.Update, modify: func(n *corev1.Namespace) { n.Labels[api.LabelKeyTenant] = "tenant-b" }},
		{name: "transfer platform", op: admissionv1.Update, modify: func(n *corev1.Namespace) { n.Labels = map[string]string{api.LabelKeyOwner: api.OwnerPlatform} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := original.DeepCopy()
			if tc.modify != nil {
				tc.modify(ns)
			}
			raw, _ := json.Marshal(ns)
			old, _ := json.Marshal(original)
			if tc.op == admissionv1.Delete {
				old = raw
			}
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: ns.Name, Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Operation: tc.op, Object: runtime.RawExtension{Raw: raw}, OldObject: runtime.RawExtension{Raw: old}, UserInfo: authenticationv1.UserInfo{Username: "oidc:alice"}}}
			v := NamespaceValidator{Client: c, Decoder: admission.NewDecoder(scheme), DeletionProtection: true}
			if r := v.Handle(context.Background(), req); r.Allowed != tc.allowed {
				t.Fatalf("allowed=%v want %v: %v", r.Allowed, tc.allowed, r.Result)
			}
			if tc.op == admissionv1.Update && tc.name != "strip deletion protection" {
				m := NamespaceMutator{Client: c, Decoder: admission.NewDecoder(scheme)}
				if r := m.Handle(context.Background(), req); r.Allowed {
					t.Fatal("mutator allowed ownership transfer")
				}
			}
		})
	}
}

// Existing namespace bindings must not depend on emergency authorization availability.
func TestEmergencyOrdinaryBindingsDoNotReview(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	labels := map[string]string{api.LabelKeyOwner: api.OwnerTenant, api.LabelKeyTenant: "tenant-a"}
	bd := &api.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "ordinary"}, Spec: api.BindDefinitionSpec{
		Subjects:     []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "oidc:alice", APIGroup: rbacv1.GroupName}},
		RoleBindings: []api.NamespaceBinding{{ClusterRoleRefs: []string{"view"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: labels}}}},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			t.Fatal("ordinary namespace binding attempted an emergency review")
			return errors.New("unexpected review")
		},
	}).Build()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-test", Labels: labels}}
	raw, err := json.Marshal(ns)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete} {
		req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Name: ns.Name, Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Operation: op,
			Object: runtime.RawExtension{Raw: raw}, OldObject: runtime.RawExtension{Raw: raw},
			UserInfo: authenticationv1.UserInfo{Username: "oidc:alice"},
		}}
		validator := NamespaceValidator{Client: c, Decoder: admission.NewDecoder(scheme), DeletionProtection: true}
		if response := validator.Handle(context.Background(), req); !response.Allowed {
			t.Fatalf("%s validation: %v", op, response.Result)
		}
		if op != admissionv1.Delete {
			mutator := NamespaceMutator{Client: c, Decoder: admission.NewDecoder(scheme)}
			if response := mutator.Handle(context.Background(), req); !response.Allowed {
				t.Fatalf("%s mutation: %v", op, response.Result)
			}
		}
	}
}
