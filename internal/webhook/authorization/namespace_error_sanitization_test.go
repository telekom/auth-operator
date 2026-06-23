// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
	"github.com/telekom/auth-operator/pkg/indexer"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type erroringReader struct {
	client.Reader
	listErr error
	getErr  error
}

func (r erroringReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if r.getErr != nil {
		return r.getErr
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (r erroringReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if r.listErr != nil {
		return r.listErr
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestNamespaceMutatorSanitizesListErrors(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	sentinel := errors.New("sentinel backend token leak")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return sentinel
			},
		}).
		Build()
	mutator := &webhooks.NamespaceMutator{
		Client:  fakeClient,
		Reader:  fake.NewClientBuilder().WithScheme(scheme).Build(),
		Decoder: crAdmission.NewDecoder(scheme),
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}
	resp := mutator.Handle(context.Background(), crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Name:      ns.Name,
		UserInfo:  authenticationv1.UserInfo{Username: "alice", Groups: []string{"oidc:team-a"}},
		Object:    runtime.RawExtension{Raw: mustMarshalJSON(t, ns)},
	}})

	if resp.Allowed {
		t.Fatal("expected mutator error response")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 admission error, got %#v", resp.Result)
	}
	if strings.Contains(resp.Result.Message, sentinel.Error()) {
		t.Fatalf("response leaked backend error: %q", resp.Result.Message)
	}
	if !strings.Contains(resp.Result.Message, webhooks.ErrNamespaceWebhookInternal.Error()) {
		t.Fatalf("expected internal admission error, got %q", resp.Result.Message)
	}
}

func TestNamespaceValidatorSanitizesListErrors(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	sentinel := errors.New("sentinel backend token leak")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return sentinel
			},
		}).
		Build()
	validator := &webhooks.NamespaceValidator{
		Client:  fakeClient,
		Reader:  fake.NewClientBuilder().WithScheme(scheme).Build(),
		Decoder: crAdmission.NewDecoder(scheme),
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform},
		},
	}
	resp := validator.Handle(context.Background(), crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"},
		Operation: admissionv1.Create,
		Name:      ns.Name,
		UserInfo:  authenticationv1.UserInfo{Username: "alice", Groups: []string{"oidc:team-a"}},
		Object:    runtime.RawExtension{Raw: mustMarshalJSON(t, ns)},
	}})

	if resp.Allowed {
		t.Fatal("expected validator error response")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 admission error, got %#v", resp.Result)
	}
	if strings.Contains(resp.Result.Message, sentinel.Error()) {
		t.Fatalf("response leaked backend error: %q", resp.Result.Message)
	}
	if !strings.Contains(resp.Result.Message, webhooks.ErrNamespaceWebhookInternal.Error()) {
		t.Fatalf("expected internal admission error, got %q", resp.Result.Message)
	}
}

func TestNamespaceValidatorUsesCachedCandidatesAndLiveGet(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "cached-candidate"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "cached-candidate",
			Subjects: []rbacv1.Subject{
				{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "oidc:team-a"},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"admin"},
				NamespaceSelector: []metav1.LabelSelector{{
					MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform},
				}},
			}},
		},
	}
	cachedClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).
		WithObjects(bd.DeepCopy()).
		Build()
	liveClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd.DeepCopy()).Build()
	validator := &webhooks.NamespaceValidator{
		Client:  cachedClient,
		Reader:  erroringReader{Reader: liveClient, listErr: errors.New("live list must not be called")},
		Decoder: crAdmission.NewDecoder(scheme),
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform},
		},
	}
	resp := validator.Handle(context.Background(), crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"},
		Operation: admissionv1.Create,
		Name:      ns.Name,
		UserInfo:  authenticationv1.UserInfo{Username: "alice", Groups: []string{"oidc:team-a"}},
		Object:    runtime.RawExtension{Raw: mustMarshalJSON(t, ns)},
	}})

	if !resp.Allowed {
		t.Fatalf("expected namespace request to be allowed via cached candidate and live Get, got: %v", resp.Result)
	}
}
