// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks_test

import (
	"context"
	"errors"
	"net/http"
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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// A delegated identity does not inherit the wider ownership of the shared
// controller namespace. Test both handlers so neither depends on webhook order.
func TestServiceAccountNamespaceGrantsBoundInheritance(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	const prefix = "t-caas.telekom.com/"
	for _, owner := range []string{"tenant", "thirdparty", "platform"} {
		t.Run(owner, func(t *testing.T) {
			saName := "m2m-sa-" + owner
			own := map[string]string{prefix + "owner": owner}
			if owner != "platform" {
				own[prefix+owner] = "team-a"
			}
			binding := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "delegated-namespace-scope"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:   "delegated-namespace-scope",
					Subjects:     []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "t-caas-controllers", Name: saName}},
					RoleBindings: []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"writer"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: own, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: prefix + "protected", Operator: metav1.LabelSelectorOpDoesNotExist}}}}}},
				},
			}
			// An explicit namespace grant is still a grant: it must not fall back to the hosting namespace.
			explicitNamespaceOnly := binding.DeepCopy()
			explicitNamespaceOnly.Spec.RoleBindings = []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"writer"}, Namespace: "existing-namespace"}}
			// A name-only selector derives no ownership labels but still grants the namespace.
			nameSelector := func(name string) *authorizationv1alpha1.BindDefinition {
				bd := binding.DeepCopy()
				bd.Spec.RoleBindings = []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"writer"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{corev1.LabelMetadataName: name}}}}}
				return bd
			}
			// Grants that never authorize a namespace leave the identity unbound.
			restrictedOnly := binding.DeepCopy()
			restrictedOnly.Name = "delegated-namespaced-reader-restricted"
			clusterRoleBindingOnly := binding.DeepCopy()
			clusterRoleBindingOnly.Spec.RoleBindings = nil
			clusterRoleBindingOnly.Spec.ClusterRoleBindings = authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"viewer"}}
			// Real ServiceAccount tokens carry their namespace group.
			groupSubject := binding.DeepCopy()
			groupSubject.Spec.Subjects = []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:t-caas-controllers"}}
			cases := []struct {
				name    string
				labels  map[string]string
				bound   bool
				allowed bool
				grant   *authorizationv1alpha1.BindDefinition
			}{
				{"own", own, true, true, nil},
				{"platform", map[string]string{prefix + "owner": "platform"}, true, owner == "platform", nil},
				{"other-identity", map[string]string{prefix + "owner": owner, prefix + owner: "team-b"}, true, false, nil},
				{"addon", map[string]string{prefix + "owner": "addon", prefix + "addon": "addon-a"}, true, false, nil},
				{"protected", map[string]string{prefix + "owner": owner, prefix + owner: "team-a", prefix + "protected": "team-a"}, true, false, nil},
				// Removing the last grant must not widen access to the hosting namespace's owner.
				{"unbound-platform-denied", map[string]string{prefix + "owner": "platform"}, false, false, nil},
				// A ServiceAccount the live reader cannot find is never opted in.
				{"unbound-sa-not-found-denied", map[string]string{prefix + "owner": "platform"}, false, false, nil},
				{"restricted-only-platform-denied", map[string]string{prefix + "owner": "platform"}, true, false, restrictedOnly},
				{"clusterrolebinding-only-platform-denied", map[string]string{prefix + "owner": "platform"}, true, false, clusterRoleBindingOnly},
				{"explicit-namespace-only-platform", map[string]string{prefix + "owner": "platform"}, true, false, explicitNamespaceOnly},
				{"name-selector-platform", map[string]string{prefix + "owner": "platform"}, true, true, nameSelector("new-namespace")},
				{"name-selector-other-namespace", map[string]string{prefix + "owner": "platform"}, true, false, nameSelector("other-namespace")},
				{"group-subject-own", own, true, true, groupSubject},
				{"group-subject-platform", map[string]string{prefix + "owner": "platform"}, true, owner == "platform", groupSubject},
			}
			for _, tc := range cases {
				if owner == "platform" && tc.name == "other-identity" {
					tc.labels = map[string]string{prefix + "owner": "platform", prefix + "tenant": "other"}
				}
				grant := binding
				if tc.grant != nil {
					grant = tc.grant
				}
				t.Run(tc.name, func(t *testing.T) {
					objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-caas-controllers", Labels: map[string]string{prefix + "owner": "platform"}}}}
					if tc.bound {
						objects = append(objects, grant)
					}
					// The ServiceAccount exists without the inherit annotation, so
					// denials do not rely on a failed lookup.
					if tc.name != "unbound-sa-not-found-denied" {
						objects = append(objects, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "t-caas-controllers", Name: saName}})
					}
					c := fake.NewClientBuilder().WithScheme(scheme).WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).WithObjects(objects...).Build()
					// The live grant has not reached the webhook cache yet.
					cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects[0]).Build()
					oldBinding := grant.DeepCopy()
					oldBinding.Spec.RoleBindings = nil
					emptyCached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects[0], oldBinding).Build()
					handlers := map[string]crAdmission.Handler{
						"mutator":                      &webhooks.NamespaceMutator{Client: c, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
						"validator":                    &webhooks.NamespaceValidator{Client: c, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
						"mutator-stale-cache":          &webhooks.NamespaceMutator{Client: cached, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
						"validator-stale-cache":        &webhooks.NamespaceValidator{Client: cached, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
						"mutator-empty-cached-grant":   &webhooks.NamespaceMutator{Client: emptyCached, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
						"validator-empty-cached-grant": &webhooks.NamespaceValidator{Client: emptyCached, Reader: c, Decoder: crAdmission.NewDecoder(scheme)},
					}
					ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new-namespace", Labels: tc.labels}}
					op := admissionv1.Create
					req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: op, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:" + saName, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:t-caas-controllers", "system:authenticated"}}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
					if tc.name == "own" {
						unavailable := erroringReader{Reader: c, listErr: errors.New("private backend failure")}
						for name, handler := range map[string]crAdmission.Handler{
							"mutator":   &webhooks.NamespaceMutator{Client: cached, Reader: unavailable, Decoder: crAdmission.NewDecoder(scheme)},
							"validator": &webhooks.NamespaceValidator{Client: cached, Reader: unavailable, Decoder: crAdmission.NewDecoder(scheme)},
						} {
							response := handler.Handle(context.Background(), req)
							if response.Allowed || response.Result == nil || response.Result.Code != http.StatusInternalServerError || response.Result.Message != webhooks.ErrNamespaceWebhookInternal.Error() {
								t.Fatalf("%s did not fail closed with a sanitized live-list error: %+v", name, response)
							}
						}
					}
					for name, handler := range handlers {
						t.Run(name+"/"+string(op), func(t *testing.T) {
							response := handler.Handle(context.Background(), req)
							if response.Allowed != tc.allowed {
								t.Fatalf("allowed=%v, want %v: %+v", response.Allowed, tc.allowed, response.Result)
							}
						})
					}
				})
			}
		})
	}
}

// The transitional opt-outs restore hosting-namespace inheritance on CREATE,
// both for an identity whose grants do not match and for one without grants.
// The annotation lives only in the live reader so a stale cache cannot flip it.
func TestServiceAccountHostingNamespaceOptOuts(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	const prefix = "t-caas.telekom.com/"
	hosting := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-caas-controllers", Labels: map[string]string{prefix + "owner": "platform"}}}
	binding := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "delegated-namespace-scope"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName:   "delegated-namespace-scope",
			Subjects:     []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "t-caas-controllers", Name: "m2m-sa-tenant"}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"writer"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{prefix + "owner": "tenant", prefix + "tenant": "team-a"}}}}},
		},
	}
	cases := []struct {
		name             string
		annotation       *string
		cachedAnnotation *string
		strictDisabled   bool
		allowed          bool
	}{
		{"no-annotation", nil, nil, false, false},
		{"annotation-true", ptr.To("true"), nil, false, true},
		{"annotation-false", ptr.To("false"), nil, false, false},
		{"annotation-other", ptr.To("yes"), nil, false, false},
		{"annotation-capitalised", ptr.To("True"), nil, false, false},
		{"annotation-removed-but-cached-true", nil, ptr.To("true"), false, false},
		{"global-strict-disabled", nil, nil, true, true},
		{"global-strict-disabled-annotation-false", ptr.To("false"), nil, true, true},
	}
	for _, bound := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.name + "/unbound"
			if bound {
				name = tc.name + "/bound"
			}
			t.Run(name, func(t *testing.T) {
				sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "t-caas-controllers", Name: "m2m-sa-tenant"}}
				cachedSA := sa.DeepCopy()
				if tc.cachedAnnotation != nil {
					cachedSA.Annotations = map[string]string{authorizationv1alpha1.AnnotationKeyInheritHostingNamespaceOwnership: *tc.cachedAnnotation}
				}
				objects := []client.Object{hosting}
				if bound {
					objects = append(objects, binding)
				}
				cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append(objects, cachedSA)...).Build()
				if tc.annotation != nil {
					sa.Annotations = map[string]string{authorizationv1alpha1.AnnotationKeyInheritHostingNamespaceOwnership: *tc.annotation}
				}
				live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append(objects, sa)...).Build()
				handlers := map[string]crAdmission.Handler{
					"mutator":   &webhooks.NamespaceMutator{Client: cached, Reader: live, Decoder: crAdmission.NewDecoder(scheme), DisableStrictSANamespaceOwnership: tc.strictDisabled},
					"validator": &webhooks.NamespaceValidator{Client: cached, Reader: live, Decoder: crAdmission.NewDecoder(scheme), DisableStrictSANamespaceOwnership: tc.strictDisabled},
				}
				ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new-namespace", Labels: map[string]string{prefix + "owner": "platform"}}}
				req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: admissionv1.Create, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:m2m-sa-tenant"}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
				for name, handler := range handlers {
					t.Run(name, func(t *testing.T) {
						response := handler.Handle(context.Background(), req)
						if response.Allowed != tc.allowed {
							t.Fatalf("allowed=%v, want %v: %+v", response.Allowed, tc.allowed, response.Result)
						}
					})
				}
			})
		}
	}

	// A failed live ServiceAccount read fails closed instead of treating the SA
	// as opted in or out, with or without grants.
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "t-caas-controllers", Name: "m2m-sa-tenant"}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new-namespace", Labels: map[string]string{prefix + "owner": "platform"}}}
	req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: admissionv1.Create, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:m2m-sa-tenant"}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
	for _, bound := range []bool{true, false} {
		objects := []client.Object{hosting, sa}
		if bound {
			objects = append(objects, binding)
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
		unavailable := erroringReader{Reader: c, getErr: errors.New("private backend failure")}
		for name, handler := range map[string]crAdmission.Handler{
			"mutator":   &webhooks.NamespaceMutator{Client: c, Reader: unavailable, Decoder: crAdmission.NewDecoder(scheme)},
			"validator": &webhooks.NamespaceValidator{Client: c, Reader: unavailable, Decoder: crAdmission.NewDecoder(scheme)},
		} {
			response := handler.Handle(context.Background(), req)
			if response.Allowed || response.Result == nil || response.Result.Code != http.StatusInternalServerError {
				t.Fatalf("%s (bound=%v) did not fail closed on a live ServiceAccount read error: %+v", name, bound, response)
			}
		}
	}
}

// The live grant list and the ServiceAccount read only run when strict mode
// needs them; with the flag off, admission must follow the pre-#617 path.
func TestServiceAccountHostingNamespaceReadsOnlyWhenNeeded(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	const prefix = "t-caas.telekom.com/"
	hosting := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-caas-controllers", Labels: map[string]string{prefix + "owner": "platform"}}}
	tenant := map[string]string{prefix + "owner": "tenant", prefix + "tenant": "team-a"}
	binding := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "delegated-namespace-scope"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName:   "delegated-namespace-scope",
			Subjects:     []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "t-caas-controllers", Name: "m2m-sa-tenant"}},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"writer"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: tenant}}}},
		},
	}
	errSARead := errors.New("unexpected ServiceAccount read")
	errLiveList := errors.New("unexpected live BindDefinition list")
	cases := []struct {
		name           string
		labels         map[string]string
		bound          bool
		strictDisabled bool
	}{
		// The grant matches, so the annotation is irrelevant.
		{"strict-grant-matches", tenant, true, false},
		// Flag off: neither strict read runs.
		{"strict-disabled", map[string]string{prefix + "owner": "platform"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objects := []client.Object{hosting}
			if tc.bound {
				objects = append(objects, binding)
			}
			cached := fake.NewClientBuilder().WithScheme(scheme).WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).WithObjects(objects...).Build()
			live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						return errSARead
					}
					return c.Get(ctx, key, obj, opts...)
				},
			}).Build()
			var reader client.Reader = live
			if tc.strictDisabled {
				reader = erroringReader{Reader: live, listErr: errLiveList}
			}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new-namespace", Labels: tc.labels}}
			req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: admissionv1.Create, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:m2m-sa-tenant"}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
			for name, handler := range map[string]crAdmission.Handler{
				"mutator":   &webhooks.NamespaceMutator{Client: cached, Reader: reader, Decoder: crAdmission.NewDecoder(scheme), DisableStrictSANamespaceOwnership: tc.strictDisabled},
				"validator": &webhooks.NamespaceValidator{Client: cached, Reader: reader, Decoder: crAdmission.NewDecoder(scheme), DisableStrictSANamespaceOwnership: tc.strictDisabled},
			} {
				if response := handler.Handle(context.Background(), req); !response.Allowed {
					t.Fatalf("%s: performed an unneeded read or denied: %+v", name, response.Result)
				}
			}
		})
	}

	// Without grants, a strict CREATE must read the ServiceAccount: only its
	// annotation can authorize inheritance.
	t.Run("strict-no-grants-reads-service-account", func(t *testing.T) {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "t-caas-controllers", Name: "m2m-sa-tenant"}}
		cached := fake.NewClientBuilder().WithScheme(scheme).WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).WithObjects(hosting).Build()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "new-namespace", Labels: map[string]string{prefix + "owner": "platform"}}}
		req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: admissionv1.Create, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:m2m-sa-tenant"}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
		for _, name := range []string{"mutator", "validator"} {
			saReads := 0
			live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(hosting, sa).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						saReads++
					}
					return c.Get(ctx, key, obj, opts...)
				},
			}).Build()
			handler := map[string]crAdmission.Handler{
				"mutator":   &webhooks.NamespaceMutator{Client: cached, Reader: live, Decoder: crAdmission.NewDecoder(scheme)},
				"validator": &webhooks.NamespaceValidator{Client: cached, Reader: live, Decoder: crAdmission.NewDecoder(scheme)},
			}[name]
			if response := handler.Handle(context.Background(), req); response.Allowed {
				t.Fatalf("%s: unannotated ServiceAccount without grants was allowed", name)
			}
			if saReads == 0 {
				t.Fatalf("%s: did not read the ServiceAccount", name)
			}
		}
	})
}

// inheritingServiceAccount returns the ServiceAccount behind username opted in
// to hosting-namespace inheritance, or nil when username is not a ServiceAccount.
func inheritingServiceAccount(username string) *corev1.ServiceAccount {
	info := webhooks.ParseServiceAccount(username)
	if !info.IsServiceAccount {
		return nil
	}
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Namespace:   info.Namespace,
		Name:        info.Name,
		Annotations: map[string]string{authorizationv1alpha1.AnnotationKeyInheritHostingNamespaceOwnership: "true"},
	}}
}
