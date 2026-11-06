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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
			cases := []struct {
				name    string
				labels  map[string]string
				bound   bool
				allowed bool
			}{
				{"own", own, true, true},
				{"platform", map[string]string{prefix + "owner": "platform"}, true, owner == "platform"},
				{"other-identity", map[string]string{prefix + "owner": owner, prefix + owner: "team-b"}, true, false},
				{"addon", map[string]string{prefix + "owner": "addon", prefix + "addon": "addon-a"}, true, false},
				{"protected", map[string]string{prefix + "owner": owner, prefix + owner: "team-a", prefix + "protected": "team-a"}, true, false},
				{"unbound-platform-inheritance", map[string]string{prefix + "owner": "platform"}, false, true},
			}
			for _, tc := range cases {
				if owner == "platform" && tc.name == "other-identity" {
					tc.labels = map[string]string{prefix + "owner": "platform", prefix + "tenant": "other"}
				}
				t.Run(tc.name, func(t *testing.T) {
					objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-caas-controllers", Labels: map[string]string{prefix + "owner": "platform"}}}}
					if tc.bound {
						objects = append(objects, binding)
					}
					c := fake.NewClientBuilder().WithScheme(scheme).WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).WithObjects(objects...).Build()
					// The live grant has not reached the webhook cache yet.
					cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects[0]).Build()
					oldBinding := binding.DeepCopy()
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
					req := crAdmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: ns.Name, Operation: op, UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:t-caas-controllers:" + saName}, Object: runtime.RawExtension{Raw: mustMarshalJSON(t, ns)}}}
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
