package webhooks_test

import (
	"context"
	"testing"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestNamespaceValidatorHandle(t *testing.T) {
	// Setup the scheme for our fake client
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	// Create a BindDefinition that allows certain groups to operate on specific namespaces
	bindDefPlatform := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "platform-binddefinition",
		},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "bd-platform",
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:platform-admins",
				},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"platform-admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchLabels: map[string]string{
							"t-caas.telekom.com/owner": "platform",
						},
					},
				},
			}},
		},
	}

	bindDefTenant := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tenant-binddefinition",
		},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "bd-tenant",
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: "tenant-system",
				},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"tenant-admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchLabels: map[string]string{
							"t-caas.telekom.com/tenant": "tenant-a",
						},
					},
				},
			}},
		},
	}

	tests := []struct {
		name           string
		bindDefs       []authzv1alpha1.BindDefinition
		request        crAdmission.Request
		expectedAllow  bool
		expectedReason metav1.StatusReason
		tdgMigration   bool
	}{
		{
			name:     "allow non-namespace resource",
			bindDefs: []authzv1alpha1.BindDefinition{},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind: metav1.GroupVersionKind{Kind: "Pod"},
					Name: "test-pod",
				},
			},
			expectedAllow: true,
		},
		{
			name:     "allow kubernetes-admin user",
			bindDefs: []authzv1alpha1.BindDefinition{},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "test-ns",
					Operation: admissionv1.Create,
					UserInfo: authenticationv1.UserInfo{
						Username: "kubernetes-admin",
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:     "deny create for unauthorized user",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "unauthorized-ns",
					Operation: admissionv1.Create,
					UserInfo: authenticationv1.UserInfo{
						Username: "unauthorized-user",
						Groups:   []string{"oidc:random-group"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "unauthorized-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:     "allow create for platform admin on platform namespace",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Create,
					UserInfo: authenticationv1.UserInfo{
						Username: "platform-user",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:     "allow create for service account with matching BindDefinition",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefTenant},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "tenant-ns",
					Operation: admissionv1.Create,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:tenant-system:tenant-sa",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/tenant": "tenant-a",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:     "deny label modification on update",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "platform-user",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "changed-owner", // Changed!
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:     "allow update without label change",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "platform-user",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
									"some-other-label":         "new-value",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:     "allow delete for authorized user",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Delete,
					UserInfo: authenticationv1.UserInfo{
						Username: "platform-user",
						Groups:   []string{"oidc:platform-admins"},
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow TDG migration label change when TDGMigration enabled for helm-controller",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						// helm-controller is a TDG migration bypass user
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "old-platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build objects for fake client
			objects := make([]runtime.Object, 0, len(tt.bindDefs))
			for i := range tt.bindDefs {
				objects = append(objects, &tt.bindDefs[i])
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			decoder := crAdmission.NewDecoder(scheme)
			validator := &webhooks.NamespaceValidator{
				Client:       fakeClient,
				Decoder:      decoder,
				TDGMigration: tt.tdgMigration,
			}

			resp := validator.Handle(context.Background(), tt.request)

			if tt.expectedAllow && !resp.Allowed {
				t.Errorf("expected allowed, got denied: %s", resp.Result.Message)
			}
			if !tt.expectedAllow && resp.Allowed {
				t.Errorf("expected denied, got allowed")
			}
			// Validate expectedReason if specified
			if tt.expectedReason != "" && resp.Result != nil {
				if resp.Result.Reason != tt.expectedReason {
					t.Errorf("expected reason %q, got %q", tt.expectedReason, resp.Result.Reason)
				}
			}
		})
	}
}

func mustMarshalJSON(t *testing.T, obj interface{}) []byte {
	t.Helper()
	data, err := runtime.Encode(clientgoscheme.Codecs.LegacyCodec(corev1.SchemeGroupVersion), obj.(runtime.Object))
	if err != nil {
		t.Fatalf("failed to marshal object: %v", err)
	}
	return data
}
