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

	bindDefThirdparty := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "thirdparty-binddefinition",
		},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "bd-thirdparty",
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "thirdparty-sa",
					Namespace: "thirdparty-system",
				},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"thirdparty-admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchLabels: map[string]string{
							"t-caas.telekom.com/thirdparty": "tp-a",
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
			name:         "allow TDG migration label adoption when TDGMigration enabled for helm-controller",
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
									"schiff.telekom.de/owner":  "platform",
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
									"schiff.telekom.de/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		// === Adoption scenarios: old namespaces without t-caas labels ===
		// These test the scenario where an existing namespace (created before
		// auth-operator was deployed) needs to be adopted into the auth-operator
		// contract by adding t-caas labels for the first time.
		{
			name:     "deny adoption: adding owner label to namespace without any t-caas labels (thirdparty user)",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user@example.com",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name":          "legacy-ns",
									"platform.das-schiff.telekom.de/owner": "cas",
									"schiff.telekom.de/owner":              "cas",
									"t-caas.telekom.com/owner":             "tenant",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name":          "legacy-ns",
									"platform.das-schiff.telekom.de/owner": "cas",
									"schiff.telekom.de/owner":              "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:     "allow adoption: authorized SA adding tenant label to namespace without t-caas labels",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefTenant},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-tenant-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:tenant-system:tenant-sa",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-tenant-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-tenant-ns",
									"t-caas.telekom.com/tenant":   "tenant-a",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-tenant-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-tenant-ns",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:     "deny adoption: adding thirdparty label to namespace without any t-caas labels",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-3p-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "thirdparty-user@example.com",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-3p-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name":   "legacy-3p-ns",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-3p-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-3p-ns",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:     "deny adoption: removing existing owner label from namespace",
			bindDefs: []authzv1alpha1.BindDefinition{bindDefPlatform},
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "owned-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "platform-user",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "owned-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "owned-ns",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "owned-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "owned-ns",
									"t-caas.telekom.com/owner":    "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "allow adoption: adding multiple t-caas labels when none existed (via TDG migration bypass)",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
									"t-caas.telekom.com/owner":    "tenant",
									"t-caas.telekom.com/tenant":   "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "deny adoption: adding owner label via TDG migration bypass user when TDGMigration disabled",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: false,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
									"t-caas.telekom.com/owner":    "tenant",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:     "allow update on legacy namespace when no t-caas labels are touched",
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
									"kubernetes.io/metadata.name": "platform-ns",
									"t-caas.telekom.com/owner":    "platform",
									"schiff.telekom.de/owner":     "cas",
									"some-new-label":              "value",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "platform-ns",
									"t-caas.telekom.com/owner":    "platform",
									"schiff.telekom.de/owner":     "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		// === Safeguard scenarios: bypass users must not switch ownership types ===
		// Even with TDG migration bypass, changing an existing t-caas ownership
		// label from platform to anything else (or vice versa) must be denied.
		// However, tenant↔thirdparty reclassification IS allowed since the
		// thirdparty concept did not exist in the legacy system.
		{
			name:         "deny bypass user switching owner from platform to tenant",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "tenant",
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
			name:         "deny bypass user switching owner from platform to thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "thirdparty",
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
			name:         "deny bypass user switching owner from tenant to platform",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "tenant-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "tenant",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny bypass user removing existing owner label",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "platform-ns",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "platform-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "platform-ns",
									"t-caas.telekom.com/owner":    "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny bypass user removing tenant owner label",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "tenant-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "tenant-ns",
									// owner label removed
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "tenant-ns",
									"t-caas.telekom.com/owner":    "tenant",
									"t-caas.telekom.com/tenant":   "tenant-a",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny bypass user removing thirdparty owner label",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefThirdparty},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "thirdparty-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "thirdparty-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "thirdparty-ns",
									// owner label removed
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "thirdparty-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name":   "thirdparty-ns",
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "tp-a",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		// === Tenant ↔ thirdparty reclassification (allowed for bypass users) ===
		// The legacy system had no thirdparty concept. Everything non-platform was
		// "tenant". During TDG migration, bypass users may reclassify between
		// tenant and thirdparty, including changing the associated name labels.
		{
			name:         "allow bypass user reclassifying tenant to thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow bypass user reclassifying thirdparty to tenant",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "component-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "component-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "component-team",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "component-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "component-team",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow bypass user reclassifying tenant to thirdparty with tenant name change",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-pg1",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas-old-name",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "deny non-bypass user reclassifying tenant to thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user@example.com",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny reclassification when TDGMigration is disabled",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: false,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
						Groups:   []string{"oidc:platform-admins"},
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		// === Legacy cross-label validation ===
		// When adopting a namespace with a legacy schiff.telekom.de/owner label,
		// the new t-caas.telekom.com/owner must be consistent:
		// - Legacy "platform"/"schiff" → must adopt as "platform"
		// - Legacy anything else (e.g. "cas") → must adopt as "tenant" or "thirdparty"
		{
			name:         "deny adoption: legacy platform NS adopted as tenant",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "kube-logging",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-logging",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "platform",
									"t-caas.telekom.com/owner": "tenant",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-logging",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny adoption: legacy platform NS adopted as thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "kube-monitoring",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-monitoring",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "platform",
									"t-caas.telekom.com/owner": "thirdparty",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-monitoring",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny adoption: legacy schiff-owner NS adopted as tenant",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "schiff-infra-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "schiff-infra-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "schiff",
									"t-caas.telekom.com/owner": "tenant",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "schiff-infra-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "schiff",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny adoption: legacy non-platform NS adopted as platform",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-pg1",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "cas",
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "allow adoption: legacy platform NS adopted as platform",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "kube-logging",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-logging",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "platform",
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "kube-logging",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow adoption: legacy schiff-owner NS adopted as platform",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "schiff-infra-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "schiff-infra-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "schiff",
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "schiff-infra-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "schiff",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow adoption: legacy non-platform NS adopted as tenant",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "tenant-app-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-app-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "cas",
									"t-caas.telekom.com/owner": "tenant",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-app-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow adoption: legacy non-platform NS adopted as thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-pg1",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"schiff.telekom.de/owner":       "cas",
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"schiff.telekom.de/owner": "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "deny bypass user adopting platform label on legacy non-platform namespace",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
									"t-caas.telekom.com/owner":    "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "legacy-ns",
									"schiff.telekom.de/owner":     "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "allow bypass user updating non-t-caas labels on already-adopted namespace",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
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
		// === Legacy label cleanup: removing schiff.telekom.de/owner after adoption ===
		// Once the new t-caas labels are established, bypass users should be able
		// to remove the old schiff.telekom.de/owner label as the final migration step.
		{
			name:         "allow bypass user removing legacy schiff label when t-caas owner exists",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
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
									"t-caas.telekom.com/owner": "platform",
									"schiff.telekom.de/owner":  "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow bypass user removing legacy schiff label from tenant namespace",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "tenant-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "tenant-a",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "tenant-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "tenant-a",
									"schiff.telekom.de/owner":   "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "deny bypass user removing legacy schiff label when no t-caas owner exists",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "unadopted-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "unadopted-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "unadopted-ns",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "unadopted-ns",
								Labels: map[string]string{
									"kubernetes.io/metadata.name": "unadopted-ns",
									"schiff.telekom.de/owner":     "cas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		{
			name:         "deny non-bypass user removing legacy schiff label even with t-caas owner",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
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
									"schiff.telekom.de/owner":  "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},
		// === Combined migration: adopt + cleanup in single update ===
		{
			name:         "allow bypass user adopting t-caas labels and removing schiff label in one update",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
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
									"schiff.telekom.de/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		// === Reclassification with legacy cleanup combined ===
		{
			name:         "allow bypass user reclassifying tenant to thirdparty and removing schiff label",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-pg1",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"schiff.telekom.de/owner":   "cas",
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		// === Reclassification with tenant label removal (not just swap) ===
		{
			name:         "allow bypass user reclassifying: remove tenant label when switching to thirdparty",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefTenant},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "ocas-pg1",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:kustomize-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "ocas-pg1",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":  "tenant",
									"t-caas.telekom.com/tenant": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},
		{
			name:         "allow legacy schiff label removal when TDGMigration is disabled",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: false,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "platform-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "kubernetes-admin",
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
									"t-caas.telekom.com/owner": "platform",
									"schiff.telekom.de/owner":  "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: true,
		},

		// --- Edge case: thirdparty → platform switch (missing symmetric test) ---
		{
			name:         "deny bypass user switching owner from thirdparty to platform",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "thirdparty-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "thirdparty-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "thirdparty-ns",
								Labels: map[string]string{
									"t-caas.telekom.com/owner":      "thirdparty",
									"t-caas.telekom.com/thirdparty": "ocas",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
		},

		// --- Edge case: modifying (not removing) legacy schiff label value ---
		{
			name:         "deny bypass user modifying legacy schiff label value",
			bindDefs:     []authzv1alpha1.BindDefinition{bindDefPlatform},
			tdgMigration: true,
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "legacy-ns",
					Operation: admissionv1.Update,
					UserInfo: authenticationv1.UserInfo{
						Username: "system:serviceaccount:flux-system:helm-controller",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "platform",
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
					OldObject: runtime.RawExtension{
						Raw: mustMarshalJSON(t, &corev1.Namespace{
							ObjectMeta: metav1.ObjectMeta{
								Name: "legacy-ns",
								Labels: map[string]string{
									"schiff.telekom.de/owner":  "cas",
									"t-caas.telekom.com/owner": "platform",
								},
							},
						}),
					},
				},
			},
			expectedAllow: false,
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
