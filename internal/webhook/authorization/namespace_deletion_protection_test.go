package webhooks_test

import (
	"context"
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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// deleteRequest builds a namespace DELETE admission request. DELETE requests
// carry the namespace object in OldObject.
func deleteRequest(t *testing.T, ns *corev1.Namespace, username string, groups ...string) crAdmission.Request {
	t.Helper()
	return crAdmission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
			Name:      ns.Name,
			Operation: admissionv1.Delete,
			UserInfo: authenticationv1.UserInfo{
				Username: username,
				Groups:   groups,
			},
			OldObject: runtime.RawExtension{
				Raw: mustMarshalJSON(t, ns),
			},
		},
	}
}

func namespaceWith(name string, labels, annotations map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: annotations,
		},
	}
}

func TestNamespaceValidatorDeletionProtection(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))

	platformLabels := map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform}
	allowDeletion := map[string]string{authorizationv1alpha1.AnnotationKeyAllowDeletion: authorizationv1alpha1.AllowDeletionTrue}

	// BindDefinition granting oidc:platform-admins access to platform namespaces,
	// used to prove that the allow-deletion annotation only lifts protection and
	// normal BindDefinition authorization still applies afterwards.
	bindDefPlatform := authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "platform-binddefinition",
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "bd-platform",
			Subjects: []rbacv1.Subject{
				{
					APIGroup: rbacv1.GroupName,
					Kind:     rbacv1.GroupKind,
					Name:     "oidc:platform-admins",
				},
			},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"platform-admin"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchLabels: map[string]string{
							authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform,
						},
					},
				},
			}},
		},
	}

	tests := []struct {
		name                     string
		bindDefs                 []authorizationv1alpha1.BindDefinition
		request                  crAdmission.Request
		deletionProtection       bool
		extraProtectedNamespaces []string
		tdgMigration             bool
		expectedAllow            bool
		expectedMessagePart      string
	}{
		{
			name:                "deny platform namespace delete by kubernetes-admin without annotation",
			request:             deleteRequest(t, namespaceWith("platform-ns", platformLabels, nil), "kubernetes-admin"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "deletion-protected",
		},
		{
			name:                "deny platform namespace delete by system:masters without annotation",
			request:             deleteRequest(t, namespaceWith("platform-ns", platformLabels, nil), "cluster-admin-user", "system:masters"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "deletion-protected",
		},
		{
			name:               "allow platform namespace delete by kubernetes-admin with allow-deletion annotation",
			request:            deleteRequest(t, namespaceWith("platform-ns", platformLabels, allowDeletion), "kubernetes-admin"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name:               "allow platform namespace delete with annotation by BindDefinition-authorized user",
			bindDefs:           []authorizationv1alpha1.BindDefinition{bindDefPlatform},
			request:            deleteRequest(t, namespaceWith("platform-ns", platformLabels, allowDeletion), "platform-user", "oidc:platform-admins"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name:                "deny platform namespace delete with annotation by unauthorized user",
			bindDefs:            []authorizationv1alpha1.BindDefinition{bindDefPlatform},
			request:             deleteRequest(t, namespaceWith("platform-ns", platformLabels, allowDeletion), "random-user", "oidc:some-other-group"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "is not the owner",
		},
		{
			name:                "deny kube-system delete by kubernetes-admin even with allow-deletion annotation",
			request:             deleteRequest(t, namespaceWith("kube-system", nil, allowDeletion), "kubernetes-admin"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "protected system namespace",
		},
		{
			name:                "deny kube-public delete by system:masters",
			request:             deleteRequest(t, namespaceWith("kube-public", nil, nil), "cluster-admin-user", "system:masters"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "protected system namespace",
		},
		{
			name:                "deny kube-node-lease delete by system:masters",
			request:             deleteRequest(t, namespaceWith("kube-node-lease", nil, nil), "cluster-admin-user", "system:masters"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "protected system namespace",
		},
		{
			name:                "deny default namespace delete by system:masters",
			request:             deleteRequest(t, namespaceWith("default", nil, nil), "cluster-admin-user", "system:masters"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "protected system namespace",
		},
		{
			name:                     "deny extra protected namespace delete even with annotation",
			request:                  deleteRequest(t, namespaceWith("monitoring", nil, allowDeletion), "kubernetes-admin"),
			deletionProtection:       true,
			extraProtectedNamespaces: []string{"monitoring"},
			expectedAllow:            false,
			expectedMessagePart:      "protected system namespace",
		},
		{
			name: "deny opted-in tenant namespace delete without annotation",
			request: deleteRequest(t, namespaceWith("tenant-ns", map[string]string{
				authorizationv1alpha1.LabelKeyOwner:              authorizationv1alpha1.OwnerTenant,
				authorizationv1alpha1.LabelKeyTenant:             "tenant-a",
				authorizationv1alpha1.LabelKeyDeletionProtection: authorizationv1alpha1.DeletionProtectionEnabled,
			}, nil), "cluster-admin-user", "system:masters"),
			deletionProtection:  true,
			expectedAllow:       false,
			expectedMessagePart: "deletion-protected",
		},
		{
			name: "allow opted-in tenant namespace delete with allow-deletion annotation",
			request: deleteRequest(t, namespaceWith("tenant-ns", map[string]string{
				authorizationv1alpha1.LabelKeyOwner:              authorizationv1alpha1.OwnerTenant,
				authorizationv1alpha1.LabelKeyTenant:             "tenant-a",
				authorizationv1alpha1.LabelKeyDeletionProtection: authorizationv1alpha1.DeletionProtectionEnabled,
			}, allowDeletion), "kubernetes-admin"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name: "allow plain tenant namespace delete without opt-in",
			request: deleteRequest(t, namespaceWith("tenant-ns", map[string]string{
				authorizationv1alpha1.LabelKeyOwner:  authorizationv1alpha1.OwnerTenant,
				authorizationv1alpha1.LabelKeyTenant: "tenant-a",
			}, nil), "cluster-admin-user", "system:masters"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name: "allow namespace with non-enabled deletion-protection label value",
			request: deleteRequest(t, namespaceWith("tenant-ns", map[string]string{
				authorizationv1alpha1.LabelKeyOwner:              authorizationv1alpha1.OwnerTenant,
				authorizationv1alpha1.LabelKeyTenant:             "tenant-a",
				authorizationv1alpha1.LabelKeyDeletionProtection: "true",
			}, nil), "kubernetes-admin"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name: "deny legacy schiff namespace delete when TDG migration is enabled",
			request: deleteRequest(t, namespaceWith("legacy-ns", map[string]string{
				"schiff.telekom.de/owner": "schiff",
			}, nil), "kubernetes-admin"),
			deletionProtection:  true,
			tdgMigration:        true,
			expectedAllow:       false,
			expectedMessagePart: "deletion-protected",
		},
		{
			name: "allow legacy schiff namespace delete when TDG migration is disabled",
			request: deleteRequest(t, namespaceWith("legacy-ns", map[string]string{
				"schiff.telekom.de/owner": "schiff",
			}, nil), "kubernetes-admin"),
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name:               "allow platform namespace delete when deletion protection is disabled",
			request:            deleteRequest(t, namespaceWith("platform-ns", platformLabels, nil), "kubernetes-admin"),
			deletionProtection: false,
			expectedAllow:      true,
		},
		{
			name: "allow kube-system named CREATE request - protection only gates DELETE",
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "kube-system",
					Operation: admissionv1.Create,
					UserInfo: authenticationv1.UserInfo{
						Username: "kubernetes-admin",
					},
					Object: runtime.RawExtension{
						Raw: mustMarshalJSON(t, namespaceWith("kube-system", nil, nil)),
					},
				},
			},
			deletionProtection: true,
			expectedAllow:      true,
		},
		{
			name: "error on protected delete request without namespace object",
			request: crAdmission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Kind:      metav1.GroupVersionKind{Kind: "Namespace"},
					Name:      "some-ns",
					Operation: admissionv1.Delete,
					UserInfo: authenticationv1.UserInfo{
						Username: "kubernetes-admin",
					},
				},
			},
			deletionProtection: true,
			expectedAllow:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := make([]runtime.Object, 0, len(tt.bindDefs))
			for i := range tt.bindDefs {
				objects = append(objects, &tt.bindDefs[i])
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionHasRoleBindingsField, indexer.BindDefinitionHasRoleBindingsFunc).
				Build()

			validator := &webhooks.NamespaceValidator{
				Client:                   fakeClient,
				Decoder:                  crAdmission.NewDecoder(scheme),
				TDGMigration:             tt.tdgMigration,
				DeletionProtection:       tt.deletionProtection,
				ExtraProtectedNamespaces: tt.extraProtectedNamespaces,
			}

			resp := validator.Handle(context.Background(), tt.request)

			if tt.expectedAllow && !resp.Allowed {
				t.Errorf("expected allowed, got denied: %s", resp.Result.Message)
			}
			if !tt.expectedAllow && resp.Allowed {
				t.Errorf("expected denied, got allowed")
			}
			if tt.expectedMessagePart != "" && resp.Result != nil &&
				!strings.Contains(resp.Result.Message, tt.expectedMessagePart) {
				t.Errorf("expected message to contain %q, got %q", tt.expectedMessagePart, resp.Result.Message)
			}
		})
	}
}
