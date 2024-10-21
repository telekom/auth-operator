package webhooks

import (
	"context"
	"net/http"

	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type NamespaceValidator struct {
	Client  client.Client
	Decoder admission.Decoder
}

func (v *NamespaceValidator) InjectDecoder(d admission.Decoder) error {
	v.Decoder = d
	return nil
}

func (v *NamespaceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Only handle namespace CREATE, UPDATE, DELETE operations
	if req.Kind.Kind != "Namespace" {
		return admission.Allowed("")
	}

	var ns corev1.Namespace
	err := v.Decoder.Decode(req, &ns)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Get the user's groups from the request
	userGroups := req.UserInfo.Groups

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authorizationv1alpha1.BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitions); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Check if any BindDefinition allows the user to perform the operation
	isAllowed := false

	for _, bindDef := range bindDefinitions.Items {
		// Check if the BindDefinition includes the user's group in its subjects
		if !userInGroups(userGroups, bindDef.Spec.Subjects) {
			continue
		}

		// Get the NamespaceSelector from the BindDefinition
		namespaceSelector := bindDef.Spec.RoleBindings.NamespaceSelector

		// Check if the namespace matches the selector
		matches, err := namespaceMatchesSelector(&ns, &namespaceSelector)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		if matches {
			// User is allowed to perform the operation
			isAllowed = true
			break
		}
	}

	if isAllowed {
		return admission.Allowed("")
	}

	return admission.Denied("User is not allowed to perform the operation on this namespace")
}

func userInGroups(userGroups []string, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		if subject.Kind != "Group" {
			continue
		}
		for _, userGroup := range userGroups {
			if subject.Name == userGroup {
				return true
			}
		}
	}
	return false
}

func namespaceMatchesSelector(ns *corev1.Namespace, selector *metav1.LabelSelector) (bool, error) {
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}
	labels := labels.Set(ns.Labels)
	return sel.Matches(labels), nil
}
