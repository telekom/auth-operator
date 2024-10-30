package webhooks

import (
	"context"
	"net/http"
	"strings"

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
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
	var err error

	switch req.Operation {
	case admissionv1.Create, admissionv1.Update:
		// For create and update operations, decode the object
		err = v.Decoder.Decode(req, &ns)
	case admissionv1.Delete:
		// For delete operations, decode the old object
		err = v.Decoder.DecodeRaw(req.OldObject, &ns)
	default:
		return admission.Allowed("")
	}

	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Extract user information
	userGroups := req.UserInfo.Groups
	username := req.UserInfo.Username

	// Check if the user is a ServiceAccount
	var saNamespace, saName string
	isServiceAccount := false
	usernameParts := strings.Split(username, ":")
	if len(usernameParts) == 4 && usernameParts[0] == "system" && usernameParts[1] == "serviceaccount" {
		isServiceAccount = true
		saNamespace = usernameParts[2]
		saName = usernameParts[3]
	}

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitions); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Check if any BindDefinition allows the user to perform the operation
	isAllowed := false

	for _, bindDef := range bindDefinitions.Items {
		// Skip BindDefinitions whose name ends with "-namespaced-reader-restricted"
		if strings.HasSuffix(bindDef.Name, "-namespaced-reader-restricted") {
			continue
		}
		userMatchFound := false
		// Check if the user matches any subjects in the BindDefinition
		for _, subject := range bindDef.Spec.Subjects {
			if subject.Kind == "Group" {
				for _, userGroup := range userGroups {
					if subject.Name == userGroup {
						userMatchFound = true
						break
					}
				}
			} else if subject.Kind == "ServiceAccount" && isServiceAccount {
				if subject.Namespace == saNamespace && subject.Name == saName {
					userMatchFound = true
					break
				}
			}
			if userMatchFound {
				break
			}
		}
		if !userMatchFound {
			continue
		}

		// Get the NamespaceSelectors from the BindDefinition
		namespaceSelectors := bindDef.Spec.RoleBindings.NamespaceSelector
		namespaceMatchFound := false
		for _, namespaceSelector := range namespaceSelectors {
			matches, err := namespaceMatchesSelector(&ns, &namespaceSelector)
			if err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			if matches {
				namespaceMatchFound = true
				break
			}
		}
		if namespaceMatchFound {
			isAllowed = true
			break
		}
	}
	if isAllowed {
		return admission.Allowed("")
	}

	return admission.Denied("You are not the owner of this namespace")
}

func namespaceMatchesSelector(ns *corev1.Namespace, selector *metav1.LabelSelector) (bool, error) {
	// Convert the LabelSelector into a labels.Selector
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}

	// Check if the namespace's labels match the selector
	return labelSelector.Matches(labels.Set(ns.Labels)), nil
}
