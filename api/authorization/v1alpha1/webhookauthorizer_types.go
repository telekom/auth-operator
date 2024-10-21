package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	WebhookAuthorizerAllow = "true"
	WebhookAuthorizerDeny  = "false"
)

type Principal struct {
	// User is the requesting user in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	User string `json:"user,omitempty"`

	// Groups is the requesting user groups in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	Groups []string `json:"groups,omitempty"`
}

// WebhookAuthorizerSpec defines the desired state of WebhookAuthorizer
type WebhookAuthorizerSpec struct {
	// APIGroup is the group of the API that should be allowed.
	// +kubebuilder:validation:Required
	APIGroup string `json:"apiGroup"`

	// APIVersion is the version of the API that should be allowed.
	// +kubebuilder:validation:Required
	APIVersion string `json:"apiVersion"`

	// Resource is the resource of the API that should be allowed. Resource can be a RegEx pattern to match multiple resources.
	// +kubebuilder:validation:Required
	Resource string `json:"resource"`

	// Verbs is a list of verbs that should be allowed.
	// +kubebuilder:validation:Required
	Verbs []string `json:"verbs"`

	// AllowedPrincipals is a slice of principals this authorizer should allow.
	// +kubebuilder:validation:Optional
	AllowedPrincipals []Principal `json:"allowedPrincipals,omitempty"`

	// DeniedPrincipals is a slice of principals this authorizer should deny.
	// +kubebuilder:validation:Optional
	DeniedPrincipals []Principal `json:"deniedPrincipals,omitempty"`

	// NamespaceSelector is a label selector to match namespaces that should allow the specified API calls.
	// +kubebuilder:validation:Optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// WebhookAuthorizerStatus defines the observed state of WebhookAuthorizer
type WebhookAuthorizerStatus struct {
	// Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify webhook authorizer as configured.
	// +kubebuilder:validation:Optional
	AuthorizerConfigured bool `json:"authorizerConfigured,omitempty"`

	// Conditions defines current service state of the Webhook authorizer. All conditions should evaluate to true to signify successful configuration.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// WebhookAuthorizer is the Schema for the webhookauthorizers API
type WebhookAuthorizer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebhookAuthorizerSpec   `json:"spec,omitempty"`
	Status WebhookAuthorizerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebhookAuthorizerList contains a list of WebhookAuthorizer
type WebhookAuthorizerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebhookAuthorizer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WebhookAuthorizer{}, &WebhookAuthorizerList{})
}

// Satisfy the generic Getter interface
func (wa *WebhookAuthorizer) GetConditions() []metav1.Condition {
	return wa.Status.Conditions
}

// Satisfy the generic Setter interface
func (wa *WebhookAuthorizer) SetConditions(conditions []metav1.Condition) {
	wa.Status.Conditions = conditions
}
