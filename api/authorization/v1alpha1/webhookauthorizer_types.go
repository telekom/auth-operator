package v1alpha1

import (
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookAuthorizer-related constants for authorization decisions.
const (
	// WebhookAuthorizerAllow indicates an allow decision.
	WebhookAuthorizerAllow = "true"
	// WebhookAuthorizerDeny indicates a deny decision.
	WebhookAuthorizerDeny = "false"
)

// Principal represents a requesting user or service account identity.
type Principal struct {
	// User is the requesting user in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	User string `json:"user,omitempty"`

	// Groups is the requesting user groups in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	Groups []string `json:"groups,omitempty"`

	// Namespace is the requesting user namespace in case the requesting user is a ServiceAccount.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	Namespace string `json:"namespace,omitempty"`
}

// WebhookAuthorizerSpec defines the desired state of WebhookAuthorizer.
// +kubebuilder:validation:XValidation:rule="(has(self.resourceRules) && size(self.resourceRules) > 0) || (has(self.nonResourceRules) && size(self.nonResourceRules) > 0)",message="at least one resourceRules or nonResourceRules must be specified"
// +kubebuilder:validation:XValidation:rule="(has(self.allowedPrincipals) && size(self.allowedPrincipals) > 0) || (has(self.deniedPrincipals) && size(self.deniedPrincipals) > 0)",message="at least one allowedPrincipals or deniedPrincipals must be specified"
type WebhookAuthorizerSpec struct {
	// Resources which will be used to evaluate the SubjectAccessReviewSpec.ResourceAttributes
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ResourceRules []authzv1.ResourceRule `json:"resourceRules,omitempty"`

	// Resources which will be used to evaluate the SubjectAccessReviewSpec.NonResourceAttributes
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	NonResourceRules []authzv1.NonResourceRule `json:"nonResourceRules,omitempty"`

	// AllowedPrincipals is a slice of principals this authorizer should allow.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	AllowedPrincipals []Principal `json:"allowedPrincipals,omitempty"`

	// DeniedPrincipals is a slice of principals this authorizer should deny.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	DeniedPrincipals []Principal `json:"deniedPrincipals,omitempty"`

	// NamespaceSelector is a label selector to match namespaces that should allow the specified API calls.
	// +kubebuilder:validation:Optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// WebhookAuthorizerStatus defines the observed state of WebhookAuthorizer.
type WebhookAuthorizerStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// This is used by kstatus to determine if the resource is current.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

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
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the WebhookAuthorizer is ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since creation"

// WebhookAuthorizer is the Schema for the webhookauthorizers API.
type WebhookAuthorizer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebhookAuthorizerSpec   `json:"spec,omitempty"`
	Status WebhookAuthorizerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebhookAuthorizerList contains a list of WebhookAuthorizer.
type WebhookAuthorizerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebhookAuthorizer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WebhookAuthorizer{}, &WebhookAuthorizerList{})
}

// GetConditions returns the conditions of the WebhookAuthorizer.
func (wa *WebhookAuthorizer) GetConditions() []metav1.Condition {
	return wa.Status.Conditions
}

// SetConditions sets the conditions of the WebhookAuthorizer.
func (wa *WebhookAuthorizer) SetConditions(conditions []metav1.Condition) {
	wa.Status.Conditions = conditions
}
