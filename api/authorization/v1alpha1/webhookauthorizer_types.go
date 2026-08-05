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

// PrincipalExtraMatch matches a single SubjectAccessReview spec.extra entry.
// The apiserver populates spec.extra from the authenticated requester's extra
// values, including impersonation-related keys such as
// authentication.kubernetes.io/node-name.
type PrincipalExtraMatch struct {
	// Key is the extra key to match, e.g. "authentication.kubernetes.io/node-name".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`

	// Values are the accepted values for Key. The principal matches when at least
	// one of the request's values for Key is listed here. Use ["*"] to require only
	// that the key is present with any non-empty value.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Values []string `json:"values"`
}

// Principal represents a requesting user or service account identity.
// +kubebuilder:validation:XValidation:rule="(has(self.user) && self.user != \"\") || (has(self.groups) && size(self.groups) > 0) || (has(self.uid) && self.uid != \"\") || (has(self.extra) && size(self.extra) > 0)",message="principal must specify user, uid, at least one group, or at least one extra matcher"
type Principal struct {
	// User is the requesting user in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	User string `json:"user,omitempty"`

	// Groups is the requesting user groups in SubjectAccessReview request.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	Groups []string `json:"groups,omitempty"`

	// Namespace scopes User to a Kubernetes ServiceAccount namespace. When set,
	// User may be either the short ServiceAccount name or the full
	// system:serviceaccount:<namespace>:<name> username.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	Namespace string `json:"namespace,omitempty"`

	// UID matches SubjectAccessReview spec.uid, the UID of the authenticated
	// requester. Matching on UID pins a principal to one specific identity instance
	// even when usernames are reused, which matters for constrained impersonation
	// because the requester's UID is part of the impersonation authorization check.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	UID string `json:"uid,omitempty"`

	// Extra matches SubjectAccessReview spec.extra entries. All listed matchers must
	// match (AND) for the principal to match. This makes attributes such as
	// authentication.kubernetes.io/node-name — the value the associated-node
	// impersonation mode is keyed on — usable in authorization decisions.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	Extra []PrincipalExtraMatch `json:"extra,omitempty"`
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

	// DeniedPrincipals is a slice of principals this authorizer should deny
	// when the request also matches ResourceRules or NonResourceRules.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	DeniedPrincipals []Principal `json:"deniedPrincipals,omitempty"`

	// NamespaceSelector is a label selector to match namespaces that should allow the specified API calls.
	// +kubebuilder:validation:Optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ImpersonationVerbPolicy controls how this authorizer treats Kubernetes
	// constrained impersonation (KEP-5284) verbs — `impersonate:<mode>` and
	// `impersonate-on:<mode>:<verb>` — in resourceRules[].verbs.
	//
	// Defaults to "RequireExplicitVerb", which is a deliberate hardening: a
	// pre-existing rule with verbs: ["*"] would otherwise silently start granting
	// constrained impersonation the moment the feature gate is on. See the
	// ImpersonationVerbPolicy type documentation for the full rationale.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=RequireExplicitVerb
	ImpersonationVerbPolicy ImpersonationVerbPolicy `json:"impersonationVerbPolicy,omitempty"`
}

// ImpersonationVerbPolicy selects how an authorizer handles constrained
// impersonation verbs.
//
// KEP-5284 explicitly warns that "a permissive webhook that allows unknown verbs
// silently grants constrained impersonation". Because Kubernetes RBAC treats
// verbs: ["*"] as matching every verb — including `impersonate:user-info` — any
// pre-existing wildcard allow rule becomes an unintended impersonation grant when
// the feature gate is enabled.
// +kubebuilder:validation:Enum=RequireExplicitVerb;AllowWildcard;Deny
type ImpersonationVerbPolicy string

// Impersonation verb handling policies for WebhookAuthorizer.
const (
	// ImpersonationVerbPolicyRequireExplicitVerb (the default) means a constrained
	// impersonation verb only matches a rule that lists it literally. A rule with
	// verbs: ["*"] does NOT match `impersonate:user-info`. This is fail-safe and
	// keeps existing wildcard rules from silently widening.
	ImpersonationVerbPolicyRequireExplicitVerb ImpersonationVerbPolicy = "RequireExplicitVerb"

	// ImpersonationVerbPolicyAllowWildcard restores plain Kubernetes RBAC
	// semantics, where verbs: ["*"] matches constrained impersonation verbs too.
	// Only use this on authorizers whose rules are known to be narrow.
	ImpersonationVerbPolicyAllowWildcard ImpersonationVerbPolicy = "AllowWildcard"

	// ImpersonationVerbPolicyDeny makes this authorizer return an explicit deny for
	// any request carrying a constrained impersonation verb that matches its rules,
	// regardless of the allowed principals. Use it as a cluster-wide kill switch for
	// constrained impersonation.
	//
	// Rule matching uses plain RBAC semantics, so verbs: ["*"] DOES match every
	// impersonation verb here. This differs from RequireExplicitVerb on purpose:
	// ignoring "*" is fail-safe when granting but fail-open when denying, and a kill
	// switch written as verbs: ["*"] must not silently match nothing.
	ImpersonationVerbPolicyDeny ImpersonationVerbPolicy = "Deny"
)

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
