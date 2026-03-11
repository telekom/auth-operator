// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RBACPolicy-related constants for finalizers.
const (
	// RBACPolicyFinalizer is the finalizer used to prevent deletion while
	// RestrictedBindDefinitions or RestrictedRoleDefinitions still reference this policy.
	RBACPolicyFinalizer = "rbacpolicy.authorization.t-caas.telekom.com/finalizer"
)

// PolicyScope defines which namespaces this policy governs.
type PolicyScope struct {
	// NamespaceSelector selects namespaces by label selector.
	// +kubebuilder:validation:Optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Namespaces is an explicit list of namespace names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Namespaces []string `json:"namespaces,omitempty"`
}

// RoleRefLimits controls which role references are allowed or forbidden.
type RoleRefLimits struct {
	// AllowedRoleRefs is a list of allowed role names. Supports simple wildcards:
	// "prefix*" and "*suffix". An empty list means no role refs are allowed (default-deny).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	AllowedRoleRefs []string `json:"allowedRoleRefs,omitempty"`

	// AllowedRoleRefSelector selects allowed roles by label.
	// +kubebuilder:validation:Optional
	AllowedRoleRefSelector *metav1.LabelSelector `json:"allowedRoleRefSelector,omitempty"`

	// ForbiddenRoleRefs is a list of explicitly forbidden role names.
	// Takes precedence over AllowedRoleRefs.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ForbiddenRoleRefs []string `json:"forbiddenRoleRefs,omitempty"`

	// ForbiddenRoleRefSelector selects forbidden roles by label.
	// +kubebuilder:validation:Optional
	ForbiddenRoleRefSelector *metav1.LabelSelector `json:"forbiddenRoleRefSelector,omitempty"`
}

// NamespaceLimits controls which namespaces can be targeted by bindings.
type NamespaceLimits struct {
	// AllowedNamespaceSelector selects allowed namespaces by label.
	// +kubebuilder:validation:Optional
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`

	// ForbiddenNamespaces is a list of namespace names that may not be targeted.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ForbiddenNamespaces []string `json:"forbiddenNamespaces,omitempty"`

	// ForbiddenNamespacePrefixes is a list of namespace name prefixes that may not be targeted.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenNamespacePrefixes []string `json:"forbiddenNamespacePrefixes,omitempty"`

	// MaxTargetNamespaces limits the number of target namespaces per binding.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	MaxTargetNamespaces *int32 `json:"maxTargetNamespaces,omitempty"`
}

// BindingLimits defines constraints on role bindings created by restricted definitions.
type BindingLimits struct {
	// AllowClusterRoleBindings controls whether ClusterRoleBindings may be created.
	// Default is false (deny by default).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowClusterRoleBindings bool `json:"allowClusterRoleBindings"`

	// ClusterRoleBindingLimits constrains which ClusterRoles may be referenced in CRBs.
	// +kubebuilder:validation:Optional
	ClusterRoleBindingLimits *RoleRefLimits `json:"clusterRoleBindingLimits,omitempty"`

	// RoleBindingLimits constrains which ClusterRoles/Roles may be referenced in RBs.
	// +kubebuilder:validation:Optional
	RoleBindingLimits *RoleRefLimits `json:"roleBindingLimits,omitempty"`

	// TargetNamespaceLimits constrains which namespaces may be targeted.
	// +kubebuilder:validation:Optional
	TargetNamespaceLimits *NamespaceLimits `json:"targetNamespaceLimits,omitempty"`
}

// ResourceVerbRule specifies a forbidden combination of resource, API group, and verbs.
type ResourceVerbRule struct {
	// Resource is the resource name (e.g., "pods", "secrets").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`

	// APIGroup is the API group of the resource. Empty string means core group.
	// +kubebuilder:validation:Optional
	APIGroup string `json:"apiGroup,omitempty"`

	// Verbs are the verbs forbidden on this resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Verbs []string `json:"verbs"`
}

// RoleLimits defines constraints on roles created by RestrictedRoleDefinitions.
type RoleLimits struct {
	// AllowClusterRoles controls whether ClusterRoles may be generated.
	// Default is false (deny by default).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowClusterRoles bool `json:"allowClusterRoles"`

	// ForbiddenVerbs is a list of verbs that must not appear in generated roles.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	ForbiddenVerbs []string `json:"forbiddenVerbs,omitempty"`

	// ForbiddenResources is a list of resources that must not appear in generated roles.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ForbiddenResources []string `json:"forbiddenResources,omitempty"`

	// ForbiddenAPIGroups is a list of API groups that must not appear in generated roles.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenAPIGroups []string `json:"forbiddenAPIGroups,omitempty"`

	// ForbiddenResourceVerbs is a list of specific resource+verb combinations that are forbidden.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenResourceVerbs []ResourceVerbRule `json:"forbiddenResourceVerbs,omitempty"`

	// MaxRulesPerRole limits the number of rules in a single generated role.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	MaxRulesPerRole *int32 `json:"maxRulesPerRole,omitempty"`
}

// NameMatchLimits defines name-based allow/deny patterns for subjects.
type NameMatchLimits struct {
	// AllowedNames is a list of allowed subject names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	AllowedNames []string `json:"allowedNames,omitempty"`

	// ForbiddenNames is a list of forbidden subject names.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ForbiddenNames []string `json:"forbiddenNames,omitempty"`

	// AllowedPrefixes is a list of allowed name prefixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	AllowedPrefixes []string `json:"allowedPrefixes,omitempty"`

	// ForbiddenPrefixes is a list of forbidden name prefixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenPrefixes []string `json:"forbiddenPrefixes,omitempty"`

	// AllowedSuffixes is a list of allowed name suffixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	AllowedSuffixes []string `json:"allowedSuffixes,omitempty"`

	// ForbiddenSuffixes is a list of forbidden name suffixes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenSuffixes []string `json:"forbiddenSuffixes,omitempty"`
}

// SARef is a reference to a specific ServiceAccount.
type SARef struct {
	// Name of the ServiceAccount.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the ServiceAccount.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// SACreationConfig controls ServiceAccount auto-creation behaviour.
type SACreationConfig struct {
	// AllowAutoCreate controls whether ServiceAccounts may be auto-created.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowAutoCreate bool `json:"allowAutoCreate"`

	// AllowedCreationNamespaceSelector selects namespaces where SA creation is allowed.
	// +kubebuilder:validation:Optional
	AllowedCreationNamespaceSelector *metav1.LabelSelector `json:"allowedCreationNamespaceSelector,omitempty"`

	// AllowedCreationNamespaces is an explicit list of namespaces where SA creation is allowed.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	AllowedCreationNamespaces []string `json:"allowedCreationNamespaces,omitempty"`

	// AutomountServiceAccountToken controls automount for auto-created SAs.
	// +kubebuilder:validation:Optional
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`

	// DisableAdoption prevents adoption of pre-existing ServiceAccounts.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	DisableAdoption bool `json:"disableAdoption"`
}

// ServiceAccountLimits defines constraints on ServiceAccount subjects.
type ServiceAccountLimits struct {
	// AllowedNamespaceSelector selects namespaces whose SAs may be referenced.
	// +kubebuilder:validation:Optional
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`

	// ForbiddenNamespaces is a list of namespaces whose SAs may not be referenced.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	ForbiddenNamespaces []string `json:"forbiddenNamespaces,omitempty"`

	// ForbiddenNamespacePrefixes is a list of namespace prefixes to deny.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ForbiddenNamespacePrefixes []string `json:"forbiddenNamespacePrefixes,omitempty"`

	// Creation constrains ServiceAccount auto-creation behaviour.
	// +kubebuilder:validation:Optional
	Creation *SACreationConfig `json:"creation,omitempty"`
}

// SubjectLimits defines constraints on the subjects a tenant may use.
type SubjectLimits struct {
	// AllowedKinds controls which subject kinds are allowed.
	// Valid values: "User", "Group", "ServiceAccount".
	// An empty list means no subject kinds are allowed (default-deny).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=3
	AllowedKinds []string `json:"allowedKinds,omitempty"`

	// ForbiddenKinds lists subject kinds that are explicitly forbidden.
	// Takes precedence over AllowedKinds.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=3
	ForbiddenKinds []string `json:"forbiddenKinds,omitempty"`

	// UserLimits constrains User subject names.
	// +kubebuilder:validation:Optional
	UserLimits *NameMatchLimits `json:"userLimits,omitempty"`

	// GroupLimits constrains Group subject names.
	// +kubebuilder:validation:Optional
	GroupLimits *NameMatchLimits `json:"groupLimits,omitempty"`

	// ServiceAccountLimits constrains ServiceAccount subjects.
	// +kubebuilder:validation:Optional
	ServiceAccountLimits *ServiceAccountLimits `json:"serviceAccountLimits,omitempty"`
}

// RBACPolicySpec defines the desired state of RBACPolicy.
// +kubebuilder:validation:XValidation:rule="has(self.appliesTo.namespaceSelector) || (has(self.appliesTo.namespaces) && size(self.appliesTo.namespaces) > 0)",message="appliesTo must specify at least namespaceSelector or namespaces"
type RBACPolicySpec struct {
	// AppliesTo defines the namespace scope this policy governs.
	// +kubebuilder:validation:Required
	AppliesTo PolicyScope `json:"appliesTo"`

	// BindingLimits constrains role bindings that may be created.
	// +kubebuilder:validation:Optional
	BindingLimits *BindingLimits `json:"bindingLimits,omitempty"`

	// RoleLimits constrains roles that may be generated.
	// +kubebuilder:validation:Optional
	RoleLimits *RoleLimits `json:"roleLimits,omitempty"`

	// SubjectLimits constrains the subjects a tenant may use.
	// +kubebuilder:validation:Optional
	SubjectLimits *SubjectLimits `json:"subjectLimits,omitempty"`
}

// RBACPolicyStatus defines the observed state of RBACPolicy.
type RBACPolicyStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// BoundResourceCount is the number of RestrictedBindDefinitions and
	// RestrictedRoleDefinitions currently referencing this policy.
	// +kubebuilder:validation:Optional
	BoundResourceCount int32 `json:"boundResourceCount,omitempty"`

	// Conditions defines current service state of the RBACPolicy.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RBACPolicy is the Schema for the rbacpolicies API.
// It defines RBAC guardrails that RestrictedBindDefinitions and
// RestrictedRoleDefinitions must comply with.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=rbacpolicies,scope=Cluster,shortName=rbacpol
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the RBACPolicy is ready"
// +kubebuilder:printcolumn:name="Bound",type="integer",JSONPath=".status.boundResourceCount",description="Number of bound restricted resources"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time since creation"
type RBACPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RBACPolicySpec   `json:"spec,omitempty"`
	Status RBACPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RBACPolicyList contains a list of RBACPolicy.
type RBACPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RBACPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACPolicy{}, &RBACPolicyList{})
}

// GetConditions returns the conditions of the RBACPolicy.
func (p *RBACPolicy) GetConditions() []metav1.Condition {
	return p.Status.Conditions
}

// SetConditions sets the conditions of the RBACPolicy.
func (p *RBACPolicy) SetConditions(conditions []metav1.Condition) {
	p.Status.Conditions = conditions
}
