// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RestrictedRoleDefinition-related constants.
const (
	// RestrictedRoleDefinitionKind is the Kubernetes kind name for RestrictedRoleDefinition.
	RestrictedRoleDefinitionKind = "RestrictedRoleDefinition"
	// RestrictedRoleDefinitionFinalizer is the finalizer used to prevent orphaned resources.
	RestrictedRoleDefinitionFinalizer = "restrictedroledefinition.authorization.t-caas.telekom.com/finalizer"
)

// RestrictedRoleDefinitionSpec defines the desired state of RestrictedRoleDefinition.
// +kubebuilder:validation:XValidation:rule="self.targetRole != 'Role' || (has(self.targetNamespace) && size(self.targetNamespace) > 0)",message="targetNamespace is required when targetRole is 'Role'"
// +kubebuilder:validation:XValidation:rule="self.targetRole != 'ClusterRole' || !has(self.targetNamespace) || size(self.targetNamespace) == 0",message="targetNamespace must be empty when targetRole is 'ClusterRole'"
type RestrictedRoleDefinitionSpec struct {
	// PolicyRef references the RBACPolicy that governs this role definition.
	// This field is immutable after creation.
	// +kubebuilder:validation:Required
	PolicyRef RBACPolicyReference `json:"policyRef"`

	// TargetRole is the role type that will be reconciled: ClusterRole or Role.
	// This field is immutable after creation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ClusterRole;Role
	TargetRole string `json:"targetRole"`

	// TargetName is the name of the target role.
	// This field is immutable after creation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$`
	TargetName string `json:"targetName"`

	// TargetNamespace is the target namespace for the Role.
	// Required when "TargetRole" is "Role".
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// ScopeNamespaced controls whether the API resource filter includes
	// namespaced or cluster-scoped resources.
	// +kubebuilder:validation:Required
	ScopeNamespaced bool `json:"scopeNamespaced"`

	// RestrictedAPIs defines API group-level restrictions for the generated role.
	// Each entry can either fully block an API group or restrict only certain verbs:
	//   - When Verbs is empty or omitted, the entire API group is fully blocked
	//     (no resources from that group appear in the generated role).
	//   - When Verbs is specified, only those verbs are removed for resources in
	//     the group — the remaining verbs are still allowed (partial restriction).
	// Version filtering narrows which API versions are affected:
	//   - When Versions is empty, all versions of the group are affected.
	//   - When Versions is specified, only those API versions are restricted.
	// Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource
	// exists in a non-restricted version of the same group, it will still appear
	// in the generated role.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	RestrictedAPIs []RestrictedAPIGroup `json:"restrictedApis,omitempty"`

	// RestrictedResources defines resource-level restrictions for the generated role.
	// Verbs is required by the schema. An empty list, "*" or the legacy "all"
	// excludes the entire matching resource; otherwise only the listed verbs are removed,
	// except that matching exec, attach, portforward and proxy subresources are fully excluded.
	// Matching entries are cumulative, including parent-resource restrictions on subresources.
	// An empty Group or "*" matches all API groups.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	RestrictedResources []metav1.APIResource `json:"restrictedResources,omitempty"`

	// RestrictedVerbs holds verbs which will NOT be included in the generated role.
	//
	// Kubernetes constrained impersonation (KEP-5284) verbs are accepted here too,
	// i.e. "impersonate:<mode>" and "impersonate-on:<mode>:<verb>", plus the legacy
	// bare "impersonate" verb. Because every mode x verb combination is a separate
	// entry, MaxItems is 64 rather than the historical 16.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^([a-z]+|\*|impersonate:(user-info|serviceaccount|arbitrary-node|associated-node)|impersonate-on:(user-info|serviceaccount|arbitrary-node|associated-node):[a-z]+)$`
	RestrictedVerbs []string `json:"restrictedVerbs,omitempty"`

	// ConstrainedImpersonation declares a Kubernetes constrained impersonation
	// (KEP-5284) grant using a typed API instead of hand-written magic verb strings.
	// The controller appends the generated PolicyRules to the discovery-derived rules
	// of the generated role.
	//
	// Unlike RoleDefinition, the grant is additionally checked against the governing
	// RBACPolicy: roleLimits.forbiddenVerbs and roleLimits.forbiddenResourceVerbs can
	// forbid `impersonate:*`-style grants, and
	// roleLimits.constrainedImpersonation can restrict the allowed modes, identity
	// resources and identity names.
	// +kubebuilder:validation:Optional
	ConstrainedImpersonation *ConstrainedImpersonationSpec `json:"constrainedImpersonation,omitempty"`
}

// RestrictedRoleDefinitionStatus defines the observed state of RestrictedRoleDefinition.
type RestrictedRoleDefinitionStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RoleReconciled indicates whether the target role has been successfully reconciled.
	// +kubebuilder:validation:Optional
	RoleReconciled bool `json:"roleReconciled,omitempty"`

	// PolicyViolations lists policy violations detected during the last reconciliation.
	// +kubebuilder:validation:Optional
	PolicyViolations []string `json:"policyViolations,omitempty"`

	// Conditions defines current service state.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RestrictedRoleDefinition is the Schema for the restrictedroledefinitions API.
// It is similar to RoleDefinition but requires a policy reference and enforces
// RBAC guardrails defined by the referenced RBACPolicy.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=restrictedroledefinitions,scope=Cluster,shortName=rroledef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the RestrictedRoleDefinition is ready"
// +kubebuilder:printcolumn:name="Policy",type="string",JSONPath=".status.conditions[?(@.type=='PolicyCompliant')].status",description="Whether the resource complies with its policy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time since creation"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetRole",description="Target RBAC object type"
// +kubebuilder:printcolumn:name="Role name",type="string",JSONPath=".spec.targetName",description="Name of the generated role"
// +kubebuilder:printcolumn:name="Namespaced scope",type="boolean",JSONPath=".spec.scopeNamespaced",description="Whether the generated role covers namespaced resources"
// +kubebuilder:printcolumn:name="PolicyRef",type="string",JSONPath=".spec.policyRef.name",description="The referenced RBACPolicy"
type RestrictedRoleDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   RestrictedRoleDefinitionSpec   `json:"spec"`
	Status RestrictedRoleDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RestrictedRoleDefinitionList contains a list of RestrictedRoleDefinition.
type RestrictedRoleDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RestrictedRoleDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RestrictedRoleDefinition{}, &RestrictedRoleDefinitionList{})
}

// GetConditions returns the conditions of the RestrictedRoleDefinition.
func (rrd *RestrictedRoleDefinition) GetConditions() []metav1.Condition {
	return rrd.Status.Conditions
}

// SetConditions sets the conditions of the RestrictedRoleDefinition.
func (rrd *RestrictedRoleDefinition) SetConditions(conditions []metav1.Condition) {
	rrd.Status.Conditions = conditions
}
