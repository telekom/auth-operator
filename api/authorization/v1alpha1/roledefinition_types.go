package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RoleDefinition-related constants for finalizers and role types.
const (
	// RoleDefinitionFinalizer is the finalizer used to prevent orphaned resources.
	RoleDefinitionFinalizer = "roledefinition.authorization.t-caas.telekom.com/finalizer"
	// DefinitionClusterRole indicates a ClusterRole type.
	DefinitionClusterRole = "ClusterRole"
	// DefinitionNamespacedRole indicates a namespaced Role type.
	DefinitionNamespacedRole = "Role"
)

// RoleDefinitionSpec defines the desired state of RoleDefinition
type RoleDefinitionSpec struct {
	// The target role that will be reconciled. This can be a ClusterRole or a namespaced Role
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ClusterRole;Role
	TargetRole string `json:"targetRole"`

	// The name of the target role. This can be any name that accurately describes the ClusterRole/Role.
	// Must be a valid Kubernetes name (max 63 characters for most resources).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetName string `json:"targetName"`

	// The target namespace for the Role. This value is necessary when the "TargetRole" is "Role"
	// +kubebuilder:validation:Optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// The scope controls whether the API resource is namespaced or not. This can also be checked by
	// running `kubectl api-resources --namespaced=true/false`
	// +kubebuilder:validation:Required
	ScopeNamespaced bool `json:"scopeNamespaced"`

	// The restricted APIs field holds all API groups which will *NOT* be reconciled into the "TargetRole"
	// The RBAC operator discovers all API groups available and removes those which are defined by "RestrictedAPIs"
	// +kubebuilder:validation:Optional
	RestrictedAPIs []metav1.APIGroup `json:"restrictedApis,omitempty"`

	// The restricted resources field holds all resources which will *NOT* be reconciled into the "TargetRole"
	// The RBAC operator discovers all API resources available and removes those which are defined by "RestrictedResources"
	// +kubebuilder:validation:Optional
	RestrictedResources []metav1.APIResource `json:"restrictedResources,omitempty"`

	// The restricted verbs field holds all verbs which will *NOT* be reconciled into the "TargetRole"
	// The RBAC operator discovers all resource verbs available and removes those which are defined by "RestrictedVerbs"
	// +kubebuilder:validation:Optional
	RestrictedVerbs []string `json:"restrictedVerbs,omitempty"`
}

// RoleDefinitionStatus defines the observed state of RoleDefinition
type RoleDefinitionStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// This is used by kstatus to determine if the resource is current.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify completed reconciliation.
	// +kubebuilder:validation:Optional
	RoleReconciled bool `json:"roleReconciled,omitempty"`

	// Conditions defines current service state of the Role definition. All conditions should evaluate to true to signify successful reconciliation.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RoleDefinition is the Schema for the roledefinitions API.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=roledefinitions,scope=Cluster,shortName=roledef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the RoleDefinition is ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since creation of this RoleDefinition"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetRole",description="Kubernetes API target RBAC object - can be ClusterRole or Role"
// +kubebuilder:printcolumn:name="Role name",type="string",JSONPath=".spec.targetName",description="The name of the child object created by this RoleDefinition"
// +kubebuilder:printcolumn:name="Namespaced scope",type="boolean",JSONPath=".spec.scopeNamespaced",description="The boolean value signifying whether this RoleDefinition is reconciling Cluster scoped resources or Namespace scoped resources"
type RoleDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleDefinitionSpec   `json:"spec,omitempty"`
	Status RoleDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RoleDefinitionList contains a list of RoleDefinition
type RoleDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoleDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RoleDefinition{}, &RoleDefinitionList{})
}

// GetConditions returns the conditions of the RoleDefinition.
func (rd *RoleDefinition) GetConditions() []metav1.Condition {
	return rd.Status.Conditions
}

// SetConditions sets the conditions of the RoleDefinition.
func (rd *RoleDefinition) SetConditions(conditions []metav1.Condition) {
	rd.Status.Conditions = conditions
}
