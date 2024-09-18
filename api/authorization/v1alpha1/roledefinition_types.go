package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	RoleDefinitionFinalizer  = "roledefinition.authorization.t-caas.telekom.com"
	DefinitionClusterRole    = "ClusterRole"
	DefinitionNamespacedRole = "Role"
)

// RoleDefinitionSpec defines the desired state of RoleDefinition
type RoleDefinitionSpec struct {
	// The target role that will be reconciled. This can be a ClusterRole or a namespaced Role
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ClusterRole;Role
	TargetRole string `json:"targetRole"`

	// The name of the target role. This can be any name that accurately describes the ClusterRole/Role
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
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
	// Not extremely important as most status updates are driven by Conditions
	// We read the JSONPath from this status field to signify completed reconciliation
	// +kubebuilder:validation:Optional
	RoleReconciled bool `json:"roleReconciled,omitempty"`

	// Conditions defines current service state of the Role definition
	// All conditions should evaluate to true to signify successful reconciliation
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=roledefinitions,scope=Cluster,shortName=roledef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since creation of this RoleDefinition"
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.targetRole",description="Kubernetes API target RBAC object - can be ClusterRole or Role"
// +kubebuilder:printcolumn:name="Role name",type="string",JSONPath=".spec.targetName",description="The name of the child object created by this RoleDefinition"
// +kubebuilder:printcolumn:name="Namespaced scope",type="boolean",JSONPath=".spec.scopeNamespaced",description="The boolean value signifying whether this RoleDefinition is reconciling Cluster scoped resources or Namespace scoped resources"
// +kubebuilder:printcolumn:name="Reconciled role",type="string",JSONPath=".status.roleReconciled",description="The boolean value signifying if the target role has been reconciled or not"
// RoleDefinition is the Schema for the roledefinitions API
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

// Satisfy the generic Getter interface
func (rd *RoleDefinition) GetConditions() []metav1.Condition {
	return rd.Status.Conditions
}

// Satisfy the generic Setter interface
func (rd *RoleDefinition) SetConditions(conditions []metav1.Condition) {
	rd.Status.Conditions = conditions
}
