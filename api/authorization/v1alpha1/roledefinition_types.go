package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
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

// RoleDefinitionSpec defines the desired state of RoleDefinition.
type RoleDefinitionSpec struct {
	// TargetRole is the role type that will be reconciled. This can be a ClusterRole or a namespaced Role.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ClusterRole;Role
	TargetRole string `json:"targetRole"`

	// TargetName is the name of the target role. This can be any name that accurately describes the ClusterRole/Role.
	// Must be a valid Kubernetes name (max 63 characters for most resources).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetName string `json:"targetName"`

	// TargetNamespace is the target namespace for the Role. Required when "TargetRole" is "Role".
	// +kubebuilder:validation:Optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// ScopeNamespaced controls whether the API resource is namespaced or not. This can also be checked by
	// running `kubectl api-resources --namespaced=true/false`.
	// +kubebuilder:validation:Required
	ScopeNamespaced bool `json:"scopeNamespaced"`

	// RestrictedAPIs holds all API groups which will *NOT* be reconciled into the "TargetRole".
	// The RBAC operator discovers all API groups available and removes those which are defined here.
	// When Versions is empty (versions: []), all versions of that group are restricted.
	// When Versions is specified, only those API versions are excluded from resource discovery.
	// Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource exists in
	// a non-restricted version of the same group, it will still appear in the generated role.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	RestrictedAPIs []metav1.APIGroup `json:"restrictedApis,omitempty"`

	// RestrictedResources holds all resources which will *NOT* be reconciled into the "TargetRole".
	// The RBAC operator discovers all API resources available and removes those listed here.
	// +kubebuilder:validation:Optional
	RestrictedResources []metav1.APIResource `json:"restrictedResources,omitempty"`

	// RestrictedVerbs holds all verbs which will *NOT* be reconciled into the "TargetRole".
	// The RBAC operator discovers all resource verbs available and removes those listed here.
	// +kubebuilder:validation:Optional
	RestrictedVerbs []string `json:"restrictedVerbs,omitempty"`

	// AggregationLabels are additional labels applied to the generated ClusterRole so that
	// it participates in Kubernetes' built-in ClusterRole aggregation mechanism.
	// For example, setting `rbac.authorization.k8s.io/aggregate-to-view: "true"` causes the
	// generated ClusterRole's rules to be aggregated into the default "view" ClusterRole.
	// Only applicable when targetRole is ClusterRole.
	// +kubebuilder:validation:Optional
	AggregationLabels map[string]string `json:"aggregationLabels,omitempty"`

	// AggregateFrom generates an aggregating ClusterRole that uses label selectors
	// to compose rules from other ClusterRoles, instead of specifying rules directly.
	// When set, the controller skips API discovery and filtering; the generated ClusterRole
	// has an aggregationRule and empty rules[] (rules are managed by the aggregation controller).
	// Mutually exclusive with RestrictedAPIs, RestrictedResources, and RestrictedVerbs.
	// Only applicable when targetRole is ClusterRole.
	// +kubebuilder:validation:Optional
	AggregateFrom *rbacv1.AggregationRule `json:"aggregateFrom,omitempty"`
}

// RoleDefinitionStatus defines the observed state of RoleDefinition.
type RoleDefinitionStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// This is used by kstatus to determine if the resource is current.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RoleReconciled indicates whether the target role has been successfully reconciled.
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

// RoleDefinitionList contains a list of RoleDefinition.
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
