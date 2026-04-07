// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RestrictedBindDefinition-related constants for finalizers.
const (
	// RestrictedBindDefinitionFinalizer is the finalizer used to prevent orphaned resources.
	RestrictedBindDefinitionFinalizer = "restrictedbinddefinition.authorization.t-caas.telekom.com/finalizer"
)

// RestrictedBindDefinitionSpec defines the desired state of RestrictedBindDefinition.
// +kubebuilder:validation:XValidation:rule="(has(self.clusterRoleBindings) && has(self.clusterRoleBindings.clusterRoleRefs) && size(self.clusterRoleBindings.clusterRoleRefs) > 0) || (has(self.roleBindings) && self.roleBindings.exists(rb, (has(rb.clusterRoleRefs) && size(rb.clusterRoleRefs) > 0) || (has(rb.roleRefs) && size(rb.roleRefs) > 0)))",message="at least one binding with a referenced role must be specified"
// +kubebuilder:validation:XValidation:rule="size(self.subjects) > 0",message="at least one subject must be specified"
// +kubebuilder:validation:XValidation:rule="self.subjects.all(s, s.kind != 'ServiceAccount' || (has(s.namespace) && size(s.namespace) > 0))",message="ServiceAccount subjects must specify a namespace"
type RestrictedBindDefinitionSpec struct {
	// PolicyRef references the RBACPolicy that governs this binding.
	// This field is immutable after creation.
	// +kubebuilder:validation:Required
	PolicyRef RBACPolicyReference `json:"policyRef"`

	// TargetName is the name prefix for generated bindings. Follows format
	// "targetName-clusterrole/role-binding".
	// This field is immutable after creation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=200
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetName string `json:"targetName"`

	// Subjects lists the subjects that will be bound to the target ClusterRole/Role.
	// Can be "User", "Group" or "ServiceAccount".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxItems=256
	Subjects []rbacv1.Subject `json:"subjects"`

	// ClusterRoleBindings defines cluster-scoped role bindings.
	// +kubebuilder:validation:Optional
	ClusterRoleBindings *ClusterBinding `json:"clusterRoleBindings,omitempty"`

	// RoleBindings defines namespace-scoped role bindings.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	RoleBindings []NamespaceBinding `json:"roleBindings,omitempty"`

	// AutomountServiceAccountToken controls whether to automount API credentials
	// for ServiceAccounts created by this RestrictedBindDefinition.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
}

// RestrictedBindDefinitionStatus defines the observed state of RestrictedBindDefinition.
type RestrictedBindDefinitionStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// BindReconciled indicates whether bindings have been successfully reconciled.
	// +kubebuilder:validation:Optional
	BindReconciled bool `json:"bindReconciled,omitempty"`

	// GeneratedServiceAccounts lists ServiceAccounts that were auto-created.
	// +kubebuilder:validation:Optional
	GeneratedServiceAccounts []rbacv1.Subject `json:"generatedServiceAccounts,omitempty"`

	// MissingRoleRefs lists role references that could not be resolved.
	// Format: "ClusterRole/<name>" or "Role/<namespace>/<name>".
	// +kubebuilder:validation:Optional
	MissingRoleRefs []string `json:"missingRoleRefs,omitempty"`

	// ExternalServiceAccounts lists ServiceAccounts referenced by this RestrictedBindDefinition
	// that were not created by the controller.
	// Format: "<namespace>/<name>".
	// +kubebuilder:validation:Optional
	ExternalServiceAccounts []string `json:"externalServiceAccounts,omitempty"`

	// PolicyViolations lists policy violations detected during the last reconciliation.
	// Format: "<fieldPath>: <message>" when a field path is available.
	// Empty when all checks pass.
	// +kubebuilder:validation:Optional
	PolicyViolations []string `json:"policyViolations,omitempty"`

	// Conditions defines current service state.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RestrictedBindDefinition is the Schema for the restrictedbinddefinitions API.
// It is similar to BindDefinition but requires a policy reference and enforces
// RBAC guardrails defined by the referenced RBACPolicy.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=restrictedbinddefinitions,scope=Cluster,shortName=rbinddef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the RestrictedBindDefinition is ready"
// +kubebuilder:printcolumn:name="Policy",type="string",JSONPath=".status.conditions[?(@.type=='PolicyCompliant')].status",description="Whether the resource complies with its policy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time since creation"
// +kubebuilder:printcolumn:name="Bind name",type="string",JSONPath=".spec.targetName",description="The name of the child object created by this RestrictedBindDefinition"
// +kubebuilder:printcolumn:name="PolicyRef",type="string",JSONPath=".spec.policyRef.name",description="The referenced RBACPolicy"
type RestrictedBindDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RestrictedBindDefinitionSpec   `json:"spec,omitempty"`
	Status RestrictedBindDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RestrictedBindDefinitionList contains a list of RestrictedBindDefinition.
type RestrictedBindDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RestrictedBindDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RestrictedBindDefinition{}, &RestrictedBindDefinitionList{})
}

// GetConditions returns the conditions of the RestrictedBindDefinition.
func (rbd *RestrictedBindDefinition) GetConditions() []metav1.Condition {
	return rbd.Status.Conditions
}

// SetConditions sets the conditions of the RestrictedBindDefinition.
func (rbd *RestrictedBindDefinition) SetConditions(conditions []metav1.Condition) {
	rbd.Status.Conditions = conditions
}
