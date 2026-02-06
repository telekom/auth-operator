package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BindDefinition-related constants for finalizers and binding types.
const (
	// BindDefinitionFinalizer is the finalizer used to prevent orphaned resources.
	BindDefinitionFinalizer = "binddefinition.authorization.t-caas.telekom.com/finalizer"
	// RoleBindingFinalizer is the finalizer used on RoleBindings.
	RoleBindingFinalizer = "rolebinding.authorization.t-caas.telekom.com/finalizer"
	// BindClusterRoleBinding indicates a ClusterRoleBinding type.
	BindClusterRoleBinding = "ClusterRoleBinding"
	// BindRoleBinding indicates a RoleBinding type.
	BindRoleBinding = "RoleBinding"
	// BindSubjectServiceAccount indicates a ServiceAccount subject type.
	BindSubjectServiceAccount = "ServiceAccount"
)

// ClusterBinding defines cluster-scoped role bindings.
type ClusterBinding struct {
	// ClusterRoleRefs references an existing ClusterRole
	// +kubebuilder:validation:Optional
	ClusterRoleRefs []string `json:"clusterRoleRefs,omitempty"`
}

// NamespaceBinding defines namespace-scoped role bindings.
type NamespaceBinding struct {
	// ClusterRoleRefs references an existing ClusterRole
	// +kubebuilder:validation:Optional
	ClusterRoleRefs []string `json:"clusterRoleRefs,omitempty"`

	// RoleRefs references a specific Role that has to exist in the target namespaces
	// +kubebuilder:validation:Optional
	RoleRefs []string `json:"roleRefs,omitempty"`

	// Namespace of the Role that should be bound to the subjects.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s.
	// +kubebuilder:validation:Optional
	NamespaceSelector []metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// BindDefinitionSpec defines the desired state of BindDefinition.
type BindDefinitionSpec struct {
	// Name that will be prefixed to the concatenated string which is the name of the binding. Follows format "targetName-clusterrole/role-binding" where clusterrole/role is the in-cluster existing ClusterRole or Role.
	// +kubebuilder:validation:Required
	TargetName string `json:"targetName"`

	// List of subjects that will be bound to a target ClusterRole/Role. Can be "User", "Group" or "ServiceAccount".
	// +kubebuilder:validation:Required
	Subjects []rbacv1.Subject `json:"subjects"`

	// List of ClusterRoles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying this field are ClusterRoleBindings.
	// +kubebuilder:validation:Optional
	ClusterRoleBindings ClusterBinding `json:"clusterRoleBindings,omitempty"`

	// List of ClusterRoles/Roles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying the field are RoleBindings.
	// +kubebuilder:validation:Optional
	RoleBindings []NamespaceBinding `json:"roleBindings,omitempty"`

	// AutomountServiceAccountToken controls whether to automount API credentials for ServiceAccounts
	// created by this BindDefinition. Defaults to true for backward compatibility with Kubernetes
	// native ServiceAccount behavior. Set to false to improve security by preventing automatic
	// token mounting.
	// Only applies when Subjects contain ServiceAccount entries that need to be auto-created.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
}

// BindDefinitionStatus defines the observed state of BindDefinition.
type BindDefinitionStatus struct {
	// ObservedGeneration is the last observed generation of the resource.
	// This is used by kstatus to determine if the resource is current.
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify completed reconciliation.
	// +kubebuilder:validation:Optional
	BindReconciled bool `json:"bindReconciled,omitempty"`

	// If the BindDefinition points to a subject of "Kind: ServiceAccount" and the service account is not present. The controller will reconcile it automatically.
	// +kubebuilder:validation:Optional
	GeneratedServiceAccounts []rbacv1.Subject `json:"generatedServiceAccounts"`

	// Conditions defines current service state of the Bind definition. All conditions should evaluate to true to signify successful reconciliation.
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BindDefinition is the Schema for the binddefinitions API.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=binddefinitions,scope=Cluster,shortName=binddef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the BindDefinition is ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since creation of this BindDefinition"
// +kubebuilder:printcolumn:name="Bind name",type="string",JSONPath=".spec.targetName",description="The name of the child object created by this BindDefinition"
type BindDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BindDefinitionSpec   `json:"spec,omitempty"`
	Status BindDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BindDefinitionList contains a list of BindDefinition.
type BindDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BindDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BindDefinition{}, &BindDefinitionList{})
}

// GetConditions returns the conditions of the BindDefinition.
func (bd *BindDefinition) GetConditions() []metav1.Condition {
	return bd.Status.Conditions
}

// SetConditions sets the conditions of the BindDefinition.
func (bd *BindDefinition) SetConditions(conditions []metav1.Condition) {
	bd.Status.Conditions = conditions
}
