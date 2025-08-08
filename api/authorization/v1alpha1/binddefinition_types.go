package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	BindDefinitionFinalizer   = "binddefinition.authorization.t-caas.telekom.com/finalizer"
	RoleBindingFinalizer      = "rolebinding.authorization.t-caas.telekom.com/finalizer"
	BindClusterRoleBinding    = "ClusterRoleBinding"
	BindRoleBinding           = "RoleBinding"
	BindSubjectServiceAccount = "ServiceAccount"
)

type ClusterBinding struct {
	// ClusterRoleRefs references an existing ClusterRole
	// +kubebuilder:validation:Optional
	ClusterRoleRefs []string `json:"clusterRoleRefs,omitempty"`
}
type NamespaceBinding struct {
	// ClusterRoleRefs references an existing ClusterRole
	// +kubebuilder:validation:Optional
	ClusterRoleRefs []string `json:"clusterRoleRefs,omitempty"`

	// Role references an specific Role that has ro exist in the target namespaces
	// +kubebuilder:validation:Optional
	RoleRefs []string `json:"roleRefs,omitempty"`

	// Namespace of the the Role that should be bound to the subjects.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s.
	// +kubebuilder:validation:Optional
	NamespaceSelector []metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// BindDefinitionSpec defines the desired state of BindDefinition
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

	// List of ClusterRoles/Roles to which subjects will be bound to. The list is a RoleRef which means we have to specify t he full rbacv1.RoleRef schema. The result of specifying the field are RoleBindings.
	// +kubebuilder:validation:Optional
	RoleBindings []NamespaceBinding `json:"roleBindings,omitempty"`
}

// BindDefinitionStatus defines the observed state of BindDefinition
type BindDefinitionStatus struct {
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

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=binddefinitions,scope=Cluster,shortName=binddef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since creation of this BindDefinition"
// +kubebuilder:printcolumn:name="Bind name",type="string",JSONPath=".spec.targetName",description="The name of the child object created by this BindDefinition"
// +kubebuilder:printcolumn:name="Reconciled bind",type="string",JSONPath=".status.bindReconciled",description="The boolean value signifying if the target role has been reconciled or not"
// BindDefinition is the Schema for the binddefinitions API
type BindDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BindDefinitionSpec   `json:"spec,omitempty"`
	Status BindDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BindDefinitionList contains a list of BindDefinition
type BindDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BindDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BindDefinition{}, &BindDefinitionList{})
}

// Satisfy the generic Getter interface
func (bd *BindDefinition) GetConditions() []metav1.Condition {
	return bd.Status.Conditions
}

// Satisfy the generic Setter interface
func (bd *BindDefinition) SetConditions(conditions []metav1.Condition) {
	bd.Status.Conditions = conditions
}
