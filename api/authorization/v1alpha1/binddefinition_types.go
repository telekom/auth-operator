package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// BindDefinitionSpec defines the desired state of BindDefinition
type BindDefinitionSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of BindDefinition. Edit binddefinition_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// BindDefinitionStatus defines the observed state of BindDefinition
type BindDefinitionStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

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
