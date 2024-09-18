package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AuthProviderFinalizer   = "authprovider.authentication.t-caas.telekom.com"
	AuthProviderTDIInternal = "portal.security.in.pan-net.eu"
	AuthProviderTDIPortal   = "TDIPortal"
	AuthProviderZAM         = "ZAM"
	TokenRefreshService     = "token-refresh-service.t-caas.telekom.com" // have to implement a centralized microservice to serve as access token distro
)

type BackendURL struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path,omitempty"`
}

type OIDCMember struct {
	Name       string   `json:"name"`
	GroupNames []string `json:"groupNames"`
}

type OIDCGroup struct {
	GroupType   string   `json:"groupType"`
	ParentGroup string   `json:"parentGroup"`
	GroupNames  []string `json:"groupNames"`
}

type ClusterConsumer struct {
	Name    string       `json:"name"`
	Owners  []string     `json:"owners"`
	Members []OIDCMember `json:"members,omitempty"`
	Groups  []OIDCGroup  `json:"groups"`
}

// AuthProviderSpec defines the desired state of AuthProvider
type AuthProviderSpec struct {
	AuthBackend    BackendURL        `json:"authBackend"`
	RefreshBackend BackendURL        `json:"refreshBackend,omitempty"`
	Tenant         ClusterConsumer   `json:"tenant"`
	ThirdParty     []ClusterConsumer `json:"thirdParty,omitempty"`
}

// AuthProviderStatus defines the observed state of AuthProvider
type AuthProviderStatus struct {
	Status string `json:"status,omitempty"`

	// Conditions defines current service state of the Auth provider
	// All conditions should evaluate to true to signify successful reconciliation
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// AuthProvider is the Schema for the authproviders API
type AuthProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthProviderSpec   `json:"spec,omitempty"`
	Status AuthProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuthProviderList contains a list of AuthProvider
type AuthProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuthProvider{}, &AuthProviderList{})
}

// Satisfy the generic Getter interface
func (ap *AuthProvider) GetConditions() []metav1.Condition {
	return ap.Status.Conditions
}

// Satisfy the generic Setter interface
func (ap *AuthProvider) SetConditions(conditions []metav1.Condition) {
	ap.Status.Conditions = conditions
}
