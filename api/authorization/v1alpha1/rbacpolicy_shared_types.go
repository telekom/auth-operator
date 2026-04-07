// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// RBACPolicyReference is a reference to an RBACPolicy that governs a restricted resource.
type RBACPolicyReference struct {
	// Name of the RBACPolicy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}
