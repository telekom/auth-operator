// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RBACPolicyReference is a reference to an RBACPolicy that governs a restricted resource.
type RBACPolicyReference struct {
	// Name of the RBACPolicy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// UnifiedSelector provides flexible name and label matching for policy rules.
type UnifiedSelector struct {
	// Names is a list of exact names to match.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	Names []string `json:"names,omitempty"`

	// Prefixes is a list of name prefixes to match.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	Prefixes []string `json:"prefixes,omitempty"`

	// Suffixes is a list of name suffixes to match.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	Suffixes []string `json:"suffixes,omitempty"`

	// LabelSelector matches resources by label.
	// +kubebuilder:validation:Optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}
