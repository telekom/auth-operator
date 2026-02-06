// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ManagedByLabel is the legacy label for backwards compatibility.
	//
	// Deprecated: use ManagedByLabelStandard instead.
	ManagedByLabel = "app.kubernetes.io/created-by"
	// ManagedByLabelStandard is the standard Kubernetes recommended label identifying the managing tool.
	ManagedByLabelStandard = "app.kubernetes.io/managed-by"
	// AppNameLabel is the standard Kubernetes label identifying the application.
	AppNameLabel = "app.kubernetes.io/name"
	// ManagedByValue is the value for all operator identification labels.
	ManagedByValue = "auth-operator"

	// SourceKindAnnotation identifies the kind of the CRD that generated this resource.
	SourceKindAnnotation = "authorization.t-caas.telekom.com/source-kind"
	// SourceNameAnnotation identifies the name of the CRD that generated this resource.
	SourceNameAnnotation = "authorization.t-caas.telekom.com/source-name"

	// BindingSuffix is the suffix appended to binding resource names.
	BindingSuffix = "binding"
)

// BuildBindingName constructs a binding name from target name and role ref.
// Format: {targetName}-{roleRef}-binding.
func BuildBindingName(targetName, roleRef string) string {
	return fmt.Sprintf("%s-%s-%s", targetName, roleRef, BindingSuffix)
}

// BuildResourceLabels creates labels for resources managed by the auth-operator.
// It merges the source labels with the standard auth-operator identification labels.
func BuildResourceLabels(sourceLabels map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range sourceLabels {
		labels[k] = v
	}
	labels[ManagedByLabel] = ManagedByValue
	labels[ManagedByLabelStandard] = ManagedByValue
	labels[AppNameLabel] = ManagedByValue
	return labels
}

// BuildResourceAnnotations creates annotations for tracing resources back to their source CRD.
func BuildResourceAnnotations(sourceKind, sourceName string) map[string]string {
	return map[string]string{
		SourceKindAnnotation: sourceKind,
		SourceNameAnnotation: sourceName,
	}
}

// IsLabelSelectorEmpty checks if a LabelSelector has no matching criteria.
func IsLabelSelectorEmpty(selector *metav1.LabelSelector) bool {
	return selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}
