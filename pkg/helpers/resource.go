// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// maxResourceNameLength is the Kubernetes limit for resource names.
	maxResourceNameLength = 253

	// ManagedByLabel is the legacy label for backwards compatibility.
	//
	// Deprecated: No longer set on new resources as of v0.6.0.
	// Retained as a constant for migration tooling and E2E cleanup of
	// resources created by older operator versions.
	// Removal target: v0.8.0.
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
	// SourceNamesAnnotation is a comma-separated list of CRD names managing a shared resource.
	// Used for ServiceAccounts that can be managed by multiple BindDefinitions.
	SourceNamesAnnotation = "authorization.t-caas.telekom.com/source-names"

	// BindingSuffix is the suffix appended to binding resource names.
	BindingSuffix = "binding"
)

// BuildBindingName constructs a binding name from target name and role ref.
// Format: {targetName}-{roleRef}-binding.
// If the resulting name exceeds 253 characters (Kubernetes limit), the name
// is truncated and suffixed with a short hash to ensure uniqueness.
func BuildBindingName(targetName, roleRef string) string {
	fullName := fmt.Sprintf("%s-%s-%s", targetName, roleRef, BindingSuffix)

	if len(fullName) <= maxResourceNameLength {
		return fullName
	}

	// Hash the full name for uniqueness
	hash := sha256.Sum256([]byte(fullName))
	hashSuffix := hex.EncodeToString(hash[:4]) // 8 hex chars

	// Truncate to fit: truncated + "-" + hash <= 253
	maxLen := maxResourceNameLength - 1 - len(hashSuffix)
	truncatedName := fullName[:maxLen]

	return truncatedName + "-" + hashSuffix
}

// BuildResourceLabels creates labels for resources managed by the auth-operator.
// It merges the source labels with the standard auth-operator identification labels.
func BuildResourceLabels(sourceLabels map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range sourceLabels {
		labels[k] = v
	}
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

// BuildManagedSAAnnotations creates annotations for ServiceAccounts managed by BindDefinitions.
// The sourceNames parameter is a comma-separated list of BD names managing this SA.
// For new SAs, pass the single BD name. For existing SAs, pass the merged list.
func BuildManagedSAAnnotations(sourceNames string) map[string]string {
	return map[string]string{
		SourceKindAnnotation:  "BindDefinition",
		SourceNamesAnnotation: sourceNames,
	}
}

// MergeSourceNames adds a name to a comma-separated list if not already present.
// Returns the updated comma-separated string.
func MergeSourceNames(existing, newName string) string {
	if existing == "" {
		return newName
	}
	names := strings.Split(existing, ",")
	for _, n := range names {
		if strings.TrimSpace(n) == newName {
			return existing // Already present
		}
	}
	return existing + "," + newName
}

// RemoveSourceName removes a name from a comma-separated list.
// Returns the updated comma-separated string.
func RemoveSourceName(existing, nameToRemove string) string {
	if existing == "" {
		return ""
	}
	names := strings.Split(existing, ",")
	var result []string
	for _, n := range names {
		if strings.TrimSpace(n) != nameToRemove {
			result = append(result, strings.TrimSpace(n))
		}
	}
	return strings.Join(result, ",")
}

// IsLabelSelectorEmpty checks if a LabelSelector has no matching criteria.
func IsLabelSelectorEmpty(selector *metav1.LabelSelector) bool {
	return selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}
