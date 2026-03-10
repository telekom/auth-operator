package webhooks

// Denial message constants used across namespace mutating and validating webhooks.
// Centralizing these messages ensures consistency and makes them easier to maintain
// and reference in tests and documentation.

const (
	// DenialNoOIDCAttributes is returned by the namespace mutator when the user
	// has no matching BindDefinition subjects and is not a bypass-eligible admin.
	DenialNoOIDCAttributes = "The user does not have any OIDC attributes assigned to this cluster and the user is not a Kubernetes admin. Namespace creation is not allowed."

	// DenialLabelModificationFmt is a format string returned by the namespace
	// validator when a user attempts to modify or remove a controlled label.
	DenialLabelModificationFmt = "Modification of label '%s' is not allowed"

	// DenialNotNamespaceOwnerFmt is a format string returned by the namespace
	// validator when no BindDefinition authorizes the user for the operation.
	DenialNotNamespaceOwnerFmt = "User %s is not the owner of namespace %s"

	// DenialLegacyPlatformToNonPlatformFmt is a format string returned when a
	// legacy platform namespace is being adopted with a non-platform owner.
	DenialLegacyPlatformToNonPlatformFmt = "Legacy platform namespace (%s=%s) cannot be adopted as '%s'"

	// DenialLegacyNonPlatformToPlatformFmt is a format string returned when a
	// legacy non-platform namespace is being adopted as platform.
	DenialLegacyNonPlatformToPlatformFmt = "Legacy non-platform namespace (%s=%s) cannot be adopted as 'platform'"

	// DenialLabelConflictFmt is a format string returned by the namespace mutator
	// when SA namespace label inheritance detects a conflicting tracked label value
	// on the target namespace. Parameters: target namespace, label key, existing value,
	// inherited value, SA namespace name.
	DenialLabelConflictFmt = "Namespace %s already has label %s=%s which conflicts with inherited value %s from SA namespace %s"

	// DenialExtraTrackedKeyFmt is a format string returned by the namespace mutator
	// when the target namespace has a tracked label not present on the SA source namespace.
	// Parameters: target namespace, extra key, SA namespace name.
	DenialExtraTrackedKeyFmt = "Namespace %s has tracked label %s not present on SA source namespace %s"
)
