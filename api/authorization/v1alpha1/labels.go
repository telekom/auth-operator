package v1alpha1

// Label keys used for namespace ownership and tenant identification.
// These labels are used by the namespace webhooks to control access
// and inject ownership metadata.
const (
	// LabelKeyProtected classifies namespaces that require the protected persona.
	LabelKeyProtected = "t-caas.telekom.com/protected"

	// WellKnownNamespaceLabelPrefix identifies well-known T-CaaS namespace labels
	// that may be used by BindDefinition namespace admission selectors.
	WellKnownNamespaceLabelPrefix = DefaultNamespaceAdmissionSelectorLabelGroup + "/"

	// DefaultNamespaceAdmissionSelectorLabelGroup is the label key domain
	// allowed by default in BindDefinition namespace selectors.
	DefaultNamespaceAdmissionSelectorLabelGroup = "t-caas.telekom.com"

	// LabelKeyOwner identifies the owner type of a namespace (platform, tenant, or thirdparty).
	LabelKeyOwner = "t-caas.telekom.com/owner"

	// LabelKeyTenant identifies the specific tenant that owns the namespace.
	LabelKeyTenant = "t-caas.telekom.com/tenant"

	// LabelKeyThirdParty identifies the specific third party that owns the namespace.
	LabelKeyThirdParty = "t-caas.telekom.com/thirdparty"

	// LabelKeyDeletionProtection opts a namespace into deletion protection.
	// Namespaces carrying this label with the value DeletionProtectionEnabled
	// can only be deleted after the AnnotationKeyAllowDeletion escape hatch
	// has been set. Platform-owned namespaces are protected implicitly and
	// do not need this label.
	LabelKeyDeletionProtection = "t-caas.telekom.com/deletion-protection"
)

// Annotation keys used by the auth-operator.
const (
	// AnnotationKeyReferencedBy tracks which BindDefinitions reference an external ServiceAccount.
	// The value is a comma-separated list of BindDefinition names.
	// This annotation is added to external (pre-existing) ServiceAccounts when a BindDefinition
	// references them, and removed when no BindDefinitions reference them anymore.
	AnnotationKeyReferencedBy = "authorization.t-caas.telekom.com/referenced-by"

	// AnnotationKeyExternalFieldManagers records the SSA managers whose label
	// ownership caused auth-operator to relinquish ServiceAccount lifecycle ownership.
	// The value is a sorted, comma-separated list of field manager names.
	AnnotationKeyExternalFieldManagers = "authorization.t-caas.telekom.com/external-field-managers"

	// AnnotationKeyAllowDeletion is the explicit escape hatch that permits
	// deletion of a deletion-protected namespace. It must be set to
	// AllowDeletionTrue on the namespace before the DELETE request; it never
	// unlocks hard-protected system namespaces (kube-system and friends).
	AnnotationKeyAllowDeletion = "t-caas.telekom.com/allow-deletion"

	// AnnotationKeyCreatedBy records the best-effort effective request username
	// observed when a resource was created.
	AnnotationKeyCreatedBy = "t-caas.telekom.com/created-by"

	// AnnotationKeyCreatedByGroups records the encoded effective request groups
	// observed when a resource was created.
	AnnotationKeyCreatedByGroups = "t-caas.telekom.com/created-by-groups"

	// AnnotationKeyUpdatedBy records best-effort encoded effective request
	// usernames observed on resource updates.
	AnnotationKeyUpdatedBy = "t-caas.telekom.com/updated-by"
)

// Owner label values.
const (
	// OwnerPlatform indicates the namespace is owned by the platform team.
	OwnerPlatform = "platform"

	// OwnerTenant indicates the namespace is owned by a tenant.
	OwnerTenant = "tenant"

	// OwnerThirdParty indicates the namespace is owned by a third party.
	OwnerThirdParty = "thirdparty"
)

// Deletion protection label and annotation values.
const (
	// DeletionProtectionEnabled is the only LabelKeyDeletionProtection value
	// that opts a namespace into deletion protection.
	DeletionProtectionEnabled = "enabled"

	// AllowDeletionTrue is the only AnnotationKeyAllowDeletion value that
	// lifts deletion protection for a protected namespace.
	AllowDeletionTrue = "true"
)
