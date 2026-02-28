// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "github.com/telekom/auth-operator/pkg/conditions"

// AuthZConditionType represents authorization-related condition types.
type AuthZConditionType = conditions.ConditionType

// AuthZConditionReason represents authorization-related condition reasons.
type AuthZConditionReason = conditions.ConditionReason

// AuthZConditionMessage represents authorization-related condition messages.
type AuthZConditionMessage = conditions.ConditionMessage

// Ready condition reasons.
const (
	// ReadyReasonReconciled indicates the resource is fully reconciled.
	ReadyReasonReconciled AuthZConditionReason = "Reconciled"
)

// Ready condition messages.
const (
	// ReadyMessageReconciled is the message when the resource is fully reconciled.
	ReadyMessageReconciled AuthZConditionMessage = "Resource is fully reconciled"
)

// Reconciling condition reasons.
const (
	// ReconcilingReasonProgressing indicates the controller is making progress.
	ReconcilingReasonProgressing AuthZConditionReason = "Progressing"
)

// Reconciling condition messages.
const (
	// ReconcilingMessageProgressing is the message when the controller is progressing.
	ReconcilingMessageProgressing AuthZConditionMessage = "Controller is reconciling the resource"
)

// Stalled condition reasons.
const (
	// StalledReasonError indicates an error occurred during reconciliation.
	StalledReasonError AuthZConditionReason = "Error"
)

// Stalled condition messages.
const (
	// StalledMessageError is the message format when an error occurred.
	StalledMessageError AuthZConditionMessage = "Error during reconciliation: %s"
)

// Finalizer-related condition constants.
const (
	// FinalizerCondition indicates whether the finalizer has been set.
	FinalizerCondition AuthZConditionType = "Finalizer"
	// FinalizerReason is the reason for finalizer condition.
	FinalizerReason AuthZConditionReason = "OrphanPrevention"
	// FinalizerMessage is the message for finalizer condition.
	FinalizerMessage AuthZConditionMessage = "Set finalizer to prevent orphaned resources"
)

// Namespace termination related condition constants.
const (
	// NamespaceTerminationBlockedCondition indicates namespace termination is blocked.
	NamespaceTerminationBlockedCondition AuthZConditionType = "AuthOperatorNamespaceTerminationBlocked"
	// NamespaceTerminationBlockedReason is the reason for blocking namespace termination.
	NamespaceTerminationBlockedReason AuthZConditionReason = "AuthOperatorPreventedTermination"
	// NamespaceTerminationBlockedMessage is the message when termination is blocked.
	NamespaceTerminationBlockedMessage AuthZConditionMessage = "Auth-operator blocked role bindings termination due to remaining resources"

	// NamespaceTerminationAllowedReason is the reason when termination is allowed.
	NamespaceTerminationAllowedReason AuthZConditionReason = "AuthOperatorResourcesCleanedUp"
	// NamespaceTerminationAllowedMessage is the message when termination is allowed.
	NamespaceTerminationAllowedMessage AuthZConditionMessage = "All role bindings created by auth-operator have been cleaned up"
)

// Owner reference related condition constants.
const (
	// OwnerRefCondition indicates owner reference status.
	OwnerRefCondition AuthZConditionType = "OwnerRef"
	// OwnerRefReason is the reason for owner reference condition.
	OwnerRefReason AuthZConditionReason = "ResourceOwnership"
	// OwnerRefMessage is the message for owner reference condition.
	OwnerRefMessage AuthZConditionMessage = "Set owner reference to child resource"
)

// Delete related condition constants.
const (
	// DeleteCondition indicates deletion status.
	DeleteCondition AuthZConditionType = "Deleted"
	// DeleteReason is the reason for deletion condition.
	DeleteReason AuthZConditionReason = "TriggeredDelete"
	// DeleteMessage is the message for deletion condition.
	DeleteMessage AuthZConditionMessage = "Reconciling deletion request"
)

// API discovery related condition constants.
const (
	// APIDiscoveryCondition indicates API group discovery status.
	APIDiscoveryCondition AuthZConditionType = "APIGroupDiscovered"
	// APIDiscoveryReason is the reason for API discovery condition.
	APIDiscoveryReason AuthZConditionReason = "Discovery"
	// APIDiscoveryMessage is the message for API discovery condition.
	APIDiscoveryMessage AuthZConditionMessage = "Fetching all available API groups"
)

// Resource discovery related condition constants.
const (
	// ResourceDiscoveryCondition indicates resource discovery status.
	ResourceDiscoveryCondition AuthZConditionType = "ResourceDiscovered"
	// ResourceDiscoveryReason is the reason for resource discovery condition.
	ResourceDiscoveryReason AuthZConditionReason = "Discovery"
	// ResourceDiscoveryMessage is the message for resource discovery condition.
	ResourceDiscoveryMessage AuthZConditionMessage = "Fetching all available API resources"
)

// API filtering related condition constants.
const (
	// APIFilteredCondition indicates API group filtering status.
	APIFilteredCondition AuthZConditionType = "APIGroupFiltered"
	// APIFilteredReason is the reason for API filtering condition.
	APIFilteredReason AuthZConditionReason = "Filtering"
	// APIFilteredMessage is the message for API filtering condition.
	APIFilteredMessage AuthZConditionMessage = "Filtering API groups via denylist"
)

// Resource filtering related condition constants.
const (
	// ResourceFilteredCondition indicates resource filtering status.
	ResourceFilteredCondition AuthZConditionType = "ResourceFiltered"
	// ResourceFilteredReason is the reason for resource filtering condition.
	ResourceFilteredReason AuthZConditionReason = "Filtering"
	// ResourceFilteredMessage is the message for resource filtering condition.
	ResourceFilteredMessage AuthZConditionMessage = "Filtering API resources via denylist"
)

// Create related condition constants.
const (
	// CreateCondition indicates creation status.
	CreateCondition AuthZConditionType = "Created"
	// CreateReason is the reason for creation condition.
	CreateReason AuthZConditionReason = "TriggeredCreate"
	// CreateMessage is the message for creation condition.
	CreateMessage AuthZConditionMessage = "Reconciling creation request"
)

// Role reference validation related condition constants.
const (
	// RoleRefValidCondition indicates whether all referenced roles exist.
	RoleRefValidCondition AuthZConditionType = "RoleRefsValid"
	// RoleRefValidReason is the reason for valid role reference condition.
	RoleRefValidReason AuthZConditionReason = "RoleRefValidation"
	// RoleRefValidMessage is the message for valid role reference condition.
	RoleRefValidMessage AuthZConditionMessage = "All referenced roles exist"

	// RoleRefInvalidReason is used when one or more referenced roles don't exist.
	RoleRefInvalidReason AuthZConditionReason = "RoleRefNotFound"
	// RoleRefInvalidMessage is the format string when role references are missing.
	// Use with the list of missing role names (accepts any type via %v).
	RoleRefInvalidMessage AuthZConditionMessage = "Missing role references: %v"
)

// WebhookAuthorizer condition types.
const (
	// WebhookAuthorizerReadyCondition indicates overall readiness of the WebhookAuthorizer.
	WebhookAuthorizerReadyCondition AuthZConditionType = "Ready"
	// WebhookAuthorizerRulesValidCondition indicates whether resource and non-resource rules are valid.
	WebhookAuthorizerRulesValidCondition AuthZConditionType = "RulesValid"
	// WebhookAuthorizerNamespaceSelectorValidCondition indicates whether the namespace selector is parseable.
	WebhookAuthorizerNamespaceSelectorValidCondition AuthZConditionType = "NamespaceSelectorValid"
	// WebhookAuthorizerPrincipalConfiguredCondition indicates whether principals are defined.
	WebhookAuthorizerPrincipalConfiguredCondition AuthZConditionType = "PrincipalConfigured"
)

// WebhookAuthorizer Ready condition reasons.
const (
	// WAReadyReasonAuthorizerReady indicates the authorizer is processing requests.
	WAReadyReasonAuthorizerReady AuthZConditionReason = "AuthorizerReady"
	// WAReadyReasonInvalidRules indicates one or more rules are malformed.
	WAReadyReasonInvalidRules AuthZConditionReason = "InvalidRules"
	// WAReadyReasonInvalidNamespaceSelector indicates the namespace selector cannot be parsed.
	WAReadyReasonInvalidNamespaceSelector AuthZConditionReason = "InvalidNamespaceSelector"
	// WAReadyReasonNoPrincipals indicates neither allowed nor denied principals are defined.
	WAReadyReasonNoPrincipals AuthZConditionReason = "NoPrincipals"
)

// WebhookAuthorizer Ready condition messages.
const (
	// WAReadyMessageAuthorizerReady is the message when the authorizer is healthy.
	WAReadyMessageAuthorizerReady AuthZConditionMessage = "All rules are valid and the authorizer is actively processing requests"
	// WAReadyMessageInvalidRules is the message when rules are invalid.
	WAReadyMessageInvalidRules AuthZConditionMessage = "One or more resource/non-resource rules are malformed: %s"
	// WAReadyMessageInvalidSelector is the message when the namespace selector is invalid.
	WAReadyMessageInvalidSelector AuthZConditionMessage = "The namespace selector cannot be parsed: %s"
	// WAReadyMessageNoPrincipals is the message when no principals are defined.
	WAReadyMessageNoPrincipals AuthZConditionMessage = "Neither allowedPrincipals nor deniedPrincipals are defined"
)

// WebhookAuthorizer RulesValid condition reasons.
const (
	// WARulesValidReasonAllValid indicates all rules are syntactically valid.
	WARulesValidReasonAllValid AuthZConditionReason = "AllRulesValid"
	// WARulesValidReasonInvalidResourceRule indicates a resourceRule is invalid.
	WARulesValidReasonInvalidResourceRule AuthZConditionReason = "InvalidResourceRule"
	// WARulesValidReasonInvalidNonResourceRule indicates a nonResourceRule is invalid.
	WARulesValidReasonInvalidNonResourceRule AuthZConditionReason = "InvalidNonResourceRule"
)

// WebhookAuthorizer RulesValid condition messages.
const (
	// WARulesValidMessageAllValid is the message when all rules are valid.
	WARulesValidMessageAllValid AuthZConditionMessage = "All resourceRules and nonResourceRules are syntactically valid"
	// WARulesValidMessageInvalidResource is the message when a resource rule is invalid.
	WARulesValidMessageInvalidResource AuthZConditionMessage = "A resourceRule contains invalid API groups, resources, or verbs: %s"
	// WARulesValidMessageInvalidNonResource is the message when a non-resource rule is invalid.
	WARulesValidMessageInvalidNonResource AuthZConditionMessage = "A nonResourceRule contains invalid paths or verbs: %s"
)

// WebhookAuthorizer NamespaceSelectorValid condition reasons.
const (
	// WANSSelectorValidReasonValid indicates the namespace selector is parseable.
	WANSSelectorValidReasonValid AuthZConditionReason = "SelectorValid"
	// WANSSelectorValidReasonEmpty indicates no namespace selector is defined.
	WANSSelectorValidReasonEmpty AuthZConditionReason = "SelectorEmpty"
	// WANSSelectorValidReasonInvalid indicates the namespace selector cannot be parsed.
	WANSSelectorValidReasonInvalid AuthZConditionReason = "SelectorInvalid"
)

// WebhookAuthorizer NamespaceSelectorValid condition messages.
const (
	// WANSSelectorValidMessageValid is the message when the selector is valid.
	WANSSelectorValidMessageValid AuthZConditionMessage = "Namespace selector is parseable and matches namespaces"
	// WANSSelectorValidMessageEmpty is the message when no selector is defined.
	WANSSelectorValidMessageEmpty AuthZConditionMessage = "No namespace selector defined (matches all namespaces)"
	// WANSSelectorValidMessageInvalid is the message when the selector is invalid.
	WANSSelectorValidMessageInvalid AuthZConditionMessage = "Namespace selector cannot be parsed: %s"
)

// WebhookAuthorizer PrincipalConfigured condition reasons.
const (
	// WAPrincipalReasonConfigured indicates principals are defined.
	WAPrincipalReasonConfigured AuthZConditionReason = "PrincipalsConfigured"
	// WAPrincipalReasonNotConfigured indicates no principals are defined.
	WAPrincipalReasonNotConfigured AuthZConditionReason = "NoPrincipalsConfigured"
	// WAPrincipalReasonOverlap indicates a principal appears in both allowed and denied lists.
	// Expected status: metav1.ConditionUnknown (warning — authorizer will still function).
	WAPrincipalReasonOverlap AuthZConditionReason = "PrincipalOverlap"
)

// WebhookAuthorizer PrincipalConfigured condition messages.
const (
	// WAPrincipalMessageConfigured is the message when principals are defined.
	WAPrincipalMessageConfigured AuthZConditionMessage = "AllowedPrincipals and/or DeniedPrincipals are defined"
	// WAPrincipalMessageNotConfigured is the message when no principals are defined.
	WAPrincipalMessageNotConfigured AuthZConditionMessage = "No principals defined — authorizer will never match"
	// WAPrincipalMessageOverlap is the message when principals overlap.
	WAPrincipalMessageOverlap AuthZConditionMessage = "A principal appears in both allowed and denied lists: %s"
)
