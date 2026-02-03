package v1alpha1

import "github.com/telekom/auth-operator/pkg/conditions"

// AuthZConditionType represents authorization-related condition types.
type AuthZConditionType = conditions.ConditionType

// AuthZConditionReason represents authorization-related condition reasons.
type AuthZConditionReason = conditions.ConditionReason

// AuthZConditionMessage represents authorization-related condition messages.
type AuthZConditionMessage = conditions.ConditionMessage

// kstatus-compliant condition types.
// See: https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md
const (
	// ReadyCondition indicates whether the resource is fully reconciled.
	// When True, the actual state matches the desired state.
	// When False, the resource is not yet fully reconciled.
	ReadyCondition AuthZConditionType = "Ready"

	// ReconcilingCondition indicates the controller is actively working on reconciling
	// the resource. This follows the "abnormal-true" pattern - present and True when
	// reconciliation is in progress, absent when reconciliation is complete.
	ReconcilingCondition AuthZConditionType = "Reconciling"

	// StalledCondition indicates the controller has encountered an error or made
	// insufficient progress. This follows the "abnormal-true" pattern - present and
	// True when stalled, absent when not stalled.
	StalledCondition AuthZConditionType = "Stalled"
)

// Ready condition reasons.
const (
	// ReadyReasonReconciled indicates the resource is fully reconciled.
	ReadyReasonReconciled AuthZConditionReason = "Reconciled"
	// ReadyReasonReconciling indicates the resource is being reconciled.
	ReadyReasonReconciling AuthZConditionReason = "Reconciling"
	// ReadyReasonFailed indicates the reconciliation failed.
	ReadyReasonFailed AuthZConditionReason = "Failed"
)

// Ready condition messages.
const (
	// ReadyMessageReconciled is the message when the resource is fully reconciled.
	ReadyMessageReconciled AuthZConditionMessage = "Resource is fully reconciled"
	// ReadyMessageReconciling is the message when the resource is being reconciled.
	ReadyMessageReconciling AuthZConditionMessage = "Resource reconciliation in progress"
	// ReadyMessageFailed is the message format when reconciliation failed.
	ReadyMessageFailed AuthZConditionMessage = "Reconciliation failed: %s"
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
	// StalledReasonMissingDependency indicates a required dependency is missing.
	StalledReasonMissingDependency AuthZConditionReason = "MissingDependency"
)

// Stalled condition messages.
const (
	// StalledMessageError is the message format when an error occurred.
	StalledMessageError AuthZConditionMessage = "Error during reconciliation: %s"
	// StalledMessageMissingDependency is the message when a dependency is missing.
	StalledMessageMissingDependency AuthZConditionMessage = "Missing required dependency: %s"
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

// Update related condition constants.
const (
	// UpdateCondition indicates update status.
	UpdateCondition AuthZConditionType = "Updated"
	// UpdateReason is the reason for update condition.
	UpdateReason AuthZConditionReason = "TriggeredUpdate"
	// UpdateMessage is the message for update condition.
	UpdateMessage AuthZConditionMessage = "Reconciling update request"
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
	// RoleRefInvalidMessage is the message when role reference is invalid.
	RoleRefInvalidMessage AuthZConditionMessage = "One or more referenced roles do not exist"
)
