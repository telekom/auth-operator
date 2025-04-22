package v1alpha1

import "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/conditions"

// AuthZConditionType represents authorization-related condition types.
type AuthZConditionType = conditions.ConditionType

// AuthZConditionReason represents authorization-related condition reasons.
type AuthZConditionReason = conditions.ConditionReason

// AuthZConditionMessage represents authorization-related condition messages.
type AuthZConditionMessage = conditions.ConditionMessage

const (
	FinalizerCondition AuthZConditionType    = "Finalizer"
	FinalizerReason    AuthZConditionReason  = "OrphanPrevention"
	FinalizerMessage   AuthZConditionMessage = "Set finalizer to prevent orphaned resources"
)

const (
	OwnerRefCondition AuthZConditionType    = "OwnerRef"
	OwnerRefReason    AuthZConditionReason  = "ResourceOwnership"
	OwnerRefMessage   AuthZConditionMessage = "Set owner reference to child resource"
)

const (
	DeleteCondition AuthZConditionType    = "Deleted"
	DeleteReason    AuthZConditionReason  = "TriggeredDelete"
	DeleteMessage   AuthZConditionMessage = "Reconciling deletion request"
)

const (
	APIDiscoveryCondition AuthZConditionType    = "APIGroupDiscovered"
	APIDiscoveryReason    AuthZConditionReason  = "Discovery"
	APIDiscoveryMessage   AuthZConditionMessage = "Fetching all available API groups"
)

const (
	ResourceDiscoveryCondition AuthZConditionType    = "ResourceDiscovered"
	ResourceDiscoveryReason    AuthZConditionReason  = "Discovery"
	ResourceDiscoveryMessage   AuthZConditionMessage = "Fetching all available API resources"
)

const (
	APIFilteredCondition AuthZConditionType    = "APIGroupFiltered"
	APIFilteredReason    AuthZConditionReason  = "Filtering"
	APIFilteredMessage   AuthZConditionMessage = "Filtering API groups via denylist"
)

const (
	ResourceFilteredCondition AuthZConditionType    = "ResourceFiltered"
	ResourceFilteredReason    AuthZConditionReason  = "Filtering"
	ResourceFilteredMessage   AuthZConditionMessage = "Filtering API resources via denylist"
)

const (
	CreateCondition AuthZConditionType    = "Created"
	CreateReason    AuthZConditionReason  = "TriggeredCreate"
	CreateMessage   AuthZConditionMessage = "Reconciling creation request"
)

const (
	UpdateCondition AuthZConditionType    = "Updated"
	UpdateReason    AuthZConditionReason  = "TriggeredUpdate"
	UpdateMessage   AuthZConditionMessage = "Reconciling update request"
)
