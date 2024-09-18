package v1alpha1

import "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/conditions"

// AuthNConditionType represents authentication-related condition types.
type AuthNConditionType = conditions.ConditionType

// AuthNConditionReason represents authentication-related condition reasons.
type AuthNConditionReason = conditions.ConditionReason

// AuthNConditionMessage represents authentication-related condition messages.
type AuthNConditionMessage = conditions.ConditionMessage

const (
	PlaywrightReady   AuthNConditionType    = "PlaywrightReady"
	PlaywrightReason  AuthNConditionReason  = "WrittenTo"
	PlaywrightMessage AuthNConditionMessage = "Written to all files"
)
