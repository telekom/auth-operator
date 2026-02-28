// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"regexp"
	"testing"
)

func TestWebhookAuthorizerConditionConstants(t *testing.T) {
	t.Parallel()

	// Condition types must be non-empty and unique.
	types := []AuthZConditionType{
		WebhookAuthorizerReadyCondition,
		WebhookAuthorizerRulesValidCondition,
		WebhookAuthorizerNamespaceSelectorValidCondition,
		WebhookAuthorizerPrincipalConfiguredCondition,
	}

	seen := make(map[AuthZConditionType]bool)
	for _, ct := range types {
		if ct == "" {
			t.Error("condition type is empty")
		}
		if seen[ct] {
			t.Errorf("duplicate condition type: %q", ct)
		}
		seen[ct] = true
	}
}

func TestWebhookAuthorizerReadyReasons(t *testing.T) {
	t.Parallel()

	reasons := []struct {
		reason  AuthZConditionReason
		message AuthZConditionMessage
	}{
		{WAReadyReasonAuthorizerReady, WAReadyMessageAuthorizerReady},
		{WAReadyReasonInvalidRules, WAReadyMessageInvalidRules},
		{WAReadyReasonInvalidNamespaceSelector, WAReadyMessageInvalidSelector},
		{WAReadyReasonNoPrincipals, WAReadyMessageNoPrincipals},
	}

	for _, r := range reasons {
		if r.reason == "" {
			t.Error("Ready reason is empty")
		}
		if r.message == "" {
			t.Errorf("Ready message is empty for reason %q", r.reason)
		}
	}
}

func TestWebhookAuthorizerRulesValidReasons(t *testing.T) {
	t.Parallel()

	reasons := []struct {
		reason  AuthZConditionReason
		message AuthZConditionMessage
	}{
		{WARulesValidReasonAllValid, WARulesValidMessageAllValid},
		{WARulesValidReasonInvalidResourceRule, WARulesValidMessageInvalidResource},
		{WARulesValidReasonInvalidNonResourceRule, WARulesValidMessageInvalidNonResource},
	}

	for _, r := range reasons {
		if r.reason == "" {
			t.Error("RulesValid reason is empty")
		}
		if r.message == "" {
			t.Errorf("RulesValid message is empty for reason %q", r.reason)
		}
	}
}

func TestWebhookAuthorizerNSSelectorValidReasons(t *testing.T) {
	t.Parallel()

	reasons := []struct {
		reason  AuthZConditionReason
		message AuthZConditionMessage
	}{
		{WANSSelectorValidReasonValid, WANSSelectorValidMessageValid},
		{WANSSelectorValidReasonEmpty, WANSSelectorValidMessageEmpty},
		{WANSSelectorValidReasonInvalid, WANSSelectorValidMessageInvalid},
	}

	for _, r := range reasons {
		if r.reason == "" {
			t.Error("NamespaceSelectorValid reason is empty")
		}
		if r.message == "" {
			t.Errorf("NamespaceSelectorValid message is empty for reason %q", r.reason)
		}
	}
}

func TestWebhookAuthorizerPrincipalReasons(t *testing.T) {
	t.Parallel()

	reasons := []struct {
		reason  AuthZConditionReason
		message AuthZConditionMessage
	}{
		{WAPrincipalReasonConfigured, WAPrincipalMessageConfigured},
		{WAPrincipalReasonNotConfigured, WAPrincipalMessageNotConfigured},
		{WAPrincipalReasonOverlap, WAPrincipalMessageOverlap},
	}

	for _, r := range reasons {
		if r.reason == "" {
			t.Error("PrincipalConfigured reason is empty")
		}
		if r.message == "" {
			t.Errorf("PrincipalConfigured message is empty for reason %q", r.reason)
		}
	}
}

func TestWebhookAuthorizerConditionTypesDoNotCollideWithExisting(t *testing.T) {
	t.Parallel()

	// Existing domain-specific condition types used by RoleDefinition/BindDefinition.
	existing := []AuthZConditionType{
		FinalizerCondition,
		NamespaceTerminationBlockedCondition,
		OwnerRefCondition,
		DeleteCondition,
		APIDiscoveryCondition,
		ResourceDiscoveryCondition,
		APIFilteredCondition,
		ResourceFilteredCondition,
		CreateCondition,
		RoleRefValidCondition,
	}

	waTypes := []AuthZConditionType{
		WebhookAuthorizerReadyCondition,
		WebhookAuthorizerRulesValidCondition,
		WebhookAuthorizerNamespaceSelectorValidCondition,
		WebhookAuthorizerPrincipalConfiguredCondition,
	}

	existingSet := make(map[AuthZConditionType]bool)
	for _, ct := range existing {
		existingSet[ct] = true
	}

	for _, ct := range waTypes {
		// "Ready" is expected to collide since it's the kstatus standard —
		// every CRD uses the same Ready type.
		if ct == WebhookAuthorizerReadyCondition {
			continue
		}
		if existingSet[ct] {
			t.Errorf("WebhookAuthorizer condition type %q collides with existing condition", ct)
		}
	}
}

// TestWebhookAuthorizerReasonFormat validates that all Reason constants conform to
// the Kubernetes API convention: CamelCase matching ^[A-Za-z]([A-Za-z0-9]*[A-Za-z0-9])?$
func TestWebhookAuthorizerReasonFormat(t *testing.T) {
	t.Parallel()
	validReason := regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9]*[A-Za-z0-9])?$`)
	reasons := []AuthZConditionReason{
		WAReadyReasonAuthorizerReady, WAReadyReasonInvalidRules,
		WAReadyReasonInvalidNamespaceSelector, WAReadyReasonNoPrincipals,
		WARulesValidReasonAllValid, WARulesValidReasonInvalidResourceRule,
		WARulesValidReasonInvalidNonResourceRule,
		WANSSelectorValidReasonValid, WANSSelectorValidReasonEmpty,
		WANSSelectorValidReasonInvalid,
		WAPrincipalReasonConfigured, WAPrincipalReasonNotConfigured,
		WAPrincipalReasonOverlap,
	}
	for _, r := range reasons {
		if !validReason.MatchString(string(r)) {
			t.Errorf("reason %q does not match K8s CamelCase format", r)
		}
	}
}
