// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// WebhookAuthorizerValidator implements admission.Validator for WebhookAuthorizer.
// +kubebuilder:object:generate=false
type WebhookAuthorizerValidator struct{}

var _ admission.Validator[*WebhookAuthorizer] = &WebhookAuthorizerValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (wa *WebhookAuthorizer) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, wa).
		WithValidator(&WebhookAuthorizerValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-webhookauthorizer,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=webhookauthorizers,verbs=create;update,versions=v1alpha1,name=webhookauthorizer.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for WebhookAuthorizer.
func (v *WebhookAuthorizerValidator) ValidateCreate(ctx context.Context, obj *WebhookAuthorizer) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("webhookauthorizer-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)
	return validateWebhookAuthorizer(obj)
}

// ValidateUpdate implements admission.Validator for WebhookAuthorizer.
// NOTE: We always validate on update because Kubernetes increments Generation
// after admission webhooks run, so old and new generations are always equal
// during the admission call.
func (v *WebhookAuthorizerValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *WebhookAuthorizer) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("webhookauthorizer-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)
	return validateWebhookAuthorizer(newObj)
}

// ValidateDelete implements admission.Validator for WebhookAuthorizer.
func (v *WebhookAuthorizerValidator) ValidateDelete(ctx context.Context, obj *WebhookAuthorizer) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("webhookauthorizer-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)
	return nil, nil
}

// validateWebhookAuthorizer performs semantic validation on the spec.
func validateWebhookAuthorizer(wa *WebhookAuthorizer) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Validate NamespaceSelector is parseable.
	if !isLabelSelectorEmpty(&wa.Spec.NamespaceSelector) {
		if _, err := metav1.LabelSelectorAsSelector(&wa.Spec.NamespaceSelector); err != nil {
			return nil, apierrors.NewBadRequest(
				fmt.Sprintf("invalid namespaceSelector: %v", err))
		}
	}

	// At least one of resourceRules or nonResourceRules must be defined.
	if len(wa.Spec.ResourceRules) == 0 && len(wa.Spec.NonResourceRules) == 0 {
		return nil, apierrors.NewBadRequest(
			"at least one of spec.resourceRules or spec.nonResourceRules must be non-empty")
	}

	// Validate each resourceRule has at least one verb.
	for i, rule := range wa.Spec.ResourceRules {
		if len(rule.Verbs) == 0 {
			return nil, apierrors.NewBadRequest(
				fmt.Sprintf("spec.resourceRules[%d] must have at least one verb", i))
		}
	}

	// Validate each nonResourceRule has at least one verb and one URL path.
	for i, rule := range wa.Spec.NonResourceRules {
		if len(rule.Verbs) == 0 {
			return nil, apierrors.NewBadRequest(
				fmt.Sprintf("spec.nonResourceRules[%d] must have at least one verb", i))
		}
		if len(rule.NonResourceURLs) == 0 {
			return nil, apierrors.NewBadRequest(
				fmt.Sprintf("spec.nonResourceRules[%d] must have at least one URL path", i))
		}
	}

	// Warn if allowed principals are empty.
	if len(wa.Spec.AllowedPrincipals) == 0 {
		warnings = append(warnings,
			"spec.allowedPrincipals is empty; no requests will be allowed by this authorizer")
	}

	// Warn if denied and allowed principals overlap.
	if overlaps := findPrincipalOverlaps(wa.Spec.AllowedPrincipals, wa.Spec.DeniedPrincipals); len(overlaps) > 0 {
		for _, overlap := range overlaps {
			warnings = append(warnings,
				fmt.Sprintf("principal %q appears in both allowedPrincipals and deniedPrincipals; denied takes precedence", overlap))
		}
	}

	// Warn about never-matching principals: Namespace set but User and Groups
	// are both empty, so the principal can never match any request.
	warnings = append(warnings, findNeverMatchingPrincipals("allowedPrincipals", wa.Spec.AllowedPrincipals)...)
	warnings = append(warnings, findNeverMatchingPrincipals("deniedPrincipals", wa.Spec.DeniedPrincipals)...)

	// Note on spec.allowedPrincipals[].namespace (see Issue #96):
	// The Namespace field on Principal is used only as a namespace filter for
	// ServiceAccounts and is not a full ServiceAccount reference. The
	// system:serviceaccount:<namespace>:<name> pattern applies to the User
	// field, not to Namespace. For this reason we intentionally do not enforce
	// any ServiceAccount-style naming pattern on Principal.Namespace here.

	return warnings, nil
}

// findNeverMatchingPrincipals returns warnings for principals that specify a
// Namespace but have empty User and Groups — they can never match any request.
func findNeverMatchingPrincipals(fieldName string, principals []Principal) admission.Warnings {
	var warnings admission.Warnings
	for i, p := range principals {
		if p.Namespace != "" && p.User == "" && len(p.Groups) == 0 {
			warnings = append(warnings,
				fmt.Sprintf("spec.%s[%d] has namespace %q but empty user and groups; it can never match", fieldName, i, p.Namespace))
		}
	}
	return warnings
}

// findPrincipalOverlaps returns all overlapping users or groups between
// allowed and denied principal lists. User overlap keys are NOT
// namespace-qualified because the runtime matching logic
// (principalMatches) checks principal.User == SAR.User directly,
// ignoring the Namespace field on the Principal struct.
func findPrincipalOverlaps(allowed, denied []Principal) []string {
	allowedUsers := make(map[string]struct{})
	allowedGroups := make(map[string]struct{})

	for _, p := range allowed {
		if p.User != "" {
			allowedUsers[p.User] = struct{}{}
		}
		for _, g := range p.Groups {
			allowedGroups[g] = struct{}{}
		}
	}

	seen := make(map[string]struct{})
	var overlaps []string
	for _, p := range denied {
		if p.User != "" {
			if _, ok := allowedUsers[p.User]; ok {
				if _, dup := seen[p.User]; !dup {
					seen[p.User] = struct{}{}
					overlaps = append(overlaps, p.User)
				}
			}
		}
		for _, g := range p.Groups {
			if _, ok := allowedGroups[g]; ok {
				if _, dup := seen[g]; !dup {
					seen[g] = struct{}{}
					overlaps = append(overlaps, g)
				}
			}
		}
	}
	return overlaps
}
