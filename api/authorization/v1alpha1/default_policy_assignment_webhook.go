// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type requesterServiceAccount struct {
	Name             string
	Namespace        string
	IsServiceAccount bool
}

func parseRequesterServiceAccount(username string) requesterServiceAccount {
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return requesterServiceAccount{}
	}

	return requesterServiceAccount{
		Name:             parts[3],
		Namespace:        parts[2],
		IsServiceAccount: true,
	}
}

func requesterMatchesDefaultAssignment(da *DefaultPolicyAssignment, username string, groups []string) bool {
	if da == nil {
		return false
	}

	for _, requesterGroup := range groups {
		for _, assignedGroup := range da.Groups {
			if requesterGroup == assignedGroup {
				return true
			}
		}
	}

	sa := parseRequesterServiceAccount(username)
	if !sa.IsServiceAccount {
		return false
	}

	for _, assignedSA := range da.ServiceAccounts {
		if assignedSA.Name == sa.Name && assignedSA.Namespace == sa.Namespace {
			return true
		}
	}

	return false
}

func resolveDefaultPoliciesForRequester(ctx context.Context, c client.Reader, username string, groups []string) ([]string, error) {
	policyList := &RBACPolicyList{}
	if err := c.List(ctx, policyList); err != nil {
		return nil, fmt.Errorf("list RBACPolicies: %w", err)
	}

	matchedPolicies := make([]string, 0)
	for _, policy := range policyList.Items {
		if policy.Spec.DefaultAssignment == nil {
			continue
		}
		if requesterMatchesDefaultAssignment(policy.Spec.DefaultAssignment, username, groups) {
			matchedPolicies = append(matchedPolicies, policy.Name)
		}
	}

	sort.Strings(matchedPolicies)
	return matchedPolicies, nil
}

func selectedPolicyAssignment(ctx context.Context, c client.Reader, selectedPolicy, username string, groups []string) (matchesRequester, hasDefaultAssignment, deleting bool, retErr error) {
	if selectedPolicy == "" {
		return false, false, false, nil
	}

	selected := &RBACPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: selectedPolicy}, selected); err != nil {
		if apierrors.IsNotFound(err) {
			return false, false, false, err
		}
		return false, false, false, fmt.Errorf("get selected RBACPolicy %q: %w", selectedPolicy, err)
	}

	if selected.GetDeletionTimestamp() != nil {
		return false, false, true, nil
	}

	if selected.Spec.DefaultAssignment == nil {
		return false, false, false, nil
	}
	return requesterMatchesDefaultAssignment(selected.Spec.DefaultAssignment, username, groups), true, false, nil
}

func selectedPolicyMatchesRequester(ctx context.Context, c client.Reader, selectedPolicy, username string, groups []string) (bool, error) {
	matches, _, _, err := selectedPolicyAssignment(ctx, c, selectedPolicy, username, groups)
	return matches, err
}

func invalidDeletingPolicyRef(groupKind schema.GroupKind, objName, policyName string) error {
	return apierrors.NewInvalid(
		groupKind,
		objName,
		field.ErrorList{
			field.Forbidden(
				field.NewPath("spec", "policyRef", "name"),
				fmt.Sprintf("referenced RBACPolicy %q is being deleted", policyName),
			),
		},
	)
}

func validateDefaultPolicyForRequester(
	ctx context.Context,
	c client.Reader,
	groupKind schema.GroupKind,
	objName, selectedPolicy string,
) error {
	req, reqFound := requestFromAdmissionContext(ctx)
	if !reqFound {
		// Context without admission request (e.g. direct unit call) is treated as
		// "no identity information", so default-policy enforcement is skipped.
		return nil
	}

	selectedMatches, selectedHasDefaultAssignment, selectedDeleting, err := selectedPolicyAssignment(
		ctx, c, selectedPolicy, req.UserInfo.Username, req.UserInfo.Groups)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return apierrors.NewInvalid(
				groupKind,
				objName,
				field.ErrorList{
					field.NotFound(field.NewPath("spec", "policyRef", "name"), selectedPolicy),
				},
			)
		}
		log.FromContext(ctx).Error(err, "failed to evaluate selected policy assignment", "selectedPolicy", selectedPolicy)
		return apierrors.NewInternalError(errors.New("unable to resolve default policy assignments"))
	}
	if selectedDeleting {
		return invalidDeletingPolicyRef(groupKind, objName, selectedPolicy)
	}

	matchedPolicies, err := resolveDefaultPoliciesForRequester(ctx, c, req.UserInfo.Username, req.UserInfo.Groups)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to resolve default policy assignments")
		return apierrors.NewInternalError(errors.New("unable to resolve default policy assignments"))
	}

	if len(matchedPolicies) > 1 {
		detail := fmt.Sprintf(
			"requester %q matches multiple default policies: %s",
			req.UserInfo.Username,
			strings.Join(matchedPolicies, ", "),
		)
		return apierrors.NewInvalid(
			groupKind,
			objName,
			field.ErrorList{
				field.Invalid(field.NewPath("spec", "policyRef", "name"), selectedPolicy, detail),
			},
		)
	}

	if selectedMatches {
		return nil
	}

	if selectedHasDefaultAssignment {
		detail := fmt.Sprintf(
			"requester %q is not assigned to selected default policy %q",
			req.UserInfo.Username,
			selectedPolicy,
		)
		return apierrors.NewInvalid(
			groupKind,
			objName,
			field.ErrorList{
				field.Invalid(field.NewPath("spec", "policyRef", "name"), selectedPolicy, detail),
			},
		)
	}

	if len(matchedPolicies) == 0 {
		return nil
	}

	for _, policyName := range matchedPolicies {
		if policyName == selectedPolicy {
			return nil
		}
	}

	detail := fmt.Sprintf(
		"requester %q must use one of the default policies: %s",
		req.UserInfo.Username,
		strings.Join(matchedPolicies, ", "),
	)

	return apierrors.NewInvalid(
		groupKind,
		objName,
		field.ErrorList{
			field.Invalid(field.NewPath("spec", "policyRef", "name"), selectedPolicy, detail),
		},
	)
}

func requestFromAdmissionContext(ctx context.Context) (admission.Request, bool) {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return admission.Request{}, false
	}

	return req, true
}

func metadataUpdateRequiresDefaultPolicy(ctx context.Context, oldObj, newObj client.Object) bool {
	if !reflect.DeepEqual(oldObj.GetLabels(), newObj.GetLabels()) ||
		!reflect.DeepEqual(oldObj.GetAnnotations(), newObj.GetAnnotations()) ||
		!reflect.DeepEqual(oldObj.GetOwnerReferences(), newObj.GetOwnerReferences()) {
		return true
	}

	if reflect.DeepEqual(oldObj.GetFinalizers(), newObj.GetFinalizers()) {
		return false
	}
	return !operatorFinalizerUpdateAllowed(ctx, oldObj, newObj)
}

func operatorFinalizerUpdateAllowed(ctx context.Context, oldObj, newObj client.Object) bool {
	finalizer, ok := managedFinalizerForObject(newObj)
	if !ok {
		return false
	}
	if !finalizerSetOnlyToggles(oldObj.GetFinalizers(), newObj.GetFinalizers(), finalizer) {
		return false
	}

	req, reqFound := requestFromAdmissionContext(ctx)
	if !reqFound {
		return false
	}
	return isAuthOperatorControllerServiceAccount(req.UserInfo.Username)
}

func managedFinalizerForObject(obj client.Object) (string, bool) {
	switch obj.(type) {
	case *RestrictedBindDefinition:
		return RestrictedBindDefinitionFinalizer, true
	case *RestrictedRoleDefinition:
		return RestrictedRoleDefinitionFinalizer, true
	default:
		return "", false
	}
}

func finalizerSetOnlyToggles(oldFinalizers, newFinalizers []string, target string) bool {
	oldSet := stringSet(oldFinalizers)
	newSet := stringSet(newFinalizers)
	changedTarget := false

	for finalizer := range oldSet {
		if _, exists := newSet[finalizer]; exists {
			continue
		}
		if finalizer != target {
			return false
		}
		changedTarget = true
	}
	for finalizer := range newSet {
		if _, exists := oldSet[finalizer]; exists {
			continue
		}
		if finalizer != target {
			return false
		}
		changedTarget = true
	}

	return changedTarget
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func isAuthOperatorControllerServiceAccount(username string) bool {
	sa := parseRequesterServiceAccount(username)
	if !sa.IsServiceAccount {
		return false
	}
	if sa.Namespace == "auth-operator-system" && sa.Name == "manager" {
		return true
	}
	return strings.HasSuffix(sa.Name, "-controller-manager") ||
		(strings.Contains(sa.Name, "auth-operator") && strings.HasSuffix(sa.Name, "-manager"))
}

func validateDefaultPolicyForMetadataUpdate(
	ctx context.Context,
	c client.Reader,
	groupKind schema.GroupKind,
	objName, selectedPolicy string,
	oldObj, newObj client.Object,
) error {
	if !metadataUpdateRequiresDefaultPolicy(ctx, oldObj, newObj) {
		return nil
	}
	return validateDefaultPolicyForRequester(ctx, c, groupKind, objName, selectedPolicy)
}
