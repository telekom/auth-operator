// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/telekom/auth-operator/pkg/helpers"
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

func resolveDefaultPoliciesForRequester(ctx context.Context, c client.Client, username string, groups []string) ([]string, error) {
	policyList := &RBACPolicyList{}
	if err := c.List(ctx, policyList, client.MatchingFields{HasDefaultAssignmentField: "true"}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			return nil, fmt.Errorf("list RBACPolicies with default assignment: %w", err)
		}

		// Fallback for tests/misconfigured managers without the RBACPolicy
		// default-assignment field index.
		if listErr := c.List(ctx, policyList); listErr != nil {
			return nil, fmt.Errorf("list RBACPolicies: %w", listErr)
		}
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

func selectedPolicyMatchesRequester(ctx context.Context, c client.Client, selectedPolicy, username string, groups []string) (bool, error) {
	if selectedPolicy == "" {
		return false, nil
	}

	selected := &RBACPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: selectedPolicy}, selected); err != nil {
		return false, fmt.Errorf("get selected RBACPolicy %q: %w", selectedPolicy, err)
	}

	return requesterMatchesDefaultAssignment(selected.Spec.DefaultAssignment, username, groups), nil
}

func validateDefaultPolicyForRequester(
	ctx context.Context,
	c client.Client,
	groupKind schema.GroupKind,
	objName, selectedPolicy string,
) error {
	req, reqFound := requestFromAdmissionContext(ctx)
	if !reqFound {
		// Context without admission request (e.g. direct unit call) is treated as
		// "no identity information", so default-policy enforcement is skipped.
		return nil
	}

	selectedMatches, err := selectedPolicyMatchesRequester(ctx, c, selectedPolicy, req.UserInfo.Username, req.UserInfo.Groups)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to evaluate selected policy assignment", "selectedPolicy", selectedPolicy)
		return apierrors.NewInternalError(errors.New("unable to resolve default policy assignments"))
	}
	if selectedMatches {
		// Fast path: selected policy already matches requester assignment.
		return nil
	}

	matchedPolicies, err := resolveDefaultPoliciesForRequester(ctx, c, req.UserInfo.Username, req.UserInfo.Groups)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to resolve default policy assignments")
		return apierrors.NewInternalError(errors.New("unable to resolve default policy assignments"))
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
