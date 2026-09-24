// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"fmt"
	"slices"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	rbacvalidation "k8s.io/component-helpers/auth/rbac/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
)

// bridgeBindDefinition only grants permissions a selector-backed RoleBinding
// would grant. All reads must be live: a stale label or revoked role is unsafe.
func (wa *Authorizer) bridgeBindDefinition(ctx context.Context, sar *authzv1.SubjectAccessReview) (matched bool, name string) {
	attr := sar.Spec.ResourceAttributes
	if !bridgeEligible(attr) {
		return false, ""
	}

	bindings, err := listAllCachedBindDefinitionsWithRoleBindings(ctx, wa.Client)
	if err != nil {
		wa.Log.Error(err, "failed to list BindDefinitions for authorization bridge")
		return false, ""
	}
	bindings = bridgeCandidates(bindings, sar)
	if len(bindings) == 0 {
		return false, ""
	}
	ns := &corev1.Namespace{}
	if err := wa.Client.Get(ctx, client.ObjectKey{Name: attr.Namespace}, ns); err != nil {
		wa.Log.V(1).Info("authorization bridge namespace unavailable", "namespace", attr.Namespace, "error", err)
		return false, ""
	}
	if !conditions.IsNamespaceActive(ns) {
		return false, ""
	}

	var matchedName string
	for i := range bindings {
		bd := &bindings[i]
		for _, binding := range bd.Spec.RoleBindings {
			if !binding.AuthorizeBeforeBinding || binding.Namespace != "" || len(binding.NamespaceSelector) == 0 {
				continue
			}
			matches, err := bridgeSelectorMatches(binding, ns.Labels)
			if err != nil {
				wa.Log.Error(err, "invalid BindDefinition authorization bridge selector", "bindDefinition", bd.Name)
				return false, ""
			}
			if !matches {
				continue
			}
			allowed, err := wa.bridgeBindingAllows(ctx, binding, attr)
			if err != nil {
				wa.Log.V(1).Info("authorization bridge role unavailable", "bindDefinition", bd.Name, "error", err)
				return false, ""
			}
			if allowed {
				matchedName = bd.Name
			}
		}
	}
	return matchedName != "", matchedName
}

func bridgeCandidates(bindings []authorizationv1alpha1.BindDefinition, sar *authzv1.SubjectAccessReview) []authorizationv1alpha1.BindDefinition {
	candidates := bindings[:0]
	for _, bd := range bindings {
		if !bindDefinitionSubjectMatches(sar, bd.Spec.Subjects) {
			continue
		}
		for _, binding := range bd.Spec.RoleBindings {
			if binding.AuthorizeBeforeBinding && binding.Namespace == "" && len(binding.NamespaceSelector) > 0 {
				candidates = append(candidates, bd)
				break
			}
		}
	}
	return candidates
}

func bridgeEligible(attr *authzv1.ResourceAttributes) bool {
	return attr != nil && attr.Namespace != "" && attr.Verb != "bind" &&
		attr.Verb != "escalate" && attr.Verb != "impersonate" &&
		!authorizationv1alpha1.IsImpersonationVerb(attr.Verb)
}

func bridgeSelectorMatches(binding authorizationv1alpha1.NamespaceBinding, namespaceLabels map[string]string) (bool, error) {
	selectors, err := binding.Selectors()
	if err != nil {
		return false, err
	}
	for _, selector := range selectors {
		if selector.Matches(labels.Set(namespaceLabels)) {
			return true, nil
		}
	}
	return false, nil
}

func (wa *Authorizer) bridgeBindingAllows(ctx context.Context, binding authorizationv1alpha1.NamespaceBinding, attr *authzv1.ResourceAttributes) (bool, error) {
	allowed := false
	for _, name := range binding.ClusterRoleRefs {
		role := &rbacv1.ClusterRole{}
		if err := wa.Client.Get(ctx, client.ObjectKey{Name: name}, role); err != nil {
			return false, fmt.Errorf("get ClusterRole %q: %w", name, err)
		}
		allowed = bridgeRulesAllow(role.Rules, attr) || allowed
	}
	for _, name := range binding.RoleRefs {
		role := &rbacv1.Role{}
		if err := wa.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: attr.Namespace}, role); err != nil {
			return false, fmt.Errorf("get Role %q in namespace %q: %w", name, attr.Namespace, err)
		}
		allowed = bridgeRulesAllow(role.Rules, attr) || allowed
	}
	return allowed, nil
}

func bindDefinitionSubjectMatches(sar *authzv1.SubjectAccessReview, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		switch subject.Kind {
		case rbacv1.ServiceAccountKind:
			if subject.APIGroup == "" && subject.Namespace != "" && subject.Name != "" &&
				sar.Spec.User == "system:serviceaccount:"+subject.Namespace+":"+subject.Name {
				return true
			}
		case rbacv1.UserKind:
			if subject.APIGroup == rbacv1.GroupName && subject.Namespace == "" &&
				subject.Name != "" && subject.Name == sar.Spec.User {
				return true
			}
		case rbacv1.GroupKind:
			if subject.APIGroup == rbacv1.GroupName && subject.Namespace == "" &&
				subject.Name != "" && slices.Contains(sar.Spec.Groups, subject.Name) {
				return true
			}
		}
	}
	return false
}

func bridgeRulesAllow(rules []rbacv1.PolicyRule, attr *authzv1.ResourceAttributes) bool {
	resource := attr.Resource
	if attr.Subresource != "" {
		resource += "/" + attr.Subresource
	}
	request := rbacv1.PolicyRule{
		Verbs: []string{attr.Verb}, APIGroups: []string{attr.Group}, Resources: []string{resource},
	}
	if attr.Name != "" {
		request.ResourceNames = []string{attr.Name}
	}
	covered, _ := rbacvalidation.Covers(rules, []rbacv1.PolicyRule{request})
	return covered
}
