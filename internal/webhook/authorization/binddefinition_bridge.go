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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	rbacvalidation "k8s.io/component-helpers/auth/rbac/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/indexer"
)

const (
	maxBridgeGroups     = 64
	maxBridgeCandidates = 64
	maxBridgeRoleReads  = 128
)

// Cached indexes only nominate candidates. A missing cache entry delays an allow;
// live reads of each candidate, namespace and role prevent stale cache grants.
//
//nolint:gocyclo // Fail-closed checks for each independent grant prerequisite.
func (wa *Authorizer) bridgeBindDefinition(ctx context.Context, sar *authzv1.SubjectAccessReview) (matched bool, name string) {
	attr := sar.Spec.ResourceAttributes
	if !bridgeEligible(attr) || wa.LiveReader == nil {
		return false, ""
	}
	names, err := wa.bridgeCandidates(ctx, sar)
	if err != nil {
		wa.Log.Error(err, "failed to select BindDefinitions for authorization bridge")
		return false, ""
	}
	if len(names) == 0 {
		return false, ""
	}
	if !wa.bridgeResourceNamespaced(ctx, attr) {
		return false, ""
	}
	ns := &corev1.Namespace{}
	if err := wa.LiveReader.Get(ctx, client.ObjectKey{Name: attr.Namespace}, ns); err != nil {
		wa.Log.V(1).Info("authorization bridge namespace unavailable", "namespace", attr.Namespace, "error", err)
		return false, ""
	}
	if !conditions.IsNamespaceActive(ns) {
		return false, ""
	}

	var matchedName string
	roleReads := 0
	for _, name := range names {
		bd := &authorizationv1alpha1.BindDefinition{}
		if err := wa.LiveReader.Get(ctx, client.ObjectKey{Name: name}, bd); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			wa.Log.Error(err, "failed to verify BindDefinition for authorization bridge", "bindDefinition", name)
			return false, ""
		}
		if !bd.DeletionTimestamp.IsZero() || !bindDefinitionSubjectMatches(sar, bd.Spec.Subjects) {
			continue
		}
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
			allowed, err := wa.bridgeBindingAllows(ctx, binding, attr, &roleReads)
			if err != nil {
				wa.Log.Error(err, "authorization bridge role unavailable", "bindDefinition", bd.Name)
				return false, ""
			}
			if allowed {
				matchedName = bd.Name
			}
		}
	}
	return matchedName != "", matchedName
}

func (wa *Authorizer) bridgeResourceNamespaced(ctx context.Context, attr *authzv1.ResourceAttributes) bool {
	if wa.Discovery == nil {
		return false
	}
	version := attr.Version
	if version == "*" {
		version = ""
	}
	if version == "" && attr.Group == "" {
		version = "v1"
	} else if version == "" {
		groups, err := wa.Discovery.ServerGroupsWithContext(ctx)
		if err != nil {
			wa.Log.Error(err, "authorization bridge group discovery failed")
			return false
		}
		for _, group := range groups.Groups {
			if group.Name == attr.Group {
				version = group.PreferredVersion.Version
				break
			}
		}
	}
	if version == "" {
		return false
	}
	resources, err := wa.Discovery.ServerResourcesForGroupVersionWithContext(ctx, schema.GroupVersion{Group: attr.Group, Version: version}.String())
	if err != nil {
		wa.Log.Error(err, "authorization bridge resource discovery failed", "group", attr.Group, "version", version, "resource", attr.Resource)
		return false
	}
	for _, resource := range resources.APIResources {
		if resource.Name == attr.Resource {
			return resource.Namespaced
		}
	}
	return false
}

func (wa *Authorizer) bridgeCandidates(ctx context.Context, sar *authzv1.SubjectAccessReview) ([]string, error) {
	if len(sar.Spec.Groups) > maxBridgeGroups {
		return nil, fmt.Errorf("bridge group limit exceeded: %d", len(sar.Spec.Groups))
	}
	keys := make([]string, 0, 1+len(sar.Spec.Groups))
	if sar.Spec.User != "" {
		keys = append(keys, "u:"+sar.Spec.User)
	}
	for _, group := range sar.Spec.Groups {
		if !slices.Contains(keys, "g:"+group) {
			keys = append(keys, "g:"+group)
		}
	}
	names := make([]string, 0)
	seen := make(map[string]struct{})
	for _, key := range keys {
		list := &authorizationv1alpha1.BindDefinitionList{}
		if err := wa.Client.List(ctx, list, client.MatchingFields{indexer.BindDefinitionBridgeSubjectField: key}); err != nil {
			return nil, err
		}
		for _, bd := range list.Items {
			if _, ok := seen[bd.Name]; ok {
				continue
			}
			if len(names) >= maxBridgeCandidates {
				return nil, fmt.Errorf("bridge candidate limit exceeded: %d", maxBridgeCandidates)
			}
			seen[bd.Name] = struct{}{}
			names = append(names, bd.Name)
		}
	}
	return names, nil
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

func (wa *Authorizer) bridgeBindingAllows(ctx context.Context, binding authorizationv1alpha1.NamespaceBinding, attr *authzv1.ResourceAttributes, roleReads *int) (bool, error) {
	allowed := false
	for _, name := range binding.ClusterRoleRefs {
		if *roleReads >= maxBridgeRoleReads {
			return false, fmt.Errorf("bridge role read limit exceeded: %d", maxBridgeRoleReads)
		}
		*roleReads++
		role := &rbacv1.ClusterRole{}
		if err := wa.LiveReader.Get(ctx, client.ObjectKey{Name: name}, role); err != nil {
			return false, fmt.Errorf("get ClusterRole %q: %w", name, err)
		}
		allowed = bridgeRulesAllow(role.Rules, attr) || allowed
	}
	for _, name := range binding.RoleRefs {
		if *roleReads >= maxBridgeRoleReads {
			return false, fmt.Errorf("bridge role read limit exceeded: %d", maxBridgeRoleReads)
		}
		*roleReads++
		role := &rbacv1.Role{}
		if err := wa.LiveReader.Get(ctx, client.ObjectKey{Name: name, Namespace: attr.Namespace}, role); err != nil {
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
