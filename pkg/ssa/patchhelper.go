// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// patchhelper implements a cache-aware diff-before-apply pattern inspired by
// the cluster-api patchHelper (https://github.com/kubernetes-sigs/cluster-api).
//
// The core idea: before sending an SSA Patch to the API server, read the current
// state from the controller-runtime informer cache (a free, local operation) and
// compare the fields we own. If the desired state already matches, the Apply is
// skipped entirely, saving an API round-trip.
//
// In clusters with many managed RBAC resources, this eliminates thousands of
// no-op PATCH requests per reconciliation cycle.
package ssa

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PatchApplyResult indicates the outcome of a patch-or-skip operation.
type PatchApplyResult int

const (
	// PatchApplyResultSkipped means the resource was already up-to-date (no API call made).
	PatchApplyResultSkipped PatchApplyResult = iota
	// PatchApplyResultCreated means the resource did not exist and was created via SSA.
	PatchApplyResultCreated
	// PatchApplyResultPatched means the resource existed but differed and was patched via SSA.
	PatchApplyResultPatched
)

// String returns a human-readable label for the result.
func (r PatchApplyResult) String() string {
	switch r {
	case PatchApplyResultSkipped:
		return "skipped"
	case PatchApplyResultCreated:
		return "created"
	case PatchApplyResultPatched:
		return "patched"
	default:
		return "unknown"
	}
}

// PatchApplyClusterRole reads the current ClusterRole from cache, compares it to
// the desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// Returns the result (skipped/created/patched) and any error.
func PatchApplyClusterRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return 0, fmt.Errorf("clusterRole ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return 0, fmt.Errorf("clusterRole ApplyConfiguration name must not be empty")
	}

	logger := log.FromContext(ctx)

	// Read via client (cache-backed in controllers).
	existing := &rbacv1.ClusterRole{}
	err := c.Get(ctx, types.NamespacedName{Name: *ac.Name}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Resource does not exist — must apply.
			if applyErr := c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership); applyErr != nil {
				return 0, fmt.Errorf("create ClusterRole %s: %w", *ac.Name, applyErr)
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get ClusterRole %s: %w", *ac.Name, err)
	}

	// Compare managed fields: labels, annotations, rules.
	if clusterRoleMatches(existing, ac) {
		logger.V(3).Info("ClusterRole unchanged, skipping SSA apply",
			"clusterRole", *ac.Name)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership); applyErr != nil {
		return 0, fmt.Errorf("patch ClusterRole %s: %w", *ac.Name, applyErr)
	}
	return PatchApplyResultPatched, nil
}

// PatchApplyRole reads the current Role from cache, compares it to the desired
// ApplyConfiguration, and only sends an SSA Patch if there is a diff.
func PatchApplyRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleApplyConfiguration,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return 0, fmt.Errorf("role ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return 0, fmt.Errorf("role ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil || *ac.Namespace == "" {
		return 0, fmt.Errorf("role ApplyConfiguration must have a namespace")
	}

	logger := log.FromContext(ctx)

	existing := &rbacv1.Role{}
	err := c.Get(ctx, types.NamespacedName{Name: *ac.Name, Namespace: *ac.Namespace}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if applyErr := c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership); applyErr != nil {
				return 0, fmt.Errorf("create Role %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get Role %s/%s: %w", *ac.Namespace, *ac.Name, err)
	}

	if roleMatches(existing, ac) {
		logger.V(3).Info("Role unchanged, skipping SSA apply",
			"role", *ac.Name, "namespace", *ac.Namespace)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership); applyErr != nil {
		return 0, fmt.Errorf("patch Role %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
	}
	return PatchApplyResultPatched, nil
}

// PatchApplyClusterRoleBinding reads the current CRB from cache, compares it to
// the desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
func PatchApplyClusterRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleBindingApplyConfiguration,
	fieldOwnerOverride ...string,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return 0, fmt.Errorf("clusterRoleBinding ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return 0, fmt.Errorf("clusterRoleBinding ApplyConfiguration name must not be empty")
	}

	fieldOwner, err := normalizeFieldOwner(fieldOwnerOverride...)
	if err != nil {
		return 0, err
	}

	logger := log.FromContext(ctx)

	existing := &rbacv1.ClusterRoleBinding{}
	err = c.Get(ctx, types.NamespacedName{Name: *ac.Name}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
				return 0, fmt.Errorf("create ClusterRoleBinding %s: %w", *ac.Name, applyErr)
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get ClusterRoleBinding %s: %w", *ac.Name, err)
	}

	if clusterRoleBindingMatches(existing, ac) {
		logger.V(3).Info("ClusterRoleBinding unchanged, skipping SSA apply",
			"clusterRoleBinding", *ac.Name)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
		return 0, fmt.Errorf("patch ClusterRoleBinding %s: %w", *ac.Name, applyErr)
	}
	return PatchApplyResultPatched, nil
}

// PatchApplyRoleBinding reads the current RB from cache, compares it to the
// desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
func PatchApplyRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleBindingApplyConfiguration,
	fieldOwnerOverride ...string,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return 0, fmt.Errorf("roleBinding ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return 0, fmt.Errorf("roleBinding ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil || *ac.Namespace == "" {
		return 0, fmt.Errorf("roleBinding ApplyConfiguration must have a namespace")
	}

	fieldOwner, err := normalizeFieldOwner(fieldOwnerOverride...)
	if err != nil {
		return 0, err
	}

	logger := log.FromContext(ctx)

	existing := &rbacv1.RoleBinding{}
	err = c.Get(ctx, types.NamespacedName{Name: *ac.Name, Namespace: *ac.Namespace}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
				return 0, fmt.Errorf("create RoleBinding %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get RoleBinding %s/%s: %w", *ac.Namespace, *ac.Name, err)
	}

	if roleBindingMatches(existing, ac) {
		logger.V(3).Info("RoleBinding unchanged, skipping SSA apply",
			"roleBinding", *ac.Name, "namespace", *ac.Namespace)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
		return 0, fmt.Errorf("patch RoleBinding %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
	}
	return PatchApplyResultPatched, nil
}

// PatchApplyServiceAccount reads the current SA from cache, compares it to the
// desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
func PatchApplyServiceAccount(
	ctx context.Context,
	c client.Client,
	ac *corev1ac.ServiceAccountApplyConfiguration,
	fieldOwner string,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return 0, fmt.Errorf("serviceAccount ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return 0, fmt.Errorf("serviceAccount ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil || *ac.Namespace == "" {
		return 0, fmt.Errorf("serviceAccount ApplyConfiguration must have a namespace")
	}
	if strings.TrimSpace(fieldOwner) == "" {
		return 0, fmt.Errorf("fieldOwner must not be empty")
	}

	logger := log.FromContext(ctx)

	existing := &corev1.ServiceAccount{}
	err := c.Get(ctx, types.NamespacedName{Name: *ac.Name, Namespace: *ac.Namespace}, existing)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
				return 0, fmt.Errorf("create ServiceAccount %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
			}
			return PatchApplyResultCreated, nil
		}
		return 0, fmt.Errorf("get ServiceAccount %s/%s: %w", *ac.Namespace, *ac.Name, err)
	}

	if serviceAccountMatches(existing, ac) {
		logger.V(3).Info("ServiceAccount unchanged, skipping SSA apply",
			"serviceAccount", *ac.Name, "namespace", *ac.Namespace)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership); applyErr != nil {
		return 0, fmt.Errorf("patch ServiceAccount %s/%s: %w", *ac.Namespace, *ac.Name, applyErr)
	}
	return PatchApplyResultPatched, nil
}

func normalizeFieldOwner(fieldOwnerOverride ...string) (string, error) {
	if len(fieldOwnerOverride) == 0 {
		return FieldOwner, nil
	}
	if len(fieldOwnerOverride) > 1 {
		return "", fmt.Errorf("at most one fieldOwner override is supported")
	}
	fieldOwner := strings.TrimSpace(fieldOwnerOverride[0])
	if fieldOwner == "" {
		return "", fmt.Errorf("fieldOwner must not be empty")
	}
	return fieldOwner, nil
}

// Comparison helpers — these compare only the fields we own via SSA and ignore
// server-managed fields (resourceVersion, uid, creationTimestamp, managedFields, etc.).

// clusterRoleMatches returns true if the existing ClusterRole already matches
// the desired ApplyConfiguration for all SSA-owned fields.
func clusterRoleMatches(existing *rbacv1.ClusterRole, ac *rbacv1ac.ClusterRoleApplyConfiguration) bool {
	if !labelsMatch(existing.Labels, ac.Labels) ||
		!annotationsMatch(existing.Annotations, ac.Annotations) ||
		!ownerRefsMatch(existing.OwnerReferences, ac.OwnerReferences) {
		return false
	}

	// For aggregating ClusterRoles, skip .rules comparison because the RBAC
	// aggregation controller manages .rules — comparing them would cause a
	// perpetual diff.  Compare the aggregation rule selectors instead.
	if ac.AggregationRule != nil {
		return aggregationRuleMatches(existing.AggregationRule, ac.AggregationRule)
	}

	return policyRulesMatch(existing.Rules, ac.Rules)
}

// roleMatches returns true if the existing Role already matches the desired ApplyConfiguration.
func roleMatches(existing *rbacv1.Role, ac *rbacv1ac.RoleApplyConfiguration) bool {
	return labelsMatch(existing.Labels, ac.Labels) &&
		annotationsMatch(existing.Annotations, ac.Annotations) &&
		ownerRefsMatch(existing.OwnerReferences, ac.OwnerReferences) &&
		policyRulesMatch(existing.Rules, ac.Rules)
}

// clusterRoleBindingMatches returns true if the existing CRB already matches.
func clusterRoleBindingMatches(existing *rbacv1.ClusterRoleBinding, ac *rbacv1ac.ClusterRoleBindingApplyConfiguration) bool {
	return labelsMatch(existing.Labels, ac.Labels) &&
		annotationsMatch(existing.Annotations, ac.Annotations) &&
		ownerRefsMatch(existing.OwnerReferences, ac.OwnerReferences) &&
		roleRefMatches(&existing.RoleRef, ac.RoleRef) &&
		subjectsMatch(existing.Subjects, ac.Subjects)
}

// roleBindingMatches returns true if the existing RB already matches.
func roleBindingMatches(existing *rbacv1.RoleBinding, ac *rbacv1ac.RoleBindingApplyConfiguration) bool {
	return labelsMatch(existing.Labels, ac.Labels) &&
		annotationsMatch(existing.Annotations, ac.Annotations) &&
		ownerRefsMatch(existing.OwnerReferences, ac.OwnerReferences) &&
		roleRefMatches(&existing.RoleRef, ac.RoleRef) &&
		subjectsMatch(existing.Subjects, ac.Subjects)
}

// serviceAccountMatches returns true if the existing SA already matches.
func serviceAccountMatches(existing *corev1.ServiceAccount, ac *corev1ac.ServiceAccountApplyConfiguration) bool {
	if !labelsMatch(existing.Labels, ac.Labels) {
		return false
	}
	if !annotationsMatch(existing.Annotations, ac.Annotations) {
		return false
	}
	if !ownerRefsMatch(existing.OwnerReferences, ac.OwnerReferences) {
		return false
	}
	// automountServiceAccountToken: compare if desired is set.
	if ac.AutomountServiceAccountToken != nil {
		if existing.AutomountServiceAccountToken == nil || *existing.AutomountServiceAccountToken != *ac.AutomountServiceAccountToken {
			return false
		}
	}
	return true
}

// Field-level comparators.

// labelsMatch checks that all desired labels are present in the existing object.
// Extra labels on the existing object (set by other controllers or users) are ignored
// since SSA only manages the fields we declare.
func labelsMatch(existing, desired map[string]string) bool {
	return mapContains(existing, desired)
}

// annotationsMatch checks that all desired annotations are present in the existing object.
func annotationsMatch(existing, desired map[string]string) bool {
	return mapContains(existing, desired)
}

// mapContains returns true if all entries in desired exist with the same value in existing.
func mapContains(existing, desired map[string]string) bool {
	for k, v := range desired {
		if ev, ok := existing[k]; !ok || ev != v {
			return false
		}
	}
	return true
}

// ownerRefsMatch checks that all desired OwnerReferences are present in the
// existing object (matched by UID). Extra owner refs on the existing object
// (set by other controllers) are ignored since SSA only manages the fields
// we declare. Controller and BlockOwnerDeletion flags are also compared when
// specified in the desired AC.
func ownerRefsMatch(existing []metav1.OwnerReference, desired []metav1ac.OwnerReferenceApplyConfiguration) bool {
	if len(desired) == 0 {
		return true
	}
	for _, d := range desired {
		if d.UID == nil {
			return false // cannot match without UID
		}
		found := false
		for _, e := range existing {
			if e.UID != *d.UID {
				continue
			}
			// UID matches — verify the other fields if specified.
			if d.APIVersion != nil && e.APIVersion != *d.APIVersion {
				return false
			}
			if d.Kind != nil && e.Kind != *d.Kind {
				return false
			}
			if d.Name != nil && e.Name != *d.Name {
				return false
			}
			if d.Controller != nil {
				if e.Controller == nil || *e.Controller != *d.Controller {
					return false
				}
			}
			if d.BlockOwnerDeletion != nil {
				if e.BlockOwnerDeletion == nil || *e.BlockOwnerDeletion != *d.BlockOwnerDeletion {
					return false
				}
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

// roleRefMatches compares a RoleRef to its ApplyConfiguration.
func roleRefMatches(existing *rbacv1.RoleRef, desired *rbacv1ac.RoleRefApplyConfiguration) bool {
	if desired == nil {
		return true
	}
	if desired.APIGroup != nil && existing.APIGroup != *desired.APIGroup {
		return false
	}
	if desired.Kind != nil && existing.Kind != *desired.Kind {
		return false
	}
	if desired.Name != nil && existing.Name != *desired.Name {
		return false
	}
	return true
}

// subjectsMatch compares a list of Subjects with their ApplyConfigurations.
func subjectsMatch(existing []rbacv1.Subject, desired []rbacv1ac.SubjectApplyConfiguration) bool {
	if len(existing) != len(desired) {
		return false
	}

	// Build a comparable key for each subject to handle ordering differences.
	existingKeys := make([]string, len(existing))
	for i, s := range existing {
		existingKeys[i] = subjectKey(s.Kind, s.APIGroup, s.Name, s.Namespace)
	}

	desiredKeys := make([]string, len(desired))
	for i := range desired {
		d := &desired[i]
		desiredKeys[i] = subjectACKey(d)
	}

	slices.Sort(existingKeys)
	slices.Sort(desiredKeys)
	return slices.Equal(existingKeys, desiredKeys)
}

func subjectKey(kind, apiGroup, name, namespace string) string {
	return kind + "/" + apiGroup + "/" + name + "/" + namespace
}

func subjectACKey(s *rbacv1ac.SubjectApplyConfiguration) string {
	var kind, apiGroup, name, ns string
	if s.Kind != nil {
		kind = *s.Kind
	}
	if s.APIGroup != nil {
		apiGroup = *s.APIGroup
	}
	if s.Name != nil {
		name = *s.Name
	}
	if s.Namespace != nil {
		ns = *s.Namespace
	}
	return kind + "/" + apiGroup + "/" + name + "/" + ns
}

// policyRulesMatch compares existing policy rules with desired ones from ApplyConfigurations.
func policyRulesMatch(existing []rbacv1.PolicyRule, desired []rbacv1ac.PolicyRuleApplyConfiguration) bool {
	if len(existing) != len(desired) {
		return false
	}

	// Build comparable keys for ordering-insensitive comparison.
	existingKeys := make([]string, len(existing))
	for i, r := range existing {
		existingKeys[i] = policyRuleKey(&r)
	}

	desiredKeys := make([]string, len(desired))
	for i := range desired {
		desiredKeys[i] = policyRuleACKey(&desired[i])
	}

	slices.Sort(existingKeys)
	slices.Sort(desiredKeys)
	return slices.Equal(existingKeys, desiredKeys)
}

func policyRuleKey(r *rbacv1.PolicyRule) string {
	// Normalize by sorting each slice before joining.
	verbs := slices.Clone(r.Verbs)
	slices.Sort(verbs)
	apiGroups := slices.Clone(r.APIGroups)
	slices.Sort(apiGroups)
	resources := slices.Clone(r.Resources)
	slices.Sort(resources)
	resourceNames := slices.Clone(r.ResourceNames)
	slices.Sort(resourceNames)
	nonResourceURLs := slices.Clone(r.NonResourceURLs)
	slices.Sort(nonResourceURLs)

	return strings.Join(verbs, ",") + "|" +
		strings.Join(apiGroups, ",") + "|" +
		strings.Join(resources, ",") + "|" +
		strings.Join(resourceNames, ",") + "|" +
		strings.Join(nonResourceURLs, ",")
}

func policyRuleACKey(r *rbacv1ac.PolicyRuleApplyConfiguration) string {
	verbs := slices.Clone(r.Verbs)
	slices.Sort(verbs)
	apiGroups := slices.Clone(r.APIGroups)
	slices.Sort(apiGroups)
	resources := slices.Clone(r.Resources)
	slices.Sort(resources)
	resourceNames := slices.Clone(r.ResourceNames)
	slices.Sort(resourceNames)
	nonResourceURLs := slices.Clone(r.NonResourceURLs)
	slices.Sort(nonResourceURLs)

	return strings.Join(verbs, ",") + "|" +
		strings.Join(apiGroups, ",") + "|" +
		strings.Join(resources, ",") + "|" +
		strings.Join(resourceNames, ",") + "|" +
		strings.Join(nonResourceURLs, ",")
}

// aggregationRuleMatches compares an existing AggregationRule with the desired
// ApplyConfiguration.  It only compares the clusterRoleSelectors — the .rules
// field of aggregating ClusterRoles is managed by the Kubernetes RBAC aggregation
// controller, not by the auth-operator.
func aggregationRuleMatches(existing *rbacv1.AggregationRule, desired *rbacv1ac.AggregationRuleApplyConfiguration) bool {
	if desired == nil {
		return existing == nil
	}
	if existing == nil {
		return false
	}

	if len(existing.ClusterRoleSelectors) != len(desired.ClusterRoleSelectors) {
		return false
	}

	// Build comparable keys for ordering-insensitive comparison.
	existingKeys := make([]string, len(existing.ClusterRoleSelectors))
	for i := range existing.ClusterRoleSelectors {
		existingKeys[i] = labelSelectorKey(&existing.ClusterRoleSelectors[i])
	}

	desiredKeys := make([]string, len(desired.ClusterRoleSelectors))
	for i := range desired.ClusterRoleSelectors {
		desiredKeys[i] = labelSelectorACKey(&desired.ClusterRoleSelectors[i])
	}

	slices.Sort(existingKeys)
	slices.Sort(desiredKeys)
	return slices.Equal(existingKeys, desiredKeys)
}

// labelSelectorKey produces a comparable string from a metav1.LabelSelector.
func labelSelectorKey(sel *metav1.LabelSelector) string {
	// Collect matchLabels as sorted key=value pairs.
	labels := make([]string, 0, len(sel.MatchLabels))
	for k, v := range sel.MatchLabels {
		labels = append(labels, k+"="+v)
	}
	slices.Sort(labels)

	// Collect matchExpressions.
	exprs := make([]string, 0, len(sel.MatchExpressions))
	for _, expr := range sel.MatchExpressions {
		vals := slices.Clone(expr.Values)
		slices.Sort(vals)
		exprs = append(exprs, expr.Key+string(expr.Operator)+strings.Join(vals, ","))
	}
	slices.Sort(exprs)

	return strings.Join(labels, ";") + "|" + strings.Join(exprs, ";")
}

// labelSelectorACKey produces a comparable string from a LabelSelectorApplyConfiguration.
func labelSelectorACKey(sel *metav1ac.LabelSelectorApplyConfiguration) string {
	labels := make([]string, 0, len(sel.MatchLabels))
	for k, v := range sel.MatchLabels {
		labels = append(labels, k+"="+v)
	}
	slices.Sort(labels)

	exprs := make([]string, 0, len(sel.MatchExpressions))
	for _, expr := range sel.MatchExpressions {
		var op string
		if expr.Operator != nil {
			op = string(*expr.Operator)
		}
		var key string
		if expr.Key != nil {
			key = *expr.Key
		}
		vals := slices.Clone(expr.Values)
		slices.Sort(vals)
		exprs = append(exprs, key+op+strings.Join(vals, ","))
	}
	slices.Sort(exprs)

	return strings.Join(labels, ";") + "|" + strings.Join(exprs, ";")
}
