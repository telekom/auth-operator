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
//
// The exported PatchApply* functions are thin wrappers over the generic
// Applier configured with the RBAC and ServiceAccount descriptors below.
package ssa

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	libraryssa "github.com/telekom/t-caas-go-library/pkg/ssa"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PatchApplyResult is the outcome of a cache-aware apply.
type PatchApplyResult = libraryssa.PatchApplyResult

const (
	// PatchApplyResultSkipped means no apply was needed.
	PatchApplyResultSkipped = libraryssa.PatchApplyResultSkipped
	// PatchApplyResultCreated means the preflight object was missing.
	PatchApplyResultCreated = libraryssa.PatchApplyResultCreated
	// PatchApplyResultPatched means a write request (apply or label cleanup) was
	// sent for a preflight cache hit, not necessarily a persisted mutation.
	PatchApplyResultPatched = libraryssa.PatchApplyResultPatched
)

var (
	clusterRoleApplier = libraryssa.Applier[*rbacv1.ClusterRole, *rbacv1ac.ClusterRoleApplyConfiguration]{
		Kind:            "ClusterRole",
		New:             func() *rbacv1.ClusterRole { return &rbacv1.ClusterRole{} },
		Matches:         clusterRoleMatches,
		Extract:         rbacv1ac.ExtractClusterRole,
		NormalizeFields: normalizeRBACApplyFields,
	}
	roleApplier = libraryssa.Applier[*rbacv1.Role, *rbacv1ac.RoleApplyConfiguration]{
		Kind:            "Role",
		Namespaced:      true,
		New:             func() *rbacv1.Role { return &rbacv1.Role{} },
		Matches:         roleMatches,
		Extract:         rbacv1ac.ExtractRole,
		NormalizeFields: normalizeRBACApplyFields,
	}
	clusterRoleBindingApplier = libraryssa.Applier[*rbacv1.ClusterRoleBinding, *rbacv1ac.ClusterRoleBindingApplyConfiguration]{
		Kind:            "ClusterRoleBinding",
		New:             func() *rbacv1.ClusterRoleBinding { return &rbacv1.ClusterRoleBinding{} },
		Matches:         clusterRoleBindingMatches,
		Extract:         rbacv1ac.ExtractClusterRoleBinding,
		NormalizeFields: normalizeRBACApplyFields,
	}
	roleBindingApplier = libraryssa.Applier[*rbacv1.RoleBinding, *rbacv1ac.RoleBindingApplyConfiguration]{
		Kind:            "RoleBinding",
		Namespaced:      true,
		New:             func() *rbacv1.RoleBinding { return &rbacv1.RoleBinding{} },
		Matches:         roleBindingMatches,
		Extract:         rbacv1ac.ExtractRoleBinding,
		NormalizeFields: normalizeRBACApplyFields,
	}
	serviceAccountApplier = libraryssa.Applier[*corev1.ServiceAccount, *corev1ac.ServiceAccountApplyConfiguration]{
		Kind:       "ServiceAccount",
		Namespaced: true,
		New:        func() *corev1.ServiceAccount { return &corev1.ServiceAccount{} },
		Matches:    serviceAccountMatches,
		Extract:    corev1ac.ExtractServiceAccount,
	}
)

func withFieldOwner(opts []client.ApplyOption) []client.ApplyOption {
	return append([]client.ApplyOption{client.FieldOwner(FieldOwner)}, opts...)
}

// normalizeRBACApplyFields canonicalizes RBAC lists the API server treats as
// unordered so managed-field comparisons are order-insensitive.
func normalizeRBACApplyFields(fields map[string]any) {
	if subjects, ok := fields["subjects"].([]any); ok {
		for _, subject := range subjects {
			subjectFields, ok := subject.(map[string]any)
			if !ok {
				continue
			}
			// The API server omits empty optional strings, so "" and absent
			// are the same stored value.
			for _, key := range []string{"apiGroup", "namespace"} {
				if value, ok := subjectFields[key].(string); ok && value == "" {
					delete(subjectFields, key)
				}
			}
			kind, _ := subjectFields["kind"].(string)
			if _, ok := subjectFields["apiGroup"]; !ok && (kind == rbacv1.UserKind || kind == rbacv1.GroupKind) {
				subjectFields["apiGroup"] = rbacv1.GroupName
			}
		}
		_ = sortByJSON(subjects)
	}
	if rules, ok := fields["rules"].([]any); ok {
		for _, rule := range rules {
			if value, ok := rule.(map[string]any); ok {
				for _, key := range []string{"verbs", "apiGroups", "resources", "resourceNames", "nonResourceURLs"} {
					if entries, ok := value[key].([]any); ok {
						_ = sortByJSON(entries)
					}
				}
			}
		}
		_ = sortByJSON(rules)
	}
}

// normalizeBindingApplyConfiguration canonicalizes binding subjects and owner
// references. RBAC subjects are an atomic SSA list, so the whole list is sorted
// without changing its ownership granularity.
func normalizeBindingApplyConfiguration(
	subjects []rbacv1ac.SubjectApplyConfiguration,
	metadata *metav1ac.ObjectMetaApplyConfiguration,
) error {
	for i := range subjects {
		subject := &subjects[i]
		if subject.Kind != nil && (*subject.Kind == rbacv1.UserKind || *subject.Kind == rbacv1.GroupKind) &&
			(subject.APIGroup == nil || *subject.APIGroup == "") {
			subject.WithAPIGroup(rbacv1.GroupName)
		}
	}
	if err := sortByJSON(subjects); err != nil {
		return fmt.Errorf("sort binding subjects: %w", err)
	}
	if metadata != nil {
		if err := sortByJSON(metadata.OwnerReferences); err != nil {
			return fmt.Errorf("sort binding owner references: %w", err)
		}
	}
	return nil
}

// PatchApplyClusterRole reads the current ClusterRole from cache, compares it to
// the desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// Returns the result (skipped/created/patched) and any error.
// opts are forwarded to every c.Apply call (e.g. client.ForceOwnership).
func PatchApplyClusterRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRole(ctx, c, ac, nil, false, opts...)
}

// PatchApplyClusterRoleAlways behaves like PatchApplyClusterRole but sends the
// SSA apply even when the live object already matches. Use this when the apply
// identity is itself an authorization boundary and must be rechecked.
func PatchApplyClusterRoleAlways(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRole(ctx, c, ac, nil, true, opts...)
}

// PatchApplyClusterRolePruningLabels behaves like PatchApplyClusterRole, but it
// forces an apply when the live ClusterRole still has a label that should be
// pruned from the desired state. This covers upgrade cleanup for labels that an
// older auth-operator version owned via SSA and no longer declares.
func PatchApplyClusterRolePruningLabels(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
	shouldPruneLabel func(string) bool,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRole(ctx, c, ac, shouldPruneLabel, false, opts...)
}

// PatchApplyClusterRolePruningLabelsAlways combines protected-label pruning
// with an unconditional SSA apply for continuous authorization checks.
func PatchApplyClusterRolePruningLabelsAlways(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
	shouldPruneLabel func(string) bool,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRole(ctx, c, ac, shouldPruneLabel, true, opts...)
}

// PatchApplyRole reads the current Role from cache, compares it to the desired
// ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// opts are forwarded to every c.Apply call (e.g. client.ForceOwnership).
func PatchApplyRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	if ac == nil || ac.Name == nil {
		return roleApplier.PatchApply(ctx, c, ac, false, withFieldOwner(opts)...)
	}
	return patchApplyRoleWithLegacySkip(ctx, c, roleApplier, ac, false, ac.UID != nil || ac.ResourceVersion != nil, withFieldOwner(opts)...)
}

// PatchApplyRoleAlways behaves like PatchApplyRole but sends the SSA apply
// even when the live object already matches.
func PatchApplyRoleAlways(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return roleApplier.PatchApply(ctx, c, ac, true, withFieldOwner(opts)...)
}

// PatchApplyClusterRoleBinding reads the current CRB from cache, compares it to
// the desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// opts are forwarded to every c.Apply call (e.g. client.ForceOwnership).
func PatchApplyClusterRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleBindingApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRoleBinding(ctx, c, ac, false, opts...)
}

// PatchApplyClusterRoleBindingAlways behaves like PatchApplyClusterRoleBinding
// but sends the SSA apply even when the live object already matches.
func PatchApplyClusterRoleBindingAlways(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleBindingApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyClusterRoleBinding(ctx, c, ac, true, opts...)
}

// PatchApplyRoleBinding reads the current RB from cache, compares it to the
// desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// opts are forwarded to every c.Apply call (e.g. client.ForceOwnership).
func PatchApplyRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleBindingApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyRoleBinding(ctx, c, ac, false, opts...)
}

// PatchApplyRoleBindingAlways behaves like PatchApplyRoleBinding but sends the
// SSA apply even when the live object already matches.
func PatchApplyRoleBindingAlways(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleBindingApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return patchApplyRoleBinding(ctx, c, ac, true, opts...)
}

// PatchApplyServiceAccount reads the current SA from cache, compares it to the
// desired ApplyConfiguration, and only sends an SSA Patch if there is a diff.
// Existing ServiceAccounts are patched without ForceOwnership so two
// BindDefinitions that share an SA cannot silently take over sensitive fields
// such as automountServiceAccountToken from each other.
func PatchApplyServiceAccount(
	ctx context.Context,
	c client.Client,
	ac *corev1ac.ServiceAccountApplyConfiguration,
	fieldOwner string,
) (PatchApplyResult, error) {
	if ac != nil && ac.Name != nil && (ac.UID != nil || ac.ResourceVersion != nil) {
		// Preserve the characterized no-op precondition gap; real writes must
		// still send the caller's original preconditions to the API server.
		comparison, err := cloneApplyConfiguration(ac)
		if err != nil {
			return 0, err
		}
		comparison.UID, comparison.ResourceVersion = nil, nil
		return patchApplyServiceAccount(ctx, &serviceAccountApplyClient{Client: c, desired: ac}, comparison, false, fieldOwner)
	}
	return patchApplyServiceAccount(ctx, c, ac, false, fieldOwner)
}

// PatchApplyServiceAccountAlways behaves like PatchApplyServiceAccount but
// sends the SSA apply even when the live object already matches.
func PatchApplyServiceAccountAlways(
	ctx context.Context,
	c client.Client,
	ac *corev1ac.ServiceAccountApplyConfiguration,
	fieldOwner string,
) (PatchApplyResult, error) {
	return patchApplyServiceAccount(ctx, c, ac, true, fieldOwner)
}

func patchApplyRoleWithLegacySkip[T client.Object, AC libraryssa.ApplyConfiguration](
	ctx context.Context, c client.Client, applier libraryssa.Applier[T, AC], ac AC,
	always, preconditions bool, opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	options := (&client.ApplyOptions{}).ApplyOptions(opts)
	force := options.Force != nil && *options.Force
	// Ordinary roles historically skip equal unforced requests, including
	// dry-runs and owned-field omissions. Keep that AO policy outside the library.
	if !always && !preconditions && !force && *ac.GetName() != "" &&
		(!applier.Namespaced || (ac.GetNamespace() != nil && *ac.GetNamespace() != "")) {
		key := client.ObjectKey{Name: *ac.GetName()}
		if applier.Namespaced {
			key.Namespace = *ac.GetNamespace()
		}
		existing := applier.New()
		err := c.Get(ctx, key, existing)
		if err == nil && applier.Matches(existing, ac) {
			return PatchApplyResultSkipped, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return 0, fmt.Errorf("get %s %s: %w", applier.Kind, key, err)
		}
	}
	return applier.PatchApply(ctx, c, ac, always, opts...)
}

func patchApplyClusterRole(
	ctx context.Context, c client.Client, ac *rbacv1ac.ClusterRoleApplyConfiguration,
	shouldPrune func(string) bool, always bool, opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	applyOpts := withFieldOwner(opts)
	options := (&client.ApplyOptions{}).ApplyOptions(applyOpts)
	if ac == nil || ac.Name == nil {
		return clusterRoleApplier.PatchApply(ctx, c, ac, always, applyOpts...)
	}
	pruned := false
	if shouldPrune != nil && *ac.Name != "" {
		existing := &rbacv1.ClusterRole{}
		getErr := c.Get(ctx, client.ObjectKey{Name: *ac.Name}, existing)
		if getErr != nil && !apierrors.IsNotFound(getErr) {
			return 0, fmt.Errorf("get ClusterRole %s: %w", *ac.Name, getErr)
		}
		if getErr == nil {
			var err error
			pruned, err = pruneClusterRoleLabels(
				ctx, c, existing, ac.Labels, shouldPrune,
				&client.PatchOptions{DryRun: options.DryRun},
			)
			if err != nil {
				return 0, err
			}
			if pruned && !always && (options.Force == nil || !*options.Force) && clusterRoleMatches(existing, ac) {
				result, err := clusterRoleApplier.PatchApply(ctx, c, ac, false, applyOpts...)
				if result == PatchApplyResultSkipped {
					return PatchApplyResultPatched, err
				}
				return result, err
			}
		}
	}
	result, err := patchApplyRoleWithLegacySkip(ctx, c, clusterRoleApplier, ac, always || pruned,
		ac.UID != nil || ac.ResourceVersion != nil, applyOpts...)
	if pruned && apierrors.IsConflict(err) {
		return patchApplyClusterRoleAfterPruneConflict(ctx, c, ac, applyOpts...)
	}
	return result, err
}

func patchApplyClusterRoleAfterPruneConflict(
	ctx context.Context, c client.Client, ac *rbacv1ac.ClusterRoleApplyConfiguration,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error { return c.Apply(ctx, ac, opts...) })
	if err == nil {
		return PatchApplyResultPatched, nil
	}
	return 0, fmt.Errorf("patch ClusterRole %s: %w", *ac.Name, err)
}

func patchApplyClusterRoleBinding(
	ctx context.Context, c client.Client, ac *rbacv1ac.ClusterRoleBindingApplyConfiguration,
	always bool, opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return clusterRoleBindingApplier.PatchApply(ctx, &bindingApplyClient{Client: c}, ac, always, withFieldOwner(opts)...)
}

func patchApplyRoleBinding(
	ctx context.Context, c client.Client, ac *rbacv1ac.RoleBindingApplyConfiguration,
	always bool, opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	return roleBindingApplier.PatchApply(ctx, &bindingApplyClient{Client: c}, ac, always, withFieldOwner(opts)...)
}

type bindingApplyClient struct {
	client.Client
}

// Apply clones and canonicalizes binding lists only after the preflight requires a write.
func (c *bindingApplyClient) Apply(ctx context.Context, ac runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	switch desired := ac.(type) {
	case *rbacv1ac.ClusterRoleBindingApplyConfiguration:
		clone, err := cloneApplyConfiguration(desired)
		if err != nil {
			return err
		}
		if err := normalizeBindingApplyConfiguration(clone.Subjects, clone.ObjectMetaApplyConfiguration); err != nil {
			return err
		}
		return c.Client.Apply(ctx, clone, opts...)
	case *rbacv1ac.RoleBindingApplyConfiguration:
		clone, err := cloneApplyConfiguration(desired)
		if err != nil {
			return err
		}
		if err := normalizeBindingApplyConfiguration(clone.Subjects, clone.ObjectMetaApplyConfiguration); err != nil {
			return err
		}
		return c.Client.Apply(ctx, clone, opts...)
	default:
		return c.Client.Apply(ctx, ac, opts...)
	}
}

type serviceAccountApplyClient struct {
	client.Client
	desired *corev1ac.ServiceAccountApplyConfiguration
}

// Apply sends the original preconditions, not the comparison clone.
func (c *serviceAccountApplyClient) Apply(ctx context.Context, _ runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	return c.Client.Apply(ctx, c.desired, opts...)
}

func patchApplyServiceAccount(
	ctx context.Context, c client.Client, ac *corev1ac.ServiceAccountApplyConfiguration, always bool, fieldOwner string,
) (PatchApplyResult, error) {
	result, err := serviceAccountApplier.PatchApply(ctx, c, ac, always, client.FieldOwner(fieldOwner))
	if apierrors.IsConflict(err) && strings.HasPrefix(err.Error(), "create ServiceAccount ") {
		return 0, fmt.Errorf("create ServiceAccount %s/%s conflicted after preflight: %w", *ac.Namespace, *ac.Name, err)
	}
	return result, err
}

func pruneClusterRoleLabels(
	ctx context.Context, c client.Client, existing *rbacv1.ClusterRole, desired map[string]string, shouldPrune func(string) bool,
	patchOpts ...client.PatchOption,
) (bool, error) {
	original := existing.DeepCopy()
	for key := range existing.Labels {
		if _, declared := desired[key]; !declared && shouldPrune(key) {
			delete(existing.Labels, key)
		}
	}
	if len(original.Labels) == len(existing.Labels) {
		return false, nil
	}
	if len(existing.Labels) == 0 {
		existing.Labels = nil
	}
	if err := c.Patch(ctx, existing, client.MergeFrom(original), patchOpts...); err != nil {
		return false, fmt.Errorf("prune ClusterRole %s labels: %w", existing.Name, err)
	}
	return true, nil
}

func sortByJSON[T any](items []T) error {
	type keyedItem struct {
		key   string
		value T
	}
	keyed := make([]keyedItem, len(items))
	for i, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("marshal ApplyConfiguration list item: %w", err)
		}
		keyed[i] = keyedItem{key: string(encoded), value: item}
	}
	slices.SortFunc(keyed, func(a, b keyedItem) int { return strings.Compare(a.key, b.key) })
	for i := range keyed {
		items[i] = keyed[i].value
	}
	return nil
}

func cloneApplyConfiguration[T any](ac *T) (*T, error) {
	data, err := json.Marshal(ac)
	if err != nil {
		return nil, fmt.Errorf("marshal ApplyConfiguration: %w", err)
	}
	clone := new(T)
	if err := json.Unmarshal(data, clone); err != nil {
		return nil, fmt.Errorf("unmarshal ApplyConfiguration: %w", err)
	}
	return clone, nil
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
	if apiGroup == "" && (kind == rbacv1.UserKind || kind == rbacv1.GroupKind) {
		apiGroup = rbacv1.GroupName
	}
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
	return subjectKey(kind, apiGroup, name, ns)
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
