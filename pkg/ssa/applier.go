// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
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

// ApplyConfiguration is a typed SSA apply configuration that exposes its
// object identity. All client-go and applyconfiguration-gen generated
// top-level apply configurations satisfy it.
type ApplyConfiguration interface {
	runtime.ApplyConfiguration
	GetName() *string
	GetNamespace() *string
}

// OwnershipPolicy decides whether the apply field manager's current managed
// fields allow skipping an apply whose desired values already match the live
// object.
type OwnershipPolicy int

const (
	// OwnershipExactOrSubset checks ownership for every apply. Forced applies
	// skip only when the field manager owns exactly the desired fields (so a
	// forced apply never misses reclaiming a field). Unforced applies skip
	// unless the field manager still owns a field that SSA must prune.
	// This is the zero value and the safe default.
	OwnershipExactOrSubset OwnershipPolicy = iota
	// OwnershipExactWhenForced checks ownership only for forced applies, which
	// skip only when the field manager owns exactly the desired fields.
	// Unforced applies skip on value equality alone.
	OwnershipExactWhenForced
)

// Applier describes how to skip-if-unchanged Server-Side Apply one object
// type. It reads the live object (typically from the informer cache), and
// only sends an SSA apply when the desired values differ or when the field
// manager's ownership must change (reclaim or prune).
//
// Only Kind, New, Matches and Extract are required; the remaining fields are
// optional hooks. Applier is a plain value: copy it to vary per-call hooks
// such as ShouldPruneLabel.
type Applier[T client.Object, AC ApplyConfiguration] struct {
	// Kind is used in errors and logs, e.g. "ClusterRole".
	Kind string
	// Namespaced requires a namespace on the desired apply configuration.
	Namespaced bool
	// New returns an empty object to read the live state into.
	New func() T
	// Matches reports whether existing already has every desired value.
	Matches func(existing T, desired AC) bool
	// Extract returns the fields owned by fieldManager, e.g. rbacv1ac.ExtractRole.
	Extract func(existing T, fieldManager string) (AC, error)
	// Ownership selects how managed fields are compared before skipping.
	Ownership OwnershipPolicy
	// NormalizeFields canonicalizes the JSON form of owned and desired fields
	// before comparison, e.g. sorting lists the API server treats as sets.
	// Server-populated metadata and owner reference order are always ignored.
	NormalizeFields func(fields map[string]any)
	// PrepareApply returns the apply configuration actually sent to the API
	// server. Matches, Extract and label pruning see the unprepared
	// configuration, so PrepareApply may only canonicalize it (e.g. sort lists
	// or fill API defaults) without changing its semantics. It must not mutate
	// its argument.
	PrepareApply func(desired AC) (AC, error)
	// RequeueOnCreateConflict reports a conflict while creating a missing
	// object as a dedicated "conflicted after preflight" error, so callers
	// requeue and re-classify ownership on fresh state.
	RequeueOnCreateConflict bool
	// ShouldPruneLabel, if set, removes live labels for which it returns true
	// and that are not declared in Labels(desired) via a JSON merge patch
	// before the apply decision. Use it for labels SSA can no longer prune
	// (e.g. owned by a previous field manager).
	ShouldPruneLabel func(key string) bool
	// Labels returns the desired labels. Required when ShouldPruneLabel is set.
	Labels func(desired AC) map[string]string
}

// PatchApply reads the live object and applies ac via SSA only when needed.
// opts are forwarded to every apply and must include a client.FieldOwner.
// When alwaysApply is true the apply is sent even when the live object
// already matches, e.g. when the apply identity is itself an authorization
// boundary that the API server must recheck.
//
// Dry-run applies that need an ownership check and applies whose ac carries
// UID/resourceVersion preconditions are never skipped. Pass a fresh ac on
// every call: client.Apply writes the server response, including
// resourceVersion and uid, back into it.
func (a Applier[T, AC]) PatchApply(
	ctx context.Context,
	c client.Client,
	ac AC,
	alwaysApply bool,
	opts ...client.ApplyOption,
) (PatchApplyResult, error) {
	target, options, err := a.target(ac, opts)
	if err != nil {
		return 0, err
	}

	existing := a.New()
	if err := c.Get(ctx, target.key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return 0, fmt.Errorf("get %s %s: %w", a.Kind, target.ref, err)
		}
		return a.create(ctx, c, ac, target, opts)
	}

	prunedLabels, err := a.pruneLabels(ctx, c, existing, ac, target.ref, options.DryRun)
	if err != nil {
		return 0, err
	}

	force := options.Force != nil && *options.Force
	// Forced applies after a label prune are always sent so they reclaim
	// ownership on the freshly patched object.
	if !alwaysApply && (!prunedLabels || !force) && a.Matches(existing, ac) &&
		a.canSkip(existing, ac, options, force) {
		if prunedLabels {
			// The label merge patch already converged an apply that would
			// otherwise have been skipped.
			return PatchApplyResultPatched, nil
		}
		log.FromContext(ctx).V(3).Info(a.Kind+" unchanged, skipping SSA apply", target.logKV...)
		return PatchApplyResultSkipped, nil
	}

	if applyErr := a.apply(ctx, c, ac, opts); applyErr != nil {
		if prunedLabels && apierrors.IsConflict(applyErr) {
			converged, retryErr := a.applyAfterPruneConflict(ctx, c, ac, target.key, opts)
			if converged {
				return PatchApplyResultPatched, nil
			}
			if retryErr != nil {
				applyErr = retryErr
			}
		}
		return 0, fmt.Errorf("patch %s %s: %w", a.Kind, target.ref, applyErr)
	}
	return PatchApplyResultPatched, nil
}

// applyTarget identifies the object an apply configuration targets.
type applyTarget struct {
	key   types.NamespacedName
	ref   string // "name" or "namespace/name" for errors
	logKV []any
}

func (a Applier[T, AC]) target(ac AC, opts []client.ApplyOption) (applyTarget, *client.ApplyOptions, error) {
	kind := lowerCamel(a.Kind)
	if isNil(ac) || ac.GetName() == nil {
		return applyTarget{}, nil, fmt.Errorf("%s ApplyConfiguration must have a name", kind)
	}
	target := applyTarget{key: types.NamespacedName{Name: *ac.GetName()}}
	if target.key.Name == "" {
		return applyTarget{}, nil, fmt.Errorf("%s ApplyConfiguration name must not be empty", kind)
	}
	target.ref = target.key.Name
	target.logKV = []any{kind, target.key.Name}
	if a.Namespaced {
		if ac.GetNamespace() == nil || *ac.GetNamespace() == "" {
			return applyTarget{}, nil, fmt.Errorf("%s ApplyConfiguration must have a namespace", kind)
		}
		target.key.Namespace = *ac.GetNamespace()
		target.ref = target.key.Namespace + "/" + target.key.Name
		target.logKV = append(target.logKV, "namespace", target.key.Namespace)
	}
	options := (&client.ApplyOptions{}).ApplyOptions(opts)
	if strings.TrimSpace(options.FieldManager) == "" {
		return applyTarget{}, nil, fmt.Errorf("fieldOwner must not be empty")
	}
	return target, options, nil
}

func (a Applier[T, AC]) create(
	ctx context.Context,
	c client.Client,
	ac AC,
	target applyTarget,
	opts []client.ApplyOption,
) (PatchApplyResult, error) {
	if err := a.apply(ctx, c, ac, opts); err != nil {
		if a.RequeueOnCreateConflict && apierrors.IsConflict(err) {
			log.FromContext(ctx).V(2).Info(
				a.Kind+" appeared during create apply; requeue required for fresh ownership classification",
				target.logKV...)
			return 0, fmt.Errorf("create %s %s conflicted after preflight: %w", a.Kind, target.ref, err)
		}
		return 0, fmt.Errorf("create %s %s: %w", a.Kind, target.ref, err)
	}
	return PatchApplyResultCreated, nil
}

func (a Applier[T, AC]) apply(ctx context.Context, c client.Client, ac AC, opts []client.ApplyOption) error {
	if a.PrepareApply != nil {
		prepared, err := a.PrepareApply(ac)
		if err != nil {
			return err
		}
		ac = prepared
	}
	return c.Apply(ctx, ac, opts...)
}

func (a Applier[T, AC]) canSkip(existing T, ac AC, options *client.ApplyOptions, force bool) bool {
	if hasApplyPreconditions(ac) {
		return false
	}
	if a.Ownership == OwnershipExactWhenForced && !force {
		return true
	}
	if len(options.DryRun) != 0 {
		return false
	}
	owned, err := a.Extract(existing, options.FieldManager)
	if err != nil {
		return false
	}
	ownedFields, desiredFields, ok := applyFieldMaps(owned, ac, a.NormalizeFields)
	if !ok {
		return false
	}
	if force {
		return reflect.DeepEqual(ownedFields, desiredFields)
	}
	return applyFieldMapSubset(ownedFields, desiredFields)
}

func (a Applier[T, AC]) pruneLabels(
	ctx context.Context,
	c client.Client,
	existing T,
	ac AC,
	ref string,
	dryRun []string,
) (bool, error) {
	if a.ShouldPruneLabel == nil || len(existing.GetLabels()) == 0 {
		return false, nil
	}
	if a.Labels == nil {
		return false, fmt.Errorf("prune %s %s labels: Applier.Labels must be set with ShouldPruneLabel", a.Kind, ref)
	}
	desired := a.Labels(ac)
	if !a.hasPrunableLabel(existing.GetLabels(), desired) {
		return false, nil
	}

	orig, ok := existing.DeepCopyObject().(client.Object)
	if !ok {
		return false, fmt.Errorf("prune %s %s labels: deep copy is not a client.Object", a.Kind, ref)
	}
	labels := make(map[string]string, len(existing.GetLabels()))
	for key, value := range existing.GetLabels() {
		if _, stillDesired := desired[key]; stillDesired || !a.ShouldPruneLabel(key) {
			labels[key] = value
		}
	}
	if len(labels) == 0 {
		labels = nil
	}
	existing.SetLabels(labels)
	if err := c.Patch(ctx, existing, client.MergeFrom(orig), &client.PatchOptions{DryRun: dryRun}); err != nil {
		return false, fmt.Errorf("prune %s %s labels: %w", a.Kind, ref, err)
	}
	return true, nil
}

func (a Applier[T, AC]) hasPrunableLabel(labels, desired map[string]string) bool {
	if a.ShouldPruneLabel == nil {
		return false
	}
	for key := range labels {
		if _, stillDesired := desired[key]; stillDesired {
			continue
		}
		if a.ShouldPruneLabel(key) {
			return true
		}
	}
	return false
}

// applyAfterPruneConflict retries an apply that conflicted with the label
// merge patch, and treats the object as converged when a concurrent writer
// already produced the desired state.
func (a Applier[T, AC]) applyAfterPruneConflict(
	ctx context.Context,
	c client.Client,
	ac AC,
	key types.NamespacedName,
	opts []client.ApplyOption,
) (bool, error) {
	applyErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return a.apply(ctx, c, ac, opts)
	})
	if applyErr == nil {
		return true, nil
	}
	latest := a.New()
	if getErr := c.Get(ctx, key, latest); getErr == nil &&
		a.Matches(latest, ac) &&
		!a.hasPrunableLabel(latest.GetLabels(), a.Labels(ac)) {
		return true, nil
	}
	return false, applyErr
}

// ManagedBy reports whether obj has a managedFields entry for manager with
// the given operation, e.g. metav1.ManagedFieldsOperationApply.
func ManagedBy(obj metav1.Object, manager string, operation metav1.ManagedFieldsOperationType) bool {
	return slices.ContainsFunc(obj.GetManagedFields(), func(entry metav1.ManagedFieldsEntry) bool {
		return entry.Manager == manager && entry.Operation == operation
	})
}

func hasApplyPreconditions(ac any) bool {
	data, err := json.Marshal(ac)
	if err != nil {
		return true
	}
	var object struct {
		Metadata *struct {
			UID             *string `json:"uid"`
			ResourceVersion *string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return true
	}
	return object.Metadata != nil && (object.Metadata.UID != nil || object.Metadata.ResourceVersion != nil)
}

func applyFieldMaps(owned, desired any, normalize func(map[string]any)) (ownedFields, desiredFields map[string]any, ok bool) {
	ownedJSON, err := json.Marshal(owned)
	if err != nil {
		return nil, nil, false
	}
	desiredJSON, err := json.Marshal(desired)
	if err != nil {
		return nil, nil, false
	}
	if json.Unmarshal(ownedJSON, &ownedFields) != nil || json.Unmarshal(desiredJSON, &desiredFields) != nil {
		return nil, nil, false
	}
	for _, fields := range []map[string]any{ownedFields, desiredFields} {
		normalizeMetadataFields(fields)
		if normalize != nil {
			normalize(fields)
		}
	}
	return ownedFields, desiredFields, true
}

func normalizeMetadataFields(fields map[string]any) {
	metadata, ok := fields["metadata"].(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"uid", "resourceVersion", "creationTimestamp", "generation", "managedFields"} {
		delete(metadata, key)
	}
	// ownerReferences is an SSA map-list keyed by uid, so order is irrelevant.
	if refs, ok := metadata["ownerReferences"].([]any); ok {
		_ = sortByJSON(refs)
	}
}

func applyFieldMapSubset(owned, desired map[string]any) bool {
	for key, value := range owned {
		target, ok := desired[key]
		if !ok {
			return false
		}
		if nested, ok := value.(map[string]any); ok {
			targetNested, ok := target.(map[string]any)
			if !ok || !applyFieldMapSubset(nested, targetNested) {
				return false
			}
		} else if !reflect.DeepEqual(value, target) {
			return false
		}
	}
	return true
}

// sortByJSON sorts items in place by their JSON encoding. It leaves the list
// untouched when any item cannot be encoded.
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
	slices.SortFunc(keyed, func(a, b keyedItem) int {
		return strings.Compare(a.key, b.key)
	})
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

func isNil(v any) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

// lowerCamel lowercases the leading word of a Kind for log keys and error
// messages: "ClusterRole" -> "clusterRole", "RBACPolicy" -> "rbacPolicy".
func lowerCamel(kind string) string {
	runes := []rune(kind)
	upper := 0
	for upper < len(runes) && unicode.IsUpper(runes[upper]) {
		upper++
	}
	if upper > 1 && upper < len(runes) {
		upper--
	}
	for i := range upper {
		runes[i] = unicode.ToLower(runes[i])
	}
	return string(runes)
}
