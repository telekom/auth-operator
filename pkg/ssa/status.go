// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// StatusApplier describes how to skip-if-unchanged Server-Side Apply the
// status subresource of one object type. The status is applied with
// FieldOwner and ForceOwnership because a controller is the sole owner of the
// status it computes.
//
// All fields except BeforeApply are required.
type StatusApplier[T client.Object, AC runtime.ApplyConfiguration] struct {
	// Kind is used in errors and logs, e.g. "RoleDefinition".
	Kind string
	// FieldOwner is the SSA field manager for the status apply.
	FieldOwner string
	// New returns an empty object to read the cached state into.
	New func() T
	// Equal reports whether the cached status already equals the desired one.
	Equal func(cached, desired T) bool
	// ApplyConfiguration builds the status apply configuration for desired.
	ApplyConfiguration func(desired T) AC
	// BeforeApply, if set, runs before a non-skipped apply when the object was
	// found in the cache, e.g. to clear lists SSA cannot empty.
	BeforeApply func(ctx context.Context, c client.Client, cached, desired T) error
}

// PatchApply compares the status of obj against the cached object and only
// applies the status subresource when it changed. A missing cached object is
// applied unconditionally so the API server reports a clear error.
//
// Errors are returned together with PatchApplyResultPatched.
func (s StatusApplier[T, AC]) PatchApply(ctx context.Context, c client.Client, obj T) (PatchApplyResult, error) {
	kind := lowerCamel(s.Kind)
	if isNil(obj) {
		return PatchApplyResultPatched, fmt.Errorf("%s must not be nil", kind)
	}
	name := obj.GetName()
	if name == "" {
		return PatchApplyResultPatched, fmt.Errorf("%s must have a name", kind)
	}

	logger := log.FromContext(ctx)

	cached := s.New()
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: obj.GetNamespace()}, cached); err != nil {
		if !apierrors.IsNotFound(err) {
			return PatchApplyResultPatched, fmt.Errorf("get cached %s %s: %w", s.Kind, name, err)
		}
		logger.V(2).Info(s.Kind+" not in cache, applying status unconditionally", "name", name)
	} else {
		if s.Equal(cached, obj) {
			logger.V(2).Info(s.Kind+" status unchanged, skipping apply", "name", name)
			return PatchApplyResultSkipped, nil
		}
		if s.BeforeApply != nil {
			if err := s.BeforeApply(ctx, c, cached, obj); err != nil {
				return PatchApplyResultPatched, err
			}
		}
	}

	if err := ApplyStatus(ctx, c, s.ApplyConfiguration(obj), s.FieldOwner); err != nil {
		return PatchApplyResultPatched, fmt.Errorf("apply %s %s status: %w", s.Kind, name, err)
	}
	return PatchApplyResultPatched, nil
}

// ApplyStatus applies applyConfig to the status subresource via SSA with
// fieldOwner and ForceOwnership.
func ApplyStatus(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration, fieldOwner string) error {
	if isNil(applyConfig) {
		return fmt.Errorf("applyConfig must not be nil")
	}
	return c.SubResource("status").Apply(ctx, applyConfig, client.FieldOwner(fieldOwner), client.ForceOwnership)
}
