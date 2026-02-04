// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Event reason constants for Kubernetes events emitted by the auth-operator controllers.
// These follow the convention of using PascalCase for event reasons.
// See: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/events.md
const (
	// EventReasonFinalizer indicates a finalizer operation.
	EventReasonFinalizer = "Finalizer"

	// EventReasonFinalizerRemoved indicates a finalizer was removed.
	EventReasonFinalizerRemoved = "FinalizerRemoved"

	// EventReasonCreate indicates a resource was created.
	EventReasonCreate = "Create"

	// EventReasonCreation indicates a resource creation event (alias for Create).
	EventReasonCreation = EventReasonCreate

	// EventReasonUpdate indicates a resource was updated.
	EventReasonUpdate = "Update"

	// EventReasonDeletion indicates a resource deletion operation.
	EventReasonDeletion = "Deletion"

	// EventReasonDeletionPending indicates deletion is waiting for dependent resources.
	EventReasonDeletionPending = "DeletionPending"

	// EventReasonOwnership indicates an ownership-related event (e.g., missing owner reference).
	EventReasonOwnership = "Ownership"

	// EventReasonRoleRefNotFound indicates a referenced role was not found.
	EventReasonRoleRefNotFound = "RoleRefNotFound"
)
