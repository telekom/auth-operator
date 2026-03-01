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

	// EventReasonServiceAccountPreExisting indicates a ServiceAccount already exists
	// and is not owned by any BindDefinition, so it will not be adopted.
	EventReasonServiceAccountPreExisting = "ServiceAccountPreExisting"

	// EventReasonServiceAccountShared indicates a ServiceAccount is shared between
	// multiple BindDefinitions (co-owned via non-controller ownerRefs).
	EventReasonServiceAccountShared = "ServiceAccountShared"

	// EventReasonServiceAccountRetained indicates a ServiceAccount was not deleted
	// because other BindDefinitions still reference it.
	EventReasonServiceAccountRetained = "ServiceAccountRetained"

	// EventReasonReconciled indicates a resource was successfully reconciled.
	EventReasonReconciled = "Reconciled"

	// EventReasonExternalSATracked indicates a BindDefinition now references
	// an external (pre-existing) ServiceAccount.
	EventReasonExternalSATracked = "ExternalSATracked"

	// EventReasonExternalSAUntracked indicates a BindDefinition no longer references
	// an external (pre-existing) ServiceAccount.
	EventReasonExternalSAUntracked = "ExternalSAUntracked"
)

// Event action constants for the events.k8s.io/v1 API.
// These describe the controller action that generated the event.
const (
	// EventActionReconcile indicates a reconciliation action.
	EventActionReconcile = "Reconcile"

	// EventActionCreate indicates a resource creation action.
	EventActionCreate = "CreateResource"

	// EventActionUpdate indicates a resource update action.
	EventActionUpdate = "UpdateResource"

	// EventActionDelete indicates a resource deletion action.
	EventActionDelete = "DeleteResource"

	// EventActionFinalizerAdd indicates adding a finalizer.
	EventActionFinalizerAdd = "AddFinalizer"

	// EventActionFinalizerRemove indicates removing a finalizer.
	EventActionFinalizerRemove = "RemoveFinalizer"

	// EventActionValidate indicates a validation check.
	EventActionValidate = "Validate"
)
