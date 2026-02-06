package authorization

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

// ErrInvalidTargetRole is returned when the target role type is not valid.
var ErrInvalidTargetRole = fmt.Errorf("invalid target role type: must be ClusterRole or Role")

// ownerRefForRoleDefinition creates an OwnerReference ApplyConfiguration for a RoleDefinition.
// This centralizes owner reference construction for consistency across create/update paths.
func ownerRefForRoleDefinition(roleDefinition *authnv1alpha1.RoleDefinition) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authnv1alpha1.GroupVersion.String(),
		"RoleDefinition",
		roleDefinition.Name,
		roleDefinition.UID,
		true, // controller
		true, // blockOwnerDeletion
	)
}

// markStalled marks the RoleDefinition as stalled with the given error (kstatus pattern).
// Uses SSA to apply the stalled condition atomically.
func (r *RoleDefinitionReconciler) markStalled(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	err error,
) {
	logger := log.FromContext(ctx)
	// Copy status and apply stalled condition
	conditions.MarkStalled(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.StalledReasonError, authnv1alpha1.StalledMessageError, err.Error())
	roleDefinition.Status.ObservedGeneration = roleDefinition.Generation
	if updateErr := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "roleDefinitionName", roleDefinition.Name)
	}
}

// buildRoleObject creates the initial role object (ClusterRole or Role) based on spec.
// Returns an error if the target role type is not valid.
func (r *RoleDefinitionReconciler) buildRoleObject(
	roleDefinition *authnv1alpha1.RoleDefinition,
) (client.Object, error) {
	labels := helpers.BuildResourceLabels(roleDefinition.Labels)
	annotations := helpers.BuildResourceAnnotations("RoleDefinition", roleDefinition.Name)

	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		return &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:        roleDefinition.Spec.TargetName,
				Labels:      labels,
				Annotations: annotations,
			},
		}, nil
	case authnv1alpha1.DefinitionNamespacedRole:
		return &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:        roleDefinition.Spec.TargetName,
				Namespace:   roleDefinition.Spec.TargetNamespace,
				Labels:      labels,
				Annotations: annotations,
			},
		}, nil
	default:
		return nil, fmt.Errorf("%w: got %q", ErrInvalidTargetRole, roleDefinition.Spec.TargetRole)
	}
}

// ensureFinalizer ensures the RoleDefinition has a finalizer.
func (r *RoleDefinitionReconciler) ensureFinalizer(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
) error {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer) {
		return nil
	}

	logger.V(2).Info("Adding finalizer to RoleDefinition", "roleDefinitionName", roleDefinition.Name)
	old := roleDefinition.DeepCopy()
	controllerutil.AddFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
	if err := r.client.Patch(ctx, roleDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
		logger.Error(err, "Failed to add finalizer", "roleDefinitionName", roleDefinition.Name)
		return err
	}
	r.recorder.Eventf(roleDefinition, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonFinalizer, authnv1alpha1.EventActionFinalizerAdd,
		"Adding finalizer to RoleDefinition %s", roleDefinition.Name)
	return nil
}

// handleDeletion handles the deletion of the RoleDefinition and its associated role.
// Returns the reconcile result and any error.
// Status updates use Server-Side Apply (SSA) to avoid race conditions.
func (r *RoleDefinitionReconciler) handleDeletion(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	role client.Object,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	logger.V(1).Info("RoleDefinition marked for deletion - cleaning up resources",
		"roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole,
		"targetName", roleDefinition.Spec.TargetName)

	conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation,
		authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	if err := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); err != nil {
		logger.Error(err, "Failed to apply DeleteCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	r.recorder.Eventf(roleDefinition, nil, corev1.EventTypeWarning, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
		"Deleting target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	role.SetName(roleDefinition.Spec.TargetName)
	role.SetNamespace(roleDefinition.Spec.TargetNamespace)

	logger.V(2).Info("Attempting to delete role",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	if err := r.client.Delete(ctx, role); apierrors.IsNotFound(err) {
		logger.V(2).Info("Role not found - removing finalizer",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		// Re-fetch to get the latest ResourceVersion after SSA status updates
		if err := r.client.Get(ctx, client.ObjectKeyFromObject(roleDefinition), roleDefinition); err != nil {
			return ctrl.Result{}, fmt.Errorf("re-fetch RoleDefinition %s before finalizer removal: %w", roleDefinition.Name, err)
		}
		old := roleDefinition.DeepCopy()
		controllerutil.RemoveFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
		if err := r.client.Patch(ctx, roleDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			logger.Error(err, "Failed to remove finalizer", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		logger.V(1).Info("RoleDefinition deletion completed successfully", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, nil
	} else if err != nil {
		logger.Error(err, "Failed to delete role",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		conditions.MarkFalse(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation,
			authnv1alpha1.DeleteReason, "error deleting resource: %s", err.Error())
		if updateErr := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); updateErr != nil {
			logger.Error(updateErr, "Failed to apply status after deletion error",
				"roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, fmt.Errorf("deletion failed with error %s and a second error was found during update of role definition status: %w",
				err.Error(), updateErr)
		}
		return ctrl.Result{}, err
	}

	logger.V(2).Info("Requeuing RoleDefinition deletion", "roleDefinitionName", roleDefinition.Name)
	return ctrl.Result{RequeueAfter: time.Second}, nil
}

// buildFinalRules builds the final policy rules from the filtered API resources.
func (r *RoleDefinitionReconciler) buildFinalRules(
	roleDefinition *authnv1alpha1.RoleDefinition,
	rulesByAPIGroupAndVerbs map[string]*rbacv1.PolicyRule,
) []rbacv1.PolicyRule {
	finalRules := make([]rbacv1.PolicyRule, 0, len(rulesByAPIGroupAndVerbs))
	for _, rule := range rulesByAPIGroupAndVerbs {
		finalRules = append(finalRules, *rule)
	}

	// Add non-resource URL rule for ClusterRoles only (namespaced Roles cannot have NonResourceURLs)
	if roleDefinition.Spec.TargetRole == authnv1alpha1.DefinitionClusterRole && !slices.Contains(roleDefinition.Spec.RestrictedVerbs, "get") {
		finalRules = append(finalRules, rbacv1.PolicyRule{
			NonResourceURLs: []string{"/metrics"},
			Verbs:           []string{"get"},
		})
	}

	// Sort resources within each rule for deterministic output
	for i := range finalRules {
		slices.Sort(finalRules[i].APIGroups)
		slices.Sort(finalRules[i].Resources)
		slices.Sort(finalRules[i].ResourceNames)
		slices.Sort(finalRules[i].Verbs)
		slices.Sort(finalRules[i].NonResourceURLs)
	}

	// Sort rules for consistent ordering:
	// 1. NonResourceURLs rules come last (they have no APIGroups/Resources)
	// 2. Then sort by APIGroups, then Resources, then Verbs
	slices.SortFunc(finalRules, func(a, b rbacv1.PolicyRule) int {
		// NonResourceURLs rules should come last
		aHasNonResource := len(a.NonResourceURLs) > 0
		bHasNonResource := len(b.NonResourceURLs) > 0
		if aHasNonResource != bHasNonResource {
			if aHasNonResource {
				return 1
			}
			return -1
		}

		// Sort by APIGroups
		if c := strings.Compare(strings.Join(a.APIGroups, ","), strings.Join(b.APIGroups, ",")); c != 0 {
			return c
		}

		// Sort by Resources
		if c := strings.Compare(strings.Join(a.Resources, ","), strings.Join(b.Resources, ",")); c != 0 {
			return c
		}

		// Sort by Verbs
		return strings.Compare(strings.Join(a.Verbs, ","), strings.Join(b.Verbs, ","))
	})

	return finalRules
}

// ensureRole ensures the role (ClusterRole or Role) exists and is up-to-date using Server-Side Apply (SSA).
// This unified function replaces the separate createRole and updateRole functions.
// SSA handles both creation (if not exists) and update (if different) in a single operation.
func (r *RoleDefinitionReconciler) ensureRole(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	finalRules []rbacv1.PolicyRule,
) error {
	logger := log.FromContext(ctx)

	ownerRef := ownerRefForRoleDefinition(roleDefinition)
	labels := helpers.BuildResourceLabels(roleDefinition.Labels)
	annotations := helpers.BuildResourceAnnotations("RoleDefinition", roleDefinition.Name)

	// Apply the role using SSA - handles both create and update
	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		ac := pkgssa.ClusterRoleWithLabelsAndRules(
			roleDefinition.Spec.TargetName,
			labels,
			finalRules,
		).WithOwnerReferences(ownerRef).WithAnnotations(annotations)
		if err := pkgssa.ApplyClusterRole(ctx, r.client, ac); err != nil {
			logger.Error(err, "Failed to apply ClusterRole via SSA",
				"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return err
		}
		metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceClusterRole).Inc()
	case authnv1alpha1.DefinitionNamespacedRole:
		ac := pkgssa.RoleWithLabelsAndRules(
			roleDefinition.Spec.TargetName,
			roleDefinition.Spec.TargetNamespace,
			labels,
			finalRules,
		).WithOwnerReferences(ownerRef).WithAnnotations(annotations)
		if err := pkgssa.ApplyRole(ctx, r.client, ac); err != nil {
			logger.Error(err, "Failed to apply Role via SSA",
				"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return err
		}
		metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceRole).Inc()
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTargetRole, roleDefinition.Spec.TargetRole)
	}

	logger.V(1).Info("Role ensured successfully",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	// Set conditions - SSA applied successfully
	conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
		authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	conditions.MarkReady(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)

	r.recorder.Eventf(roleDefinition, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonCreation, authnv1alpha1.EventActionReconcile,
		"Ensured target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	return nil
}
