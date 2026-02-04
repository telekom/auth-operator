package authorization

import (
	"context"
	"fmt"
	"slices"
	"sort"
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
	log := log.FromContext(ctx)
	// Copy status and apply stalled condition
	conditions.MarkStalled(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.StalledReasonError, authnv1alpha1.StalledMessageError, err.Error())
	roleDefinition.Status.ObservedGeneration = roleDefinition.Generation
	if updateErr := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); updateErr != nil {
		log.Error(updateErr, "failed to apply Stalled status via SSA", "roleDefinitionName", roleDefinition.Name)
	}
}

// buildRoleObject creates the initial role object (ClusterRole or Role) based on spec.
// Returns an error if the target role type is not valid.
func (r *RoleDefinitionReconciler) buildRoleObject(
	roleDefinition *authnv1alpha1.RoleDefinition,
) (client.Object, error) {
	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		return &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: buildResourceLabels(roleDefinition.Labels),
			},
		}, nil
	case authnv1alpha1.DefinitionNamespacedRole:
		return &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    buildResourceLabels(roleDefinition.Labels),
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
	log := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer) {
		return nil
	}

	log.V(2).Info("Adding finalizer to RoleDefinition", "roleDefinitionName", roleDefinition.Name)
	controllerutil.AddFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
	if err := r.client.Update(ctx, roleDefinition); err != nil {
		log.Error(err, "Failed to add finalizer", "roleDefinitionName", roleDefinition.Name)
		return err
	}
	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, authnv1alpha1.EventReasonFinalizer,
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
	log := log.FromContext(ctx)

	log.V(1).Info("RoleDefinition marked for deletion - cleaning up resources",
		"roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole,
		"targetName", roleDefinition.Spec.TargetName)

	conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation,
		authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	if err := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); err != nil {
		log.Error(err, "Failed to apply DeleteCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	r.recorder.Eventf(roleDefinition, corev1.EventTypeWarning, authnv1alpha1.EventReasonDeletion,
		"Deleting target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	role.SetName(roleDefinition.Spec.TargetName)
	role.SetNamespace(roleDefinition.Spec.TargetNamespace)

	log.V(2).Info("Attempting to delete role",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	if err := r.client.Delete(ctx, role); apierrors.IsNotFound(err) {
		log.V(2).Info("Role not found - removing finalizer",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		controllerutil.RemoveFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
		if err := r.client.Update(ctx, roleDefinition); err != nil {
			log.Error(err, "Failed to remove finalizer", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		log.V(1).Info("RoleDefinition deletion completed successfully", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to delete role",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		conditions.MarkFalse(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation,
			authnv1alpha1.DeleteReason, "error deleting resource: %s", err.Error())
		if updateErr := ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition); updateErr != nil {
			log.Error(updateErr, "Failed to apply status after deletion error",
				"roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, fmt.Errorf("deletion failed with error %s and a second error was found during update of role definition status: %w",
				err.Error(), updateErr)
		}
		return ctrl.Result{}, err
	}

	log.V(2).Info("Requeuing RoleDefinition deletion", "roleDefinitionName", roleDefinition.Name)
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
		sort.Strings(finalRules[i].APIGroups)
		sort.Strings(finalRules[i].Resources)
		sort.Strings(finalRules[i].ResourceNames)
		sort.Strings(finalRules[i].Verbs)
		sort.Strings(finalRules[i].NonResourceURLs)
	}

	// Sort rules for consistent ordering:
	// 1. NonResourceURLs rules come last (they have no APIGroups/Resources)
	// 2. Then sort by APIGroups, then Resources, then Verbs
	sort.Slice(finalRules, func(i, j int) bool {
		iRule := finalRules[i]
		jRule := finalRules[j]

		// NonResourceURLs rules should come last
		iHasNonResource := len(iRule.NonResourceURLs) > 0
		jHasNonResource := len(jRule.NonResourceURLs) > 0
		if iHasNonResource != jHasNonResource {
			return !iHasNonResource // Regular rules before NonResourceURL rules
		}

		// Sort by APIGroups
		iAPIGroups := strings.Join(iRule.APIGroups, ",")
		jAPIGroups := strings.Join(jRule.APIGroups, ",")
		if iAPIGroups != jAPIGroups {
			return iAPIGroups < jAPIGroups
		}

		// Sort by Resources
		iResources := strings.Join(iRule.Resources, ",")
		jResources := strings.Join(jRule.Resources, ",")
		if iResources != jResources {
			return iResources < jResources
		}

		// Sort by Verbs
		return strings.Join(iRule.Verbs, ",") < strings.Join(jRule.Verbs, ",")
	})

	return finalRules
}

// buildRoleWithRules creates a role object with the given rules.
// Note: The caller should have already validated the target role type via buildRoleObject,
// so this function assumes the target role type is valid.
func (r *RoleDefinitionReconciler) buildRoleWithRules(
	roleDefinition *authnv1alpha1.RoleDefinition,
	finalRules []rbacv1.PolicyRule,
) (role client.Object, existingRole client.Object) {
	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		role = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: buildResourceLabels(roleDefinition.Labels),
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.ClusterRole{}
	case authnv1alpha1.DefinitionNamespacedRole:
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    buildResourceLabels(roleDefinition.Labels),
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.Role{}
	default:
		// This should never happen as buildRoleObject validates the type first.
		// Return empty objects to avoid nil pointer dereference.
		return &rbacv1.ClusterRole{}, &rbacv1.ClusterRole{}
	}

	return role, existingRole
}

// createRole creates a new role and applies status using Server-Side Apply (SSA).
// This function applies status via SSA since it returns early from the Reconcile function.
func (r *RoleDefinitionReconciler) createRole(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	role client.Object,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.V(2).Info("Role does not exist - creating new role via SSA",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	// Apply the role using SSA
	if err := r.applyRoleSSA(ctx, roleDefinition, role); err != nil {
		log.Error(err, "Failed to apply role via SSA",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	log.V(1).Info("Role created successfully",
		"roleDefinitionName", roleDefinition.Name, "roleName", role.GetName())

	// Set conditions and status
	conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
		authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	roleDefinition.Status.RoleReconciled = true

	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, authnv1alpha1.EventReasonCreation,
		"Created target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	// Mark Ready and apply status via SSA (this function returns early from Reconcile)
	conditions.MarkReady(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)
	if err := r.applyStatus(ctx, roleDefinition); err != nil {
		log.Error(err, "failed to apply status after role creation", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	log.V(1).Info("RoleDefinition reconciliation completed successfully", "roleDefinitionName", roleDefinition.Name)
	return ctrl.Result{}, nil
}

// applyRoleSSA applies a role using Server-Side Apply.
func (r *RoleDefinitionReconciler) applyRoleSSA(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	role client.Object,
) error {
	ownerRef := ownerRefForRoleDefinition(roleDefinition)

	switch t := role.(type) {
	case *rbacv1.ClusterRole:
		ac := pkgssa.ClusterRoleWithLabelsAndRules(t.Name, t.Labels, t.Rules).
			WithOwnerReferences(ownerRef)
		return pkgssa.ApplyClusterRole(ctx, r.client, ac)
	case *rbacv1.Role:
		ac := pkgssa.RoleWithLabelsAndRules(t.Name, t.Namespace, t.Labels, t.Rules).
			WithOwnerReferences(ownerRef)
		return pkgssa.ApplyRole(ctx, r.client, ac)
	default:
		return fmt.Errorf("unsupported role type: %T", role)
	}
}

// updateRole updates an existing role if rules differ using Server-Side Apply (SSA).
// This function mutates conditions on the roleDefinition object; the caller applies
// the final status via SSA after this function returns.
func (r *RoleDefinitionReconciler) updateRole(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	existingRole client.Object,
	finalRules []rbacv1.PolicyRule,
) error {
	log := log.FromContext(ctx)

	// Only update roles controlled by this RoleDefinition
	if !metav1.IsControlledBy(existingRole, roleDefinition) {
		log.V(1).Info("Skipping role update - not controlled by this RoleDefinition",
			"roleDefinitionName", roleDefinition.Name, "roleName", existingRole.GetName())
		r.recorder.Eventf(roleDefinition, corev1.EventTypeWarning, authnv1alpha1.EventReasonOwnership,
			"Skipping update for %s %s: not controlled by this RoleDefinition", roleDefinition.Spec.TargetRole, existingRole.GetName())
		// Mark OwnerRef condition as false to indicate the role is not managed
		conditions.MarkFalse(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
			authnv1alpha1.OwnerRefReason, "Role %s exists but is not controlled by this RoleDefinition", existingRole.GetName())
		// Still mark Ready since the controller cannot take any action
		conditions.MarkReady(roleDefinition, roleDefinition.Generation,
			authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)
		return nil
	}

	// Role is controlled by this RoleDefinition - set OwnerRef condition
	conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
		authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)

	// Get existing rules
	var existingRules []rbacv1.PolicyRule
	switch t := existingRole.(type) {
	case *rbacv1.ClusterRole:
		existingRules = t.Rules
	case *rbacv1.Role:
		existingRules = t.Rules
	}

	if helpers.PolicyRulesEqual(existingRules, finalRules) {
		log.V(3).Info("Role rules already up-to-date - no update needed",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		// Ensure CreateCondition is set (role exists and is managed by this controller)
		// This handles controller restarts where the role already exists
		conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
			authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
		// Mark Ready condition even when no update was needed (kstatus) - caller will apply
		conditions.MarkReady(roleDefinition, roleDefinition.Generation,
			authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)
		return nil
	}

	log.V(2).Info("Role rules differ - updating role via SSA",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName,
		"existingRuleCount", len(existingRules), "newRuleCount", len(finalRules))

	ownerRef := ownerRefForRoleDefinition(roleDefinition)

	// Apply the role using SSA
	switch existingRole.(type) {
	case *rbacv1.ClusterRole:
		ac := pkgssa.ClusterRoleWithLabelsAndRules(
			roleDefinition.Spec.TargetName,
			buildResourceLabels(roleDefinition.Labels),
			finalRules,
		).WithOwnerReferences(ownerRef)
		if err := pkgssa.ApplyClusterRole(ctx, r.client, ac); err != nil {
			log.Error(err, "Failed to apply ClusterRole via SSA",
				"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return err
		}
	case *rbacv1.Role:
		ac := pkgssa.RoleWithLabelsAndRules(
			roleDefinition.Spec.TargetName,
			roleDefinition.Spec.TargetNamespace,
			buildResourceLabels(roleDefinition.Labels),
			finalRules,
		).WithOwnerReferences(ownerRef)
		if err := pkgssa.ApplyRole(ctx, r.client, ac); err != nil {
			log.Error(err, "Failed to apply Role via SSA",
				"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return err
		}
	default:
		log.Error(ErrInvalidTargetRole, "Existing role has invalid type",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName,
			"actualType", fmt.Sprintf("%T", existingRole))
		return ErrInvalidTargetRole
	}

	log.V(1).Info("Role updated successfully",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	// Batch condition updates - caller will apply status via SSA
	// Ensure CreateCondition is set (role exists and is managed by this controller)
	// This handles controller restarts where the role already exists
	conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	// Set UpdateCondition to indicate the role was updated
	conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation,
		authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
	roleDefinition.Status.RoleReconciled = true

	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, authnv1alpha1.EventReasonUpdate,
		"Updated target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	// Mark Ready condition (kstatus) - caller will apply status
	conditions.MarkReady(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)

	return nil
}
