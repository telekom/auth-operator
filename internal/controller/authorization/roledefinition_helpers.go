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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/conditions"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/helpers"
)

// ErrInvalidTargetRole is returned when the target role type is not valid.
var ErrInvalidTargetRole = fmt.Errorf("invalid target role type: must be ClusterRole or Role")

// buildRoleObject creates the initial role object (ClusterRole or Role) based on spec.
// Returns an error if the target role type is not valid.
func (r *roleDefinitionReconciler) buildRoleObject(
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
func (r *roleDefinitionReconciler) ensureFinalizer(
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
	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Finalizer",
		"Adding finalizer to RoleDefinition %s", roleDefinition.Name)
	return nil
}

// handleDeletion handles the deletion of the RoleDefinition and its associated role.
// Returns the reconcile result and any error.
func (r *roleDefinitionReconciler) handleDeletion(
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
	if err := r.client.Status().Update(ctx, roleDefinition); err != nil {
		log.Error(err, "Failed to update DeleteCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	r.recorder.Eventf(roleDefinition, corev1.EventTypeWarning, "Deletion",
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
		if updateErr := r.client.Status().Update(ctx, roleDefinition); updateErr != nil {
			log.Error(updateErr, "Failed to update status after deletion error",
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
func (r *roleDefinitionReconciler) buildFinalRules(
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

	// Sort resources within each rule
	for i := range finalRules {
		sort.Strings(finalRules[i].Resources)
		sort.Strings(finalRules[i].Verbs)
	}

	// Sort rules for consistent ordering
	sort.Slice(finalRules, func(i, j int) bool {
		iRule := finalRules[i]
		jRule := finalRules[j]
		if strings.Join(iRule.APIGroups, ",") != strings.Join(jRule.APIGroups, ",") {
			return strings.Join(iRule.APIGroups, ",") < strings.Join(jRule.APIGroups, ",")
		}
		return strings.Join(iRule.Verbs, ",") < strings.Join(jRule.Verbs, ",")
	})

	return finalRules
}

// buildRoleWithRules creates a role object with the given rules.
// Note: The caller should have already validated the target role type via buildRoleObject,
// so this function assumes the target role type is valid.
func (r *roleDefinitionReconciler) buildRoleWithRules(
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

// createRole creates a new role and updates conditions.
func (r *roleDefinitionReconciler) createRole(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	role client.Object,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.V(2).Info("Role does not exist - creating new role",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	conditions.MarkUnknown(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	if err := r.client.Status().Update(ctx, roleDefinition); err != nil {
		log.Error(err, "Failed to update CreateCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	if err := controllerutil.SetControllerReference(roleDefinition, role, r.scheme); err != nil {
		log.Error(err, "Failed to set controller reference",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		conditions.MarkFalse(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
			authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
		if updateErr := r.client.Status().Update(ctx, roleDefinition); updateErr != nil {
			log.Error(updateErr, "Failed to update status after OwnerRef error",
				"roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef",
		"Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	if err := r.client.Create(ctx, role); err != nil {
		log.Error(err, "Failed to create role",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		return ctrl.Result{}, err
	}

	log.V(1).Info("Role created successfully",
		"roleDefinitionName", roleDefinition.Name, "roleName", role.GetName())

	conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation,
		authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	if err := r.client.Status().Update(ctx, roleDefinition); err != nil {
		log.Error(err, "Failed to update status after role creation",
			"roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Creation",
		"Created target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	return ctrl.Result{}, nil
}

// updateRole updates an existing role if rules differ.
func (r *roleDefinitionReconciler) updateRole(
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
		r.recorder.Eventf(roleDefinition, corev1.EventTypeWarning, "Ownership",
			"Skipping update for %s %s: not controlled by this RoleDefinition", roleDefinition.Spec.TargetRole, existingRole.GetName())
		return nil
	}

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
		return nil
	}

	log.V(2).Info("Role rules differ - updating role",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName,
		"existingRuleCount", len(existingRules), "newRuleCount", len(finalRules))

	// Update rules on existing role
	switch t := existingRole.(type) {
	case *rbacv1.ClusterRole:
		t.Rules = finalRules
	case *rbacv1.Role:
		t.Rules = finalRules
	}

	if err := r.client.Update(ctx, existingRole); err != nil {
		log.Error(err, "Failed to update role",
			"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
		return err
	}

	log.V(1).Info("Role updated successfully",
		"roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

	conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation,
		authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
	conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
	if err := r.client.Status().Update(ctx, roleDefinition); err != nil {
		log.Error(err, "Failed to update status after role update",
			"roleDefinitionName", roleDefinition.Name)
		return err
	}

	r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Update",
		"Updated target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

	return nil
}
