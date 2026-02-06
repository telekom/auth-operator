package authorization

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	sigs_client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

// ownerRefForBindDefinition creates an OwnerReference ApplyConfiguration for a BindDefinition.
// Uses hardcoded GVK to avoid empty APIVersion/Kind after client.Get() (TypeMeta is not populated by the API server).
func ownerRefForBindDefinition(bindDef *authnv1alpha1.BindDefinition) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authnv1alpha1.GroupVersion.String(),
		"BindDefinition",
		bindDef.Name,
		bindDef.UID,
		true, // controller
		true, // blockOwnerDeletion
	)
}

// logStatusApplyError logs a status apply error without failing the operation.
// This is used when the primary error is more important than the status apply failure.
func logStatusApplyError(ctx context.Context, err error, resourceName string) {
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to apply status (non-fatal)", "resource", resourceName)
	}
}

// applyStatusNonFatal applies status via SSA and logs any error without failing.
// This is used for helper functions that need to update status but shouldn't fail on status errors.
func (r *BindDefinitionReconciler) applyStatusNonFatal(ctx context.Context, bindDef *authnv1alpha1.BindDefinition) {
	if err := ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDef); err != nil {
		logStatusApplyError(ctx, err, bindDef.Name)
	}
}

// markStalled marks the BindDefinition as stalled with the given error (kstatus pattern).
// Uses SSA to apply the stalled condition atomically.
func (r *BindDefinitionReconciler) markStalled(
	ctx context.Context,
	bindDefinition *authnv1alpha1.BindDefinition,
	err error,
) {
	logger := log.FromContext(ctx)
	conditions.MarkStalled(bindDefinition, bindDefinition.Generation,
		authnv1alpha1.StalledReasonError, authnv1alpha1.StalledMessageError, err.Error())
	bindDefinition.Status.ObservedGeneration = bindDefinition.Generation
	if updateErr := ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDefinition); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "bindDefinitionName", bindDefinition.Name)
	}
}

// markReady marks the BindDefinition as ready (kstatus pattern).
// This only mutates conditions/fields; caller is responsible for applying status via SSA.
func (r *BindDefinitionReconciler) markReady(
	ctx context.Context,
	bindDefinition *authnv1alpha1.BindDefinition,
) {
	_ = ctx // unused but kept for consistent function signature
	conditions.MarkReady(bindDefinition, bindDefinition.Generation,
		authnv1alpha1.ReadyReasonReconciled, authnv1alpha1.ReadyMessageReconciled)
	bindDefinition.Status.ObservedGeneration = bindDefinition.Generation
	bindDefinition.Status.BindReconciled = true
}

// deleteResult represents the outcome of a resource deletion attempt.
type deleteResult int

const (
	deleteResultDeleted deleteResult = iota
	deleteResultNotFound
	deleteResultNoOwnerRef
)

// deleteServiceAccount attempts to delete a service account if it has a controller reference.
// Returns the result of the deletion and any error encountered.
func (r *BindDefinitionReconciler) deleteServiceAccount(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	saName, saNamespace string,
) (deleteResult, error) {
	logger := log.FromContext(ctx)

	sa := &corev1.ServiceAccount{}
	err := r.client.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("ServiceAccount not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Unable to fetch ServiceAccount from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)
		return 0, fmt.Errorf("get ServiceAccount %s/%s: %w", saNamespace, saName, err)
	}

	// Check if referenced by other BindDefinitions
	isReferenced, err := r.isSAReferencedByOtherBindDefs(ctx, bindDef.Name, sa.Name, sa.Namespace)
	if err != nil {
		logger.Error(err, "Failed to check if ServiceAccount is referenced by other BindDefinitions",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return 0, fmt.Errorf("check ServiceAccount %s/%s references: %w", sa.Namespace, sa.Name, err)
	}

	if isReferenced {
		logger.V(2).Info("ServiceAccount is referenced by other BindDefinitions - NOT deleting",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return deleteResultNoOwnerRef, nil
	}

	if !metav1.IsControlledBy(sa, bindDef) {
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
			"Not deleting target resource ServiceAccount/%s in namespace %s because we do not have OwnerRef",
			saName, saNamespace)
		logger.V(1).Info("Cannot delete ServiceAccount - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
		"Deleting target resource ServiceAccount/%s in namespace %s", saName, saNamespace)
	logger.V(1).Info("Cleanup ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)

	if err = r.client.Delete(ctx, sa); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("ServiceAccount already deleted during deletion attempt",
				"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Failed to delete ServiceAccount",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return 0, fmt.Errorf("delete ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
	}

	logger.V(1).Info("Successfully deleted ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
	metrics.RBACResourcesDeleted.WithLabelValues(metrics.ResourceServiceAccount).Inc()
	return deleteResultDeleted, nil
}

// deleteClusterRoleBinding attempts to delete a cluster role binding if it has a controller reference.
func (r *BindDefinitionReconciler) deleteClusterRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	clusterRoleRef string,
) (deleteResult, error) {
	logger := log.FromContext(ctx)

	crb := &rbacv1.ClusterRoleBinding{}
	crbName := helpers.BuildBindingName(bindDef.Spec.TargetName, clusterRoleRef)

	err := r.client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("ClusterRoleBinding not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return 0, fmt.Errorf("get ClusterRoleBinding %s: %w", crbName, err)
	}

	if !metav1.IsControlledBy(crb, bindDef) {
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
			"Not deleting target resource ClusterRoleBinding/%s because we do not have OwnerRef", crbName)
		logger.V(1).Info("Cannot delete ClusterRoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
		"Deleting target resource ClusterRoleBinding %s", crbName)
	logger.V(1).Info("Cleanup ClusterRoleBinding",
		"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)

	if err = r.client.Delete(ctx, crb); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("ClusterRoleBinding already deleted",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Failed to delete ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return 0, fmt.Errorf("delete ClusterRoleBinding %s: %w", crbName, err)
	}

	metrics.RBACResourcesDeleted.WithLabelValues(metrics.ResourceClusterRoleBinding).Inc()
	logger.V(1).Info("Successfully deleted ClusterRoleBinding",
		"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
	return deleteResultDeleted, nil
}

// deleteRoleBinding attempts to delete a role binding if it has a controller reference.
func (r *BindDefinitionReconciler) deleteRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	roleRef, namespace string,
) (deleteResult, error) {
	logger := log.FromContext(ctx)

	rb := &rbacv1.RoleBinding{}
	rbName := helpers.BuildBindingName(bindDef.Spec.TargetName, roleRef)

	err := r.client.Get(ctx, types.NamespacedName{Name: rbName, Namespace: namespace}, rb)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RoleBinding not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "namespace", namespace, "roleBindingName", rbName)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Unable to fetch RoleBinding from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "namespace", namespace, "roleBindingName", rbName)
		return 0, fmt.Errorf("get RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	if !metav1.IsControlledBy(rb, bindDef) {
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
			"Not deleting target resource RoleBinding/%s in namespace %s because we do not have OwnerRef",
			rbName, namespace)
		logger.V(1).Info("Cannot delete RoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeWarning, authnv1alpha1.EventReasonDeletion, authnv1alpha1.EventActionDelete,
		"Deleting target resource RoleBinding/%s in namespace %s", rbName, namespace)
	logger.V(1).Info("Cleanup RoleBinding",
		"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)

	if err = r.client.Delete(ctx, rb); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RoleBinding already deleted during deletion attempt",
				"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
			return deleteResultNotFound, nil
		}
		logger.Error(err, "Failed to delete RoleBinding",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		return 0, fmt.Errorf("delete RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	metrics.RBACResourcesDeleted.WithLabelValues(metrics.ResourceRoleBinding).Inc()
	logger.V(1).Info("Successfully deleted RoleBinding",
		"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
	return deleteResultDeleted, nil
}

// filterActiveNamespaces returns namespaces that are not in terminating phase.
func (r *BindDefinitionReconciler) filterActiveNamespaces(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespaceSet map[string]corev1.Namespace,
) []corev1.Namespace {
	logger := log.FromContext(ctx)
	activeNamespaces := []corev1.Namespace{}

	for _, ns := range namespaceSet {
		if conditions.IsNamespaceActive(&ns) {
			activeNamespaces = append(activeNamespaces, ns)
		} else {
			logger.V(1).Info("Skipping update in terminating namespace",
				"bindDefinitionName", bindDef.Name, "namespace", ns.Name)
			nsObj := &corev1.Namespace{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
				r.recorder.Eventf(nsObj, nil, corev1.EventTypeWarning, authnv1alpha1.EventReasonDeletionPending, authnv1alpha1.EventActionReconcile,
					"Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
			}
		}
	}
	return activeNamespaces
}

// resolveRoleBindingNamespaces returns the namespaces that match the roleBinding's selection criteria.
func (r *BindDefinitionReconciler) resolveRoleBindingNamespaces(
	ctx context.Context,
	roleBinding authnv1alpha1.NamespaceBinding,
) ([]corev1.Namespace, error) {
	var namespaces []corev1.Namespace

	// If explicit namespace is specified, use that
	if roleBinding.Namespace != "" {
		ns := &corev1.Namespace{}
		err := r.client.Get(ctx, types.NamespacedName{Name: roleBinding.Namespace}, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil // Namespace doesn't exist, skip
			}
			return nil, fmt.Errorf("get namespace %s: %w", roleBinding.Namespace, err)
		}
		return []corev1.Namespace{*ns}, nil
	}

	// Otherwise, use namespace selectors
	seen := make(map[string]bool)
	for _, nsSelector := range roleBinding.NamespaceSelector {
		selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
		if err != nil {
			return nil, fmt.Errorf("parse namespace selector: %w", err)
		}
		namespaceList := &corev1.NamespaceList{}
		listOpts := []sigs_client.ListOption{
			&sigs_client.ListOptions{LabelSelector: selector},
		}
		if err := r.client.List(ctx, namespaceList, listOpts...); err != nil {
			return nil, fmt.Errorf("list namespaces with selector %s: %w", selector.String(), err)
		}
		for _, ns := range namespaceList.Items {
			if !seen[ns.Name] {
				seen[ns.Name] = true
				namespaces = append(namespaces, ns)
			}
		}
	}

	return namespaces, nil
}
