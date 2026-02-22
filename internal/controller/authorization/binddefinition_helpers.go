package authorization

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	sigs_client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

// ownerRefForBindDefinition creates an OwnerReference ApplyConfiguration for a BindDefinition.
// Uses hardcoded GVK to avoid empty APIVersion/Kind after client.Get() (TypeMeta is not populated by the API server).
// This creates a controller ownerRef — used for CRBs and RBs where each binding is owned by exactly one BD.
func ownerRefForBindDefinition(bindDef *authorizationv1alpha1.BindDefinition) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authorizationv1alpha1.GroupVersion.String(),
		"BindDefinition",
		bindDef.Name,
		bindDef.UID,
		true, // controller
		true, // blockOwnerDeletion
	)
}

// saOwnerRefForBindDefinition creates a non-controller OwnerReference for ServiceAccounts.
// Multiple BindDefinitions may reference the same SA, so we use controller=false to allow
// shared ownership. With non-controller ownerRefs, Kubernetes GC only deletes the SA when
// ALL owner BDs are gone — preventing premature deletion when one of several owners is removed.
func saOwnerRefForBindDefinition(bindDef *authorizationv1alpha1.BindDefinition) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authorizationv1alpha1.GroupVersion.String(),
		"BindDefinition",
		bindDef.Name,
		bindDef.UID,
		false, // controller — shared ownership, no single controller
		false, // blockOwnerDeletion — let GC handle lifecycle naturally
	)
}

// hasOwnerRef checks if the object has an ownerReference pointing to the given owner (by UID).
// Unlike metav1.IsControlledBy, this matches any ownerRef regardless of the controller flag.
func hasOwnerRef(obj, owner metav1.ObjectMetaAccessor) bool {
	ownerUID := owner.(metav1.Object).GetUID()
	for _, ref := range obj.(metav1.Object).GetOwnerReferences() {
		if ref.UID == ownerUID {
			return true
		}
	}
	return false
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
func (r *BindDefinitionReconciler) applyStatusNonFatal(ctx context.Context, bindDef *authorizationv1alpha1.BindDefinition) {
	if err := ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDef); err != nil {
		logStatusApplyError(ctx, err, bindDef.Name)
	}
}

// markStalled marks the BindDefinition as stalled with the given error (kstatus pattern).
// Uses SSA to apply the stalled condition atomically.
func (r *BindDefinitionReconciler) markStalled(
	ctx context.Context,
	bindDefinition *authorizationv1alpha1.BindDefinition,
	err error,
) {
	logger := log.FromContext(ctx)
	conditions.MarkStalled(bindDefinition, bindDefinition.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, err.Error())
	bindDefinition.Status.ObservedGeneration = bindDefinition.Generation
	if updateErr := ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDefinition); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "bindDefinitionName", bindDefinition.Name)
	}
}

// markReady marks the BindDefinition as ready (kstatus pattern).
// This only mutates conditions/fields; caller is responsible for applying status via SSA.
func (r *BindDefinitionReconciler) markReady(
	ctx context.Context,
	bindDefinition *authorizationv1alpha1.BindDefinition,
) {
	_ = ctx // unused but kept for consistent function signature
	conditions.MarkReady(bindDefinition, bindDefinition.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)
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

// deleteServiceAccount attempts to delete a service account if it has an ownerReference.
// Returns the result of the deletion and any error encountered.
func (r *BindDefinitionReconciler) deleteServiceAccount(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
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
		logger.V(2).Info("ServiceAccount is referenced by other BindDefinitions - NOT deleting, updating source-names",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)

		// Remove our BD name from the source-names annotation
		if sa.Annotations != nil {
			oldSourceNames := sa.Annotations[helpers.SourceNamesAnnotation]
			newSourceNames := helpers.RemoveSourceName(oldSourceNames, bindDef.Name)
			if newSourceNames != oldSourceNames {
				if sa.Annotations == nil {
					sa.Annotations = make(map[string]string)
				}
				sa.Annotations[helpers.SourceNamesAnnotation] = newSourceNames
				if err := r.client.Update(ctx, sa); err != nil {
					logger.Error(err, "Failed to update source-names annotation on retained ServiceAccount",
						"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
					// Non-fatal - continue with deletion cleanup
				} else {
					logger.V(2).Info("Updated source-names annotation on retained ServiceAccount",
						"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name,
						"oldSourceNames", oldSourceNames, "newSourceNames", newSourceNames)
				}
			}
		}

		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal,
			authorizationv1alpha1.EventReasonServiceAccountRetained, authorizationv1alpha1.EventActionDelete,
			"Retained ServiceAccount %s/%s (still referenced by other BindDefinitions)",
			sa.Namespace, sa.Name)
		return deleteResultNoOwnerRef, nil
	}

	if !hasOwnerRef(sa, bindDef) {
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
			"Not deleting target resource ServiceAccount/%s in namespace %s because we do not have OwnerRef",
			saName, saNamespace)
		logger.V(1).Info("Cannot delete ServiceAccount - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
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
	bindDef *authorizationv1alpha1.BindDefinition,
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
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
			"Not deleting target resource ClusterRoleBinding/%s because we do not have OwnerRef", crbName)
		logger.V(1).Info("Cannot delete ClusterRoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
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
	bindDef *authorizationv1alpha1.BindDefinition,
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
		r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
			"Not deleting target resource RoleBinding/%s in namespace %s because we do not have OwnerRef",
			rbName, namespace)
		logger.V(1).Info("Cannot delete RoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, nil, corev1.EventTypeWarning, authorizationv1alpha1.EventReasonDeletion, authorizationv1alpha1.EventActionDelete,
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
	bindDef *authorizationv1alpha1.BindDefinition,
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
				r.recorder.Eventf(nsObj, nil, corev1.EventTypeWarning, authorizationv1alpha1.EventReasonDeletionPending, authorizationv1alpha1.EventActionReconcile,
					"Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
			}
		}
	}
	return activeNamespaces
}

// resolveRoleBindingNamespaces returns the namespaces that match the roleBinding's selection criteria.
func (r *BindDefinitionReconciler) resolveRoleBindingNamespaces(
	ctx context.Context,
	roleBinding authorizationv1alpha1.NamespaceBinding,
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

// addExternalSAReference adds the BindDefinition name to the referenced-by annotation
// on an external ServiceAccount. This tracks which BDs reference pre-existing SAs.
func (r *BindDefinitionReconciler) addExternalSAReference(
	ctx context.Context,
	sa *corev1.ServiceAccount,
	bdName string,
) error {
	logger := log.FromContext(ctx)

	// Get current annotation value
	current := ""
	if sa.Annotations != nil {
		current = sa.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy]
	}

	// Parse existing references and check if already present
	refs := parseReferencedBy(current)
	for _, ref := range refs {
		if ref == bdName {
			// Already referenced, nothing to do
			return nil
		}
	}

	// Add our reference
	refs = append(refs, bdName)
	newValue := strings.Join(refs, ",")

	// Patch the ServiceAccount to add/update the annotation
	old := sa.DeepCopy()
	if sa.Annotations == nil {
		sa.Annotations = make(map[string]string)
	}
	sa.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy] = newValue

	if err := r.client.Patch(ctx, sa, sigs_client.MergeFrom(old)); err != nil {
		return fmt.Errorf("patch ServiceAccount %s/%s to add referenced-by annotation: %w",
			sa.Namespace, sa.Name, err)
	}

	logger.V(1).Info("Added referenced-by annotation to external ServiceAccount",
		"serviceAccount", sa.Name, "namespace", sa.Namespace, "bindDefinition", bdName)
	r.recorder.Eventf(sa, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonExternalSATracked, authorizationv1alpha1.EventActionReconcile,
		"BindDefinition %s now references this ServiceAccount", bdName)

	return nil
}

// removeExternalSAReference removes the BindDefinition name from the referenced-by annotation
// on an external ServiceAccount. If no references remain, the annotation is removed entirely.
func (r *BindDefinitionReconciler) removeExternalSAReference(
	ctx context.Context,
	saNamespace, saName, bdName string,
) error {
	logger := log.FromContext(ctx)

	sa := &corev1.ServiceAccount{}
	err := r.client.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// SA no longer exists, nothing to clean up
			return nil
		}
		return fmt.Errorf("get ServiceAccount %s/%s: %w", saNamespace, saName, err)
	}

	// Check if annotation exists
	if sa.Annotations == nil {
		return nil // No annotations, nothing to remove
	}
	current, exists := sa.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy]
	if !exists {
		return nil // Annotation doesn't exist
	}

	// Parse and remove our reference
	refs := parseReferencedBy(current)
	newRefs := make([]string, 0, len(refs))
	found := false
	for _, ref := range refs {
		if ref == bdName {
			found = true
			continue
		}
		newRefs = append(newRefs, ref)
	}

	if !found {
		return nil // We weren't in the list anyway
	}

	// Patch the ServiceAccount to update/remove the annotation
	old := sa.DeepCopy()
	if len(newRefs) == 0 {
		delete(sa.Annotations, authorizationv1alpha1.AnnotationKeyReferencedBy)
	} else {
		sa.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy] = strings.Join(newRefs, ",")
	}

	if err := r.client.Patch(ctx, sa, sigs_client.MergeFrom(old)); err != nil {
		return fmt.Errorf("patch ServiceAccount %s/%s to remove referenced-by annotation: %w",
			saNamespace, saName, err)
	}

	logger.V(1).Info("Removed referenced-by annotation from external ServiceAccount",
		"serviceAccount", saName, "namespace", saNamespace, "bindDefinition", bdName)
	r.recorder.Eventf(sa, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonExternalSAUntracked, authorizationv1alpha1.EventActionDelete,
		"BindDefinition %s no longer references this ServiceAccount", bdName)

	return nil
}

// parseReferencedBy parses a comma-separated referenced-by annotation value into a slice.
// It trims whitespace from each entry.
func parseReferencedBy(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// cleanupExternalSAReferences removes the BindDefinition's tracking annotations
// from all external ServiceAccounts it references. This is called during deletion.
func (r *BindDefinitionReconciler) cleanupExternalSAReferences(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) {
	logger := log.FromContext(ctx)

	// Clean up based on current status (which tracks what we've been referencing)
	for _, saRef := range bindDef.Status.ExternalServiceAccounts {
		parts := strings.SplitN(saRef, "/", 2)
		if len(parts) != 2 {
			logger.V(1).Info("Invalid external SA reference format, skipping cleanup",
				"reference", saRef)
			continue
		}
		ns, name := parts[0], parts[1]
		if err := r.removeExternalSAReference(ctx, ns, name, bindDef.Name); err != nil {
			// Log but don't fail - best effort cleanup
			logger.Error(err, "Failed to remove tracking annotation from external ServiceAccount",
				"serviceAccount", name, "namespace", ns)
		}
	}

	// Also scan spec subjects in case status is out of date
	for _, subject := range bindDef.Spec.Subjects {
		if subject.Kind != authorizationv1alpha1.BindSubjectServiceAccount {
			continue
		}
		// Check if this SA is external (not owned by any BD)
		sa := &corev1.ServiceAccount{}
		err := r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
		if err != nil {
			continue // SA doesn't exist or error - skip
		}
		if !isOwnedByBindDefinition(sa.OwnerReferences) {
			// External SA - remove our reference
			if err := r.removeExternalSAReference(ctx, subject.Namespace, subject.Name, bindDef.Name); err != nil {
				logger.Error(err, "Failed to remove tracking annotation from external ServiceAccount",
					"serviceAccount", subject.Name, "namespace", subject.Namespace)
			}
		}
	}
}
