package authorization

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	sigs_client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
)

// logStatusUpdateError logs a status update error without failing the operation.
// This is used when the primary error is more important than the status update failure.
func logStatusUpdateError(ctx context.Context, err error, resourceName string) {
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to update status (non-fatal)", "resource", resourceName)
	}
}

// buildResourceLabels creates labels for resources managed by the auth-operator.
// It merges the source labels with the standard auth-operator managed-by label.
func buildResourceLabels(sourceLabels map[string]string) map[string]string {
	labels := make(map[string]string)
	for k, v := range sourceLabels {
		labels[k] = v
	}
	labels["app.kubernetes.io/created-by"] = "auth-operator"
	return labels
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
func (r *bindDefinitionReconciler) deleteServiceAccount(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	saName, saNamespace string,
) (deleteResult, error) {
	log := log.FromContext(ctx)

	sa := &corev1.ServiceAccount{}
	err := r.client.Get(ctx, types.NamespacedName{Name: saName, Namespace: saNamespace}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("ServiceAccount not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Unable to fetch ServiceAccount from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)
		return 0, fmt.Errorf("get ServiceAccount %s/%s: %w", saNamespace, saName, err)
	}

	// Check if referenced by other BindDefinitions
	isReferenced, err := r.isSAReferencedByOtherBindDefs(ctx, bindDef.Name, sa.Name, sa.Namespace)
	if err != nil {
		log.Error(err, "Failed to check if ServiceAccount is referenced by other BindDefinitions",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return 0, fmt.Errorf("check ServiceAccount %s/%s references: %w", sa.Namespace, sa.Name, err)
	}

	if isReferenced {
		log.V(2).Info("ServiceAccount is referenced by other BindDefinitions - NOT deleting",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return deleteResultNoOwnerRef, nil
	}

	if !metav1.IsControlledBy(sa, bindDef) {
		r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Deletion",
			"Not deleting target resource ServiceAccount/%s in namespace %s because we do not have OwnerRef",
			saName, saNamespace)
		log.V(1).Info("Cannot delete ServiceAccount - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Deletion",
		"Deleting target resource ServiceAccount/%s in namespace %s", saName, saNamespace)
	log.V(1).Info("Cleanup ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", saName, "namespace", saNamespace)

	if err = r.client.Delete(ctx, sa); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("ServiceAccount already deleted during deletion attempt",
				"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Failed to delete ServiceAccount",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		return 0, fmt.Errorf("delete ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
	}

	log.V(1).Info("Successfully deleted ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
	return deleteResultDeleted, nil
}

// deleteClusterRoleBinding attempts to delete a cluster role binding if it has a controller reference.
func (r *bindDefinitionReconciler) deleteClusterRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	clusterRoleRef string,
) (deleteResult, error) {
	log := log.FromContext(ctx)

	crb := &rbacv1.ClusterRoleBinding{}
	crbName := fmt.Sprintf("%s-%s-%s", bindDef.Spec.TargetName, clusterRoleRef, "binding")

	err := r.client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("ClusterRoleBinding not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return 0, fmt.Errorf("get ClusterRoleBinding %s: %w", crbName, err)
	}

	if !metav1.IsControlledBy(crb, bindDef) {
		r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Deletion",
			"Not deleting target resource ClusterRoleBinding/%s because we do not have OwnerRef", crbName)
		log.V(1).Info("Cannot delete ClusterRoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Deletion",
		"Deleting target resource ClusterRoleBinding %s", crbName)
	log.V(1).Info("Cleanup ClusterRoleBinding",
		"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)

	if err = r.client.Delete(ctx, crb); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("ClusterRoleBinding already deleted",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Failed to delete ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		return 0, fmt.Errorf("delete ClusterRoleBinding %s: %w", crbName, err)
	}

	log.V(1).Info("Successfully deleted ClusterRoleBinding",
		"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
	return deleteResultDeleted, nil
}

// deleteRoleBinding attempts to delete a role binding if it has a controller reference.
func (r *bindDefinitionReconciler) deleteRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	roleRef, namespace string,
) (deleteResult, error) {
	log := log.FromContext(ctx)

	rb := &rbacv1.RoleBinding{}
	rbName := fmt.Sprintf("%s-%s-%s", bindDef.Spec.TargetName, roleRef, "binding")

	err := r.client.Get(ctx, types.NamespacedName{Name: rbName, Namespace: namespace}, rb)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("RoleBinding not found (already deleted)",
				"bindDefinitionName", bindDef.Name, "namespace", namespace, "roleBindingName", rbName)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Unable to fetch RoleBinding from Kubernetes API",
			"bindDefinitionName", bindDef.Name, "namespace", namespace, "roleBindingName", rbName)
		return 0, fmt.Errorf("get RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	if !metav1.IsControlledBy(rb, bindDef) {
		r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Deletion",
			"Not deleting target resource RoleBinding/%s in namespace %s because we do not have OwnerRef",
			rbName, namespace)
		log.V(1).Info("Cannot delete RoleBinding - no OwnerRef",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		return deleteResultNoOwnerRef, nil
	}

	r.recorder.Eventf(bindDef, corev1.EventTypeWarning, "Deletion",
		"Deleting target resource RoleBinding/%s in namespace %s", rbName, namespace)
	log.V(1).Info("Cleanup RoleBinding",
		"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)

	if err = r.client.Delete(ctx, rb); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("RoleBinding already deleted during deletion attempt",
				"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
			return deleteResultNotFound, nil
		}
		log.Error(err, "Failed to delete RoleBinding",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		return 0, fmt.Errorf("delete RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	log.V(1).Info("Successfully deleted RoleBinding",
		"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
	return deleteResultDeleted, nil
}

// buildBindingName constructs a binding name from target name and role ref.
func buildBindingName(targetName, roleRef string) string {
	return fmt.Sprintf("%s-%s-%s", targetName, roleRef, "binding")
}

// filterActiveNamespaces returns namespaces that are not in terminating phase.
func (r *bindDefinitionReconciler) filterActiveNamespaces(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespaceSet map[string]corev1.Namespace,
) []corev1.Namespace {
	log := log.FromContext(ctx)
	activeNamespaces := []corev1.Namespace{}

	for _, ns := range namespaceSet {
		if ns.Status.Phase != corev1.NamespaceTerminating {
			activeNamespaces = append(activeNamespaces, ns)
		} else {
			log.V(1).Info("Skipping update in terminating namespace",
				"bindDefinitionName", bindDef.Name, "namespace", ns.Name)
			nsObj := &corev1.Namespace{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
				r.recorder.Eventf(nsObj, corev1.EventTypeWarning, "DeletionPending",
					"Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
			}
		}
	}
	return activeNamespaces
}

// createServiceAccountResult represents the outcome of creating service accounts.
type createServiceAccountResult struct {
	generatedSAs []rbacv1.Subject
	err          error
}

// createServiceAccounts creates ServiceAccount resources for subjects of kind ServiceAccount.
func (r *bindDefinitionReconciler) createServiceAccounts(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) createServiceAccountResult {
	log := log.FromContext(ctx)
	saSubjects := []rbacv1.Subject{}
	automountToken := true

	for _, subject := range bindDef.Spec.Subjects {
		if subject.Kind != authnv1alpha1.BindSubjectServiceAccount {
			continue
		}

		// Check if namespace exists and is not terminating
		saNamespace := &corev1.Namespace{}
		err := r.client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.V(2).Info("ServiceAccount target namespace not found",
					"bindDefinitionName", bindDef.Name, "namespace", subject.Namespace)
				continue
			}
			return createServiceAccountResult{err: fmt.Errorf("get namespace %s: %w", subject.Namespace, err)}
		}
		if saNamespace.Status.Phase == corev1.NamespaceTerminating {
			log.V(1).Info("Skipping ServiceAccount creation in terminating namespace",
				"bindDefinitionName", bindDef.Name, "namespace", subject.Namespace)
			r.recorder.Eventf(saNamespace, corev1.EventTypeWarning, "DeletionPending",
				"Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
			continue
		}

		// Check if ServiceAccount already exists
		sa := &corev1.ServiceAccount{}
		err = r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
		if err == nil {
			log.V(3).Info("ServiceAccount already exists",
				"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name)
			continue
		}
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch ServiceAccount",
				"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name)
			conditions.MarkFalse(bindDef, authnv1alpha1.CreateCondition, bindDef.Generation,
				authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
			return createServiceAccountResult{err: fmt.Errorf("get ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)}
		}

		// Create new ServiceAccount
		sa = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      subject.Name,
				Namespace: subject.Namespace,
				Labels:    buildResourceLabels(bindDef.Labels),
			},
			AutomountServiceAccountToken: &automountToken,
		}
		if err := controllerutil.SetControllerReference(bindDef, sa, r.scheme); err != nil {
			log.Error(err, "unable to set controller reference",
				"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name)
			conditions.MarkFalse(bindDef, authnv1alpha1.OwnerRefCondition, bindDef.Generation,
				authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
			return createServiceAccountResult{err: fmt.Errorf("set controller reference for ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)}
		}
		if err := r.client.Create(ctx, sa); err != nil {
			log.Error(err, "Failed to create ServiceAccount",
				"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name)
			return createServiceAccountResult{err: fmt.Errorf("create ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)}
		}
		log.V(1).Info("Created ServiceAccount",
			"bindDefinitionName", bindDef.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
		r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Create",
			"Created resource %s/%s in namespace %s", sa.Kind, sa.Name, sa.Namespace)

		if !helpers.SubjectExists(bindDef.Status.GeneratedServiceAccounts, subject) {
			saSubjects = append(saSubjects, subject)
		}
		bindDef.Status.GeneratedServiceAccounts = helpers.MergeSubjects(
			bindDef.Status.GeneratedServiceAccounts, saSubjects)
		if err := r.client.Status().Update(ctx, bindDef); err != nil {
			log.Error(err, "Failed to update BindDefinition status",
				"bindDefinitionName", bindDef.Name)
			return createServiceAccountResult{err: fmt.Errorf("update BindDefinition status after ServiceAccount creation: %w", err)}
		}
	}
	return createServiceAccountResult{generatedSAs: saSubjects}
}

// createClusterRoleBindings creates ClusterRoleBinding resources.
func (r *bindDefinitionReconciler) createClusterRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)

	for _, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		crbName := buildBindingName(bindDef.Spec.TargetName, clusterRoleRef)

		// Check if it already exists
		crb := &rbacv1.ClusterRoleBinding{}
		err := r.client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
		if err == nil {
			log.V(3).Info("ClusterRoleBinding already exists",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			continue
		}
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch ClusterRoleBinding",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			conditions.MarkFalse(bindDef, authnv1alpha1.CreateCondition, bindDef.Generation,
				authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
			return fmt.Errorf("get ClusterRoleBinding %s: %w", crbName, err)
		}

		// Create new ClusterRoleBinding
		crb = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: buildResourceLabels(bindDef.Labels),
			},
			Subjects: bindDef.Spec.Subjects,
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRoleRef,
			},
		}
		if err := controllerutil.SetControllerReference(bindDef, crb, r.scheme); err != nil {
			log.Error(err, "unable to set controller reference",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			conditions.MarkFalse(bindDef, authnv1alpha1.OwnerRefCondition, bindDef.Generation,
				authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
			return fmt.Errorf("set controller reference for ClusterRoleBinding %s: %w", crbName, err)
		}
		if err := r.client.Create(ctx, crb); err != nil {
			log.Error(err, "Failed to create ClusterRoleBinding",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			return fmt.Errorf("create ClusterRoleBinding %s: %w", crbName, err)
		}
		log.V(1).Info("Created ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Create",
			"Created resource %s/%s", crb.Kind, crb.Name)
	}
	return nil
}

// createRoleBindings creates RoleBinding resources based on each roleBinding's namespace criteria.
// Each roleBinding in the spec has its own namespaceSelector or explicit namespace.
func (r *bindDefinitionReconciler) createRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	_ []corev1.Namespace, // Kept for API compatibility but not used - we resolve per roleBinding
) error {
	log := log.FromContext(ctx)

	for _, roleBinding := range bindDef.Spec.RoleBindings {
		// Resolve namespaces for this specific roleBinding
		targetNamespaces, err := r.resolveRoleBindingNamespaces(ctx, roleBinding)
		if err != nil {
			return fmt.Errorf("resolve namespaces for roleBinding: %w", err)
		}

		for _, ns := range targetNamespaces {
			// Skip terminating namespaces
			if ns.Status.Phase == corev1.NamespaceTerminating {
				log.V(1).Info("Skipping RoleBinding creation in terminating namespace",
					"bindDefinitionName", bindDef.Name, "namespace", ns.Name)
				continue
			}

			// Create RoleBindings for ClusterRoleRefs
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.createSingleRoleBinding(ctx, bindDef, ns.Name, clusterRoleRef, "ClusterRole"); err != nil {
					return fmt.Errorf("create RoleBinding for ClusterRole %s in namespace %s: %w", clusterRoleRef, ns.Name, err)
				}
			}
			// Create RoleBindings for RoleRefs
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.createSingleRoleBinding(ctx, bindDef, ns.Name, roleRef, "Role"); err != nil {
					return fmt.Errorf("create RoleBinding for Role %s in namespace %s: %w", roleRef, ns.Name, err)
				}
			}
		}
	}
	log.V(2).Info("RoleBindings creation completed", "bindDefinitionName", bindDef.Name)
	return nil
}

// resolveRoleBindingNamespaces returns the namespaces that match the roleBinding's selection criteria.
func (r *bindDefinitionReconciler) resolveRoleBindingNamespaces(
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

// createSingleRoleBinding creates a single RoleBinding resource.
func (r *bindDefinitionReconciler) createSingleRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespace, roleRef, roleKind string,
) error {
	log := log.FromContext(ctx)
	rbName := buildBindingName(bindDef.Spec.TargetName, roleRef)

	// Check if it already exists
	rb := &rbacv1.RoleBinding{}
	err := r.client.Get(ctx, types.NamespacedName{Name: rbName, Namespace: namespace}, rb)
	if err == nil {
		return nil // Already exists
	}
	if !apierrors.IsNotFound(err) {
		log.Error(err, "unable to fetch RoleBinding",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName)
		conditions.MarkFalse(bindDef, authnv1alpha1.CreateCondition, bindDef.Generation,
			authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
		logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
		return fmt.Errorf("get RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	// Create new RoleBinding
	rb = &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: namespace,
			Labels:    buildResourceLabels(bindDef.Labels),
		},
		Subjects: bindDef.Spec.Subjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     roleKind,
			Name:     roleRef,
		},
	}
	if err := controllerutil.SetControllerReference(bindDef, rb, r.scheme); err != nil {
		log.Error(err, "unable to set controller reference",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName)
		conditions.MarkFalse(bindDef, authnv1alpha1.OwnerRefCondition, bindDef.Generation,
			authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
		logStatusUpdateError(ctx, r.client.Status().Update(ctx, bindDef), bindDef.Name)
		return fmt.Errorf("set controller reference for RoleBinding %s/%s: %w", namespace, rbName, err)
	}
	if err := r.client.Create(ctx, rb); err != nil {
		return fmt.Errorf("create RoleBinding %s/%s: %w", namespace, rbName, err)
	}
	log.Info("Created", "RoleBinding", rb.Name)
	r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Create",
		"Created resource %s/%s in namespace %s", rb.Kind, rb.Name, rb.Namespace)
	return nil
}

// updateServiceAccounts updates ServiceAccount resources if they differ from expected.
func (r *bindDefinitionReconciler) updateServiceAccounts(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)
	automountToken := true

	for _, subject := range bindDef.Spec.Subjects {
		if subject.Kind != authnv1alpha1.BindSubjectServiceAccount {
			continue
		}

		// Check if namespace exists and is not terminating
		saNamespace := &corev1.Namespace{}
		err := r.client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("Namespace not found", "Namespace", subject.Namespace)
				continue
			}
			log.Error(err, "Unable to fetch Namespace from Kubernetes API")
			return fmt.Errorf("get namespace %s: %w", subject.Namespace, err)
		}
		if saNamespace.Status.Phase == corev1.NamespaceTerminating {
			log.Info("Skipping creation of ServiceAccount in terminating namespace", "Namespace", subject.Namespace)
			continue
		}

		// Construct expected ServiceAccount
		expectedSa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      subject.Name,
				Namespace: subject.Namespace,
				Labels:    buildResourceLabels(bindDef.Labels),
			},
			AutomountServiceAccountToken: &automountToken,
		}
		if err := controllerutil.SetControllerReference(bindDef, expectedSa, r.scheme); err != nil {
			log.Error(err, "Unable to construct Expected SA in reconcile Update function")
			return fmt.Errorf("set controller reference for expected ServiceAccount %s/%s: %w", expectedSa.Namespace, expectedSa.Name, err)
		}

		// Fetch existing ServiceAccount
		existingSa := &corev1.ServiceAccount{}
		err = r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSa)
		if err != nil {
			log.Info("ServiceAccount not found or error", "ServiceAccount", subject.Name, "error", err)
			return fmt.Errorf("get ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
		}

		// Update only if this BindDefinition controls the ServiceAccount
		if metav1.IsControlledBy(existingSa, bindDef) {
			if !helpers.ServiceAccountsEqual(existingSa, expectedSa) {
				existingSa.Labels = expectedSa.Labels
				existingSa.AutomountServiceAccountToken = expectedSa.AutomountServiceAccountToken
				if err := r.client.Update(ctx, existingSa); err != nil {
					log.Error(err, "Could not update resource", "ServiceAccount", existingSa.Name)
					return fmt.Errorf("update ServiceAccount %s/%s: %w", existingSa.Namespace, existingSa.Name, err)
				}
				log.Info("Updated", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
				r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Update",
					"Updated resource %s/%s in namespace %s", existingSa.Kind, existingSa.Name, existingSa.Namespace)
			}
		} else {
			log.Info("We are not owners of the existing ServiceAccount. The targeted ServiceAccount will not be updated")
		}
	}
	return nil
}

// updateClusterRoleBindings updates ClusterRoleBinding resources if they differ from expected.
func (r *bindDefinitionReconciler) updateClusterRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)

	for _, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		crbName := buildBindingName(bindDef.Spec.TargetName, clusterRoleRef)

		// Construct expected ClusterRoleBinding
		expectedCrb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: buildResourceLabels(bindDef.Labels),
			},
			Subjects: bindDef.Spec.Subjects,
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRoleRef,
			},
		}
		if err := controllerutil.SetControllerReference(bindDef, expectedCrb, r.scheme); err != nil {
			log.Error(err, "Unable to set controller reference for ClusterRoleBinding")
			return fmt.Errorf("set controller reference for expected ClusterRoleBinding %s: %w", crbName, err)
		}

		// Fetch existing ClusterRoleBinding
		existingCrb := &rbacv1.ClusterRoleBinding{}
		err := r.client.Get(ctx, types.NamespacedName{Name: crbName}, existingCrb)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// ClusterRoleBinding doesn't exist yet - it will be created by ensureClusterRoleBindings
				log.V(1).Info("ClusterRoleBinding not found, skipping update (will be created by ensure)", "ClusterRoleBinding", crbName)
				continue
			}
			log.Error(err, "Failed to get ClusterRoleBinding", "ClusterRoleBinding", crbName)
			return fmt.Errorf("get ClusterRoleBinding %s: %w", crbName, err)
		}

		// Update only if this BindDefinition controls the ClusterRoleBinding
		if metav1.IsControlledBy(existingCrb, bindDef) {
			if !helpers.ClusterRoleBindsEqual(existingCrb, expectedCrb) {
				existingCrb.Labels = expectedCrb.Labels
				existingCrb.Subjects = expectedCrb.Subjects
				existingCrb.RoleRef = expectedCrb.RoleRef
				if err := r.client.Update(ctx, existingCrb); err != nil {
					log.Error(err, "Could not update resource", "ClusterRoleBinding", existingCrb.Name)
					return fmt.Errorf("update ClusterRoleBinding %s: %w", existingCrb.Name, err)
				}
				log.Info("Updated", "ClusterRoleBinding", existingCrb.Name)
				r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Update",
					"Updated resource %s/%s", existingCrb.Kind, existingCrb.Name)
			}
		} else {
			log.Info("We are not owners of the existing ClusterRoleBinding. The targeted ClusterRoleBinding will not be updated")
		}
	}
	return nil
}

// updateRoleBindings updates RoleBinding resources in the given namespaces.
func (r *bindDefinitionReconciler) updateRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespaces []corev1.Namespace,
) error {
	for _, roleBinding := range bindDef.Spec.RoleBindings {
		for _, ns := range namespaces {
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.updateSingleRoleBinding(ctx, bindDef, ns.Name, clusterRoleRef, "ClusterRole"); err != nil {
					return fmt.Errorf("update RoleBinding for ClusterRole %s in namespace %s: %w", clusterRoleRef, ns.Name, err)
				}
			}
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.updateSingleRoleBinding(ctx, bindDef, ns.Name, roleRef, "Role"); err != nil {
					return fmt.Errorf("update RoleBinding for Role %s in namespace %s: %w", roleRef, ns.Name, err)
				}
			}
		}
	}
	return nil
}

// updateSingleRoleBinding updates a single RoleBinding if it differs from expected.
func (r *bindDefinitionReconciler) updateSingleRoleBinding(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespace, roleRef, roleKind string,
) error {
	log := log.FromContext(ctx)
	rbName := buildBindingName(bindDef.Spec.TargetName, roleRef)

	// Construct expected RoleBinding
	expectedRb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: namespace,
			Labels:    buildResourceLabels(bindDef.Labels),
		},
		Subjects: bindDef.Spec.Subjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     roleKind,
			Name:     roleRef,
		},
	}
	if err := controllerutil.SetControllerReference(bindDef, expectedRb, r.scheme); err != nil {
		log.Error(err, "Unable to set controller reference for RoleBinding")
		return fmt.Errorf("set controller reference for expected RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	// Fetch existing RoleBinding
	existingRb := &rbacv1.RoleBinding{}
	err := r.client.Get(ctx, types.NamespacedName{Name: rbName, Namespace: namespace}, existingRb)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// RoleBinding doesn't exist yet - it will be created by ensureRoleBindings
			log.V(1).Info("RoleBinding not found, skipping update (will be created by ensure)", "RoleBinding", rbName, "namespace", namespace)
			return nil
		}
		log.Error(err, "Failed to get RoleBinding", "RoleBinding", rbName, "namespace", namespace)
		return fmt.Errorf("get RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	// Update only if this BindDefinition controls the RoleBinding
	if metav1.IsControlledBy(existingRb, bindDef) {
		if !helpers.RoleBindsEqual(existingRb, expectedRb) {
			existingRb.Labels = expectedRb.Labels
			existingRb.Subjects = expectedRb.Subjects
			existingRb.RoleRef = expectedRb.RoleRef
			if err := r.client.Update(ctx, existingRb); err != nil {
				log.Error(err, "Could not update resource", "RoleBinding", existingRb.Name)
				return fmt.Errorf("update RoleBinding %s/%s: %w", namespace, existingRb.Name, err)
			}
			log.Info("Updated", "RoleBinding", existingRb.Name)
			r.recorder.Eventf(bindDef, corev1.EventTypeNormal, "Update",
				"Updated resource %s/%s in namespace %s", existingRb.Kind, existingRb.Name, existingRb.Namespace)
		}
	} else {
		log.Info("We are not owners of the existing RoleBinding. The targeted RoleBinding will not be updated")
	}
	return nil
}
