package authorization

import (
	"context"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	conditions "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/conditions"
	helpers "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/helpers"
)

// BindDefinitionReconciler defines the reconciler for BindDefinition and reconciles a BindDefinition object.
type BindDefinitionReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for namespace creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of namespace, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller
func (r *BindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authnv1alpha1.BindDefinition{}).
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToBindDefinitionRequests),
			builder.WithPredicates(predicate.Funcs{DeleteFunc: func(e event.DeleteEvent) bool { return false }})).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;delete;deletecollection;get;list;patch;update;watch
func (r *BindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetching the RoleDefinition custom resource from Kubernetes API
	bindDefinition := &authnv1alpha1.BindDefinition{}
	err := r.Get(ctx, req.NamespacedName, bindDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		} else {
			log.Error(err, "Unable to fetch BindDefinition resource from Kubernetes API")
			return ctrl.Result{}, err
		}
	}

	// Check if controller should reconcile BindDefinition delete
	resultDelete, err := r.reconcileDelete(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Error occurred in reconcileDelete function")
		return resultDelete, err
	}

	// Check if controller should reconcile BindDefinition create
	resultCreate, err := r.reconcileCreate(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Error occurred in reconcileCreate function")
		return resultCreate, err
	}

	// Check if controller should reconcile BindDefinition update
	resultUpdate, err := r.reconcileUpdate(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Error occurred in reconcileUpdate function")
		return resultUpdate, err
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *BindDefinitionReconciler) reconcileDelete(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Check if RoleDefinition is marked to be deleted
	if bindDefinition.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer) {
			controllerutil.AddFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
			if err := r.Update(ctx, bindDefinition); err != nil {
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Finalizer", "Adding finalizer to BindDefinition %s", bindDefinition.Name)
		}
		conditions.MarkTrue(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		if err := r.Status().Update(ctx, bindDefinition); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// RoleDefinition is marked to be deleted
		log.Info("Deleting generated ClusterRoleBindings/RoleBindings for the BindDefinition, as it is marked for deletion")
		conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		err := r.Status().Update(ctx, bindDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		if controllerutil.ContainsFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer) {
			// Delete generated ClusterRoleBindings
			for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
				clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
				clusterRoleBindingName := bindDefinition.Spec.TargetName + clusterRoleRef.Name + "-binding"
				err := r.Client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						continue
					}
					log.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API")
				}
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s", clusterRoleRef.Kind, clusterRoleBindingName)
				err = r.Client.Delete(ctx, clusterRoleBinding)
				if err != nil {
					conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
			}
			// Construct namespace list from bindDefinition namespace selectors
			namespaceList := &corev1.NamespaceList{}
			listOpts := []client.ListOption{}
			if !reflect.DeepEqual(bindDefinition.Spec.RoleBindings.NamespaceSelector, metav1.LabelSelector{}) {
				selector, err := metav1.LabelSelectorAsSelector(&bindDefinition.Spec.RoleBindings.NamespaceSelector)
				if err != nil {
					return ctrl.Result{}, err
				}
				listOpts = append(listOpts, &client.ListOptions{LabelSelector: selector})
			}
			err := r.Client.List(ctx, namespaceList, listOpts...)
			if err != nil {
				return ctrl.Result{}, err
			}
			// For each namespace
			for _, ns := range namespaceList.Items {
				// Delete RoleBindings for ClusterRoleRefs
				for _, clusterRoleRef := range bindDefinition.Spec.RoleBindings.ClusterRoleRefs {
					roleBinding := &rbacv1.RoleBinding{}
					roleBindingName := bindDefinition.Spec.TargetName + clusterRoleRef.Name + "-binding"
					err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						}
						log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					}
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s in namespace %s", clusterRoleRef.Kind, roleBindingName, ns.Name)
					err = r.Client.Delete(ctx, roleBinding)
					if err != nil {
						conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
				// Delete RoleBindings for RoleRefs
				for _, roleRef := range bindDefinition.Spec.RoleBindings.RoleRefs {
					roleBinding := &rbacv1.RoleBinding{}
					roleBindingName := bindDefinition.Spec.TargetName + roleRef.Name + "-binding"
					err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						}
						log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					}
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s in namespace %s", roleRef.Kind, roleBindingName, ns.Name)
					err = r.Client.Delete(ctx, roleBinding)
					if err != nil {
						conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
			}
			// Delete ServiceAccounts specified in Subjects
			for _, subject := range bindDefinition.Spec.Subjects {
				if subject.Kind == "ServiceAccount" {
					sa := &corev1.ServiceAccount{}
					err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						} else {
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					}
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s in namespace %s", subject.Kind, subject.Name, subject.Namespace)
					err = r.Client.Delete(ctx, sa)
					if err != nil {
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
			}

			controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.Update(ctx, bindDefinition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		err = r.Status().Update(ctx, bindDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

// Reconcile BindDefinition method
func (r *BindDefinitionReconciler) reconcileCreate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	saSubjects := []rbacv1.Subject{}
	automountToken := true
	// Create ServiceAccount resources
	for _, subject := range bindDefinition.Spec.Subjects {
		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			sa := &corev1.ServiceAccount{}
			err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
			if err != nil {
				if apierrors.IsNotFound(err) {
					sa = &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      subject.Name,
							Namespace: subject.Namespace,
							Labels:    bindDefinition.ObjectMeta.Labels,
						},
						AutomountServiceAccountToken: &automountToken,
					}
					if err := controllerutil.SetControllerReference(bindDefinition, sa, r.Scheme); err != nil {
						conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "ServiceAccount", sa.Name, "Namespace", sa.Namespace)
					if err := r.Client.Create(ctx, sa); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "ServiceAccount", sa.Name, "Namespace", sa.Namespace)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s %s in namespace %s", subject.Kind, subject.Name, subject.Namespace)
				}
			}
			if !helpers.SubjectExists(bindDefinition.Status.GeneratedServiceAccounts, subject) {
				saSubjects = append(saSubjects, subject)
			}

		}
	}
	// Update GeneratedServiceAccounts status
	bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(bindDefinition.Status.GeneratedServiceAccounts, saSubjects)
	err := r.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create ClusterRoleBinding resources
	for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		clusterRoleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
		err := r.Client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				clusterRoleBinding := &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:   clusterRoleBindingName,
						Labels: bindDefinition.ObjectMeta.Labels,
					},
					Subjects: bindDefinition.Spec.Subjects,
					RoleRef:  clusterRoleRef,
				}
				if err := controllerutil.SetControllerReference(bindDefinition, clusterRoleBinding, r.Scheme); err != nil {
					conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
				log.Info("Set OwnerRef", "ClusterRoleBinding", clusterRoleBinding.Name)
				if err := r.Client.Create(ctx, clusterRoleBinding); err != nil {
					return ctrl.Result{}, err
				}
				log.Info("Created", "ClusterRoleBinding", clusterRoleBinding.Name)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s %s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			}
		}
	}

	// Construct namespace list from bindDefinition namespace selectors
	namespaceList := &corev1.NamespaceList{}
	listOpts := []client.ListOption{}
	if !reflect.DeepEqual(bindDefinition.Spec.RoleBindings.NamespaceSelector, metav1.LabelSelector{}) {
		selector, err := metav1.LabelSelectorAsSelector(&bindDefinition.Spec.RoleBindings.NamespaceSelector)
		if err != nil {
			return ctrl.Result{}, err
		}
		listOpts = append(listOpts, &client.ListOptions{LabelSelector: selector})
	}
	err = r.Client.List(ctx, namespaceList, listOpts...)
	if err != nil {
		return ctrl.Result{}, err
	}
	// For each namespace
	for _, ns := range namespaceList.Items {
		for _, clusterRoleRef := range bindDefinition.Spec.RoleBindings.ClusterRoleRefs {
			roleBinding := &rbacv1.RoleBinding{}
			roleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					roleBinding := &rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:      roleBindingName,
							Namespace: ns.Name,
							Labels:    bindDefinition.ObjectMeta.Labels,
						},
						Subjects: bindDefinition.Spec.Subjects,
						RoleRef:  clusterRoleRef,
					}
					if err := controllerutil.SetControllerReference(bindDefinition, roleBinding, r.Scheme); err != nil {
						conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "RoleBinding", roleBinding.Name)
					if err := r.Client.Create(ctx, roleBinding); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "ClusterRoleBinding", roleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s %s", roleBinding.Kind, roleBinding.Name)
				}
			}
		}
		for _, roleRef := range bindDefinition.Spec.RoleBindings.RoleRefs {
			roleBinding := &rbacv1.RoleBinding{}
			roleBindingName := bindDefinition.Spec.TargetName + "-" + roleRef.Name + "-binding"
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					roleBinding := &rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:      roleBindingName,
							Namespace: ns.Name,
							Labels:    bindDefinition.ObjectMeta.Labels,
						},
						Subjects: bindDefinition.Spec.Subjects,
						RoleRef:  roleRef,
					}
					if err := controllerutil.SetControllerReference(bindDefinition, roleBinding, r.Scheme); err != nil {
						conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "RoleBinding", roleBinding.Name)
					if err := r.Client.Create(ctx, roleBinding); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "ClusterRoleBinding", roleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s %s", roleBinding.Kind, roleBinding.Name)
				}
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *BindDefinitionReconciler) reconcileUpdate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	automountToken := true
	// Update ServiceAccount resources
	for _, subject := range bindDefinition.Spec.Subjects {
		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			existingSa := &corev1.ServiceAccount{}
			expectedSa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      subject.Name,
					Namespace: subject.Namespace,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				AutomountServiceAccountToken: &automountToken,
			}
			err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSa)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Missing", "ServiceAccount", subject.Name, "Namespace", subject.Namespace)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unexpected Error occurred in update function when reconciling", "ServiceAccount", subject.Name, "Namespace", subject.Namespace)
					return ctrl.Result{}, err
				}
			}
			if !helpers.ServiceAccountsEqual(existingSa, expectedSa) {
				existingSa.Labels = expectedSa.Labels
				existingSa.Annotations = expectedSa.Annotations
				existingSa.AutomountServiceAccountToken = expectedSa.AutomountServiceAccountToken
				if !controllerutil.HasControllerReference(existingSa) {
					if err := controllerutil.SetControllerReference(bindDefinition, existingSa, r.Scheme); err != nil {
						log.Error(err, "Could not set controller reference", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
				}
				if err := r.Client.Update(ctx, existingSa); err != nil {
					log.Error(err, "Could not update resource", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
					return ctrl.Result{}, err
				}
				log.Info("Updated", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s %s in namespace %s", existingSa.Kind, existingSa.Name, existingSa.Namespace)
			}
		}
	}

	// Update ClusterRoleBinding resources
	for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
		existingClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		expectedClusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   clusterRoleBindingName,
				Labels: bindDefinition.ObjectMeta.Labels,
			},
			Subjects: bindDefinition.Spec.Subjects,
			RoleRef:  clusterRoleRef,
		}

		err := r.Client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, existingClusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("Missing", "ClusterRoleBinding", clusterRoleBindingName)
				return ctrl.Result{}, err
			} else {
				log.Error(err, "Unexpected Error occurred in update function when reconciling", "ClusterRoleBinding", clusterRoleBindingName)
				return ctrl.Result{}, err
			}
		}

		if !helpers.ClusterRoleBindsEqual(existingClusterRoleBinding, expectedClusterRoleBinding) {
			existingClusterRoleBinding.Labels = expectedClusterRoleBinding.Labels
			existingClusterRoleBinding.Annotations = expectedClusterRoleBinding.Annotations
			existingClusterRoleBinding.Subjects = expectedClusterRoleBinding.Subjects
			existingClusterRoleBinding.RoleRef = expectedClusterRoleBinding.RoleRef

			if !controllerutil.HasControllerReference(existingClusterRoleBinding) {
				if err := controllerutil.SetControllerReference(bindDefinition, existingClusterRoleBinding, r.Scheme); err != nil {
					log.Error(err, "Could not set controller reference", "ClusterRoleBinding", existingClusterRoleBinding.Name)
					return ctrl.Result{}, err
				}
				log.Info("Set OwnerRef", "ClusterRoleBinding", existingClusterRoleBinding.Name)
			}
			if err := r.Client.Update(ctx, existingClusterRoleBinding); err != nil {
				log.Error(err, "Could not update resource", "ClusterRoleBinding", existingClusterRoleBinding.Name)
				return ctrl.Result{}, err
			}
			log.Info("Updated", "ClusterRoleBinding", existingClusterRoleBinding.Name)
			r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s %s", existingClusterRoleBinding.Kind, existingClusterRoleBinding.Name)

		}
	}

	// Construct namespace list from bindDefinition namespace selectors
	namespaceList := &corev1.NamespaceList{}
	listOpts := []client.ListOption{}
	if !reflect.DeepEqual(bindDefinition.Spec.RoleBindings.NamespaceSelector, metav1.LabelSelector{}) {
		selector, err := metav1.LabelSelectorAsSelector(&bindDefinition.Spec.RoleBindings.NamespaceSelector)
		if err != nil {
			return ctrl.Result{}, err
		}
		listOpts = append(listOpts, &client.ListOptions{LabelSelector: selector})
	}
	err := r.Client.List(ctx, namespaceList, listOpts...)
	if err != nil {
		return ctrl.Result{}, err
	}

	// For each namespace
	for _, ns := range namespaceList.Items {
		for _, clusterRoleRef := range bindDefinition.Spec.RoleBindings.ClusterRoleRefs {
			roleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
			existingRoleBinding := &rbacv1.RoleBinding{}
			expectedRoleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleBindingName,
					Namespace: ns.Name,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				Subjects: bindDefinition.Spec.Subjects,
				RoleRef:  clusterRoleRef,
			}
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Missing", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unexpected Error occurred in update function when reconciling", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				}
			}
			if !helpers.RoleBindsEqual(existingRoleBinding, expectedRoleBinding) {
				existingRoleBinding.Labels = expectedRoleBinding.Labels
				existingRoleBinding.Annotations = expectedRoleBinding.Annotations
				existingRoleBinding.Subjects = expectedRoleBinding.Subjects
				existingRoleBinding.RoleRef = expectedRoleBinding.RoleRef
				if !controllerutil.HasControllerReference(existingRoleBinding) {
					if err := controllerutil.SetControllerReference(bindDefinition, existingRoleBinding, r.Scheme); err != nil {
						log.Error(err, "Could not set controller reference", "RoleBinding", existingRoleBinding.Name)
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "RoleBinding", existingRoleBinding.Name)
				}

				if err := r.Client.Update(ctx, existingRoleBinding); err != nil {
					log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
					return ctrl.Result{}, err
				}
				log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s %s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
			}
		}
		for _, roleRef := range bindDefinition.Spec.RoleBindings.RoleRefs {
			roleBindingName := bindDefinition.Spec.TargetName + "-" + roleRef.Name + "-binding"
			existingRoleBinding := &rbacv1.RoleBinding{}
			expectedRoleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleBindingName,
					Namespace: ns.Name,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				Subjects: bindDefinition.Spec.Subjects,
				RoleRef:  roleRef,
			}
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Missing", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unexpected Error occurred in update function when reconciling", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				}
			}
			if !helpers.RoleBindsEqual(existingRoleBinding, expectedRoleBinding) {
				existingRoleBinding.Labels = expectedRoleBinding.Labels
				existingRoleBinding.Annotations = expectedRoleBinding.Annotations
				existingRoleBinding.Subjects = expectedRoleBinding.Subjects
				existingRoleBinding.RoleRef = expectedRoleBinding.RoleRef
				if !controllerutil.HasControllerReference(existingRoleBinding) {
					if err := controllerutil.SetControllerReference(bindDefinition, existingRoleBinding, r.Scheme); err != nil {
						log.Error(err, "Could not set controller reference", "RoleBinding", existingRoleBinding.Name)
						return ctrl.Result{}, err
					}
					log.Info("Set OwnerRef", "RoleBinding", existingRoleBinding.Name)
				}
				if err := r.Client.Update(ctx, existingRoleBinding); err != nil {
					log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
					return ctrl.Result{}, err
				}
				log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s %s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
			}
		}
	}

	return ctrl.Result{}, nil
}

// namespaceToBindDefinitionRequests() implements the MapFunc type and makes it possible to return an EventHandler
// for any object implementing client.Object. Used it to fan-out updates to all RoleDefinitions on new CRD create
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#EnqueueRequestsFromMapFunc
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#MapFunc
func (r *BindDefinitionReconciler) namespaceToBindDefinitionRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	// Type assertion to ensure obj is a CRD
	_, ok := obj.(*corev1.Namespace)
	if !ok {
		log.FromContext(ctx).Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", obj)
		return nil
	}

	// List all RoleDefinition resources
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.Client.List(ctx, bindDefList)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to list BindDefinition resources")
		return nil
	}
	requests := make([]reconcile.Request, len(bindDefList.Items))
	for i, bindDef := range bindDefList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      bindDef.Name,
				Namespace: bindDef.Namespace,
			},
		}
	}
	return requests
}
