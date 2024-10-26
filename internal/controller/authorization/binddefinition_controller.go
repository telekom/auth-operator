package authorization

import (
	"context"
	"fmt"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
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

// For checking if terminating namespace has deleting resources
// Needed for RoleBinding finalizer removal
func (r *BindDefinitionReconciler) namespaceHasResources(ctx context.Context, namespace string) (bool, error) {
	// List all resource types you want to check
	// Currently: Pods, Deployments, Services

	// Check for Pods
	podList := &corev1.PodList{}
	err := r.Client.List(ctx, podList, client.InNamespace(namespace))
	if err != nil {
		return false, err
	}
	if len(podList.Items) > 0 {
		return true, nil
	}
	// Check for Deployments
	deploymentList := &appsv1.DeploymentList{}
	err = r.Client.List(ctx, deploymentList, client.InNamespace(namespace))
	if err != nil {
		return false, err
	}
	if len(deploymentList.Items) > 0 {
		return true, nil
	}
	// Check for Services
	serviceList := &corev1.ServiceList{}
	err = r.Client.List(ctx, serviceList, client.InNamespace(namespace))
	if err != nil {
		return false, err
	}
	if len(serviceList.Items) > 0 {
		return true, nil
	}

	// Add checks for other resource types as needed

	// No resources found
	return false, nil
}

// For checking if terminating BindDefinition refers a ServiceAccount
// that other non-terminating BindDefinitions reference
func (r *BindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
	// List all BindDefinitions
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.Client.List(ctx, bindDefList)
	if err != nil {
		return false, err
	}
	for _, bindDef := range bindDefList.Items {
		if bindDef.Name == currentBindDefName {
			// Skip the BindDefinition that's being deleted
			continue
		}
		// Check if any of the subjects in this BindDefinition reference the ServiceAccount
		for _, subject := range bindDef.Spec.Subjects {
			if subject.Kind == authnv1alpha1.BindSubjectServiceAccount &&
				subject.Name == saName &&
				subject.Namespace == saNamespace {
				return true, nil
			}
		}
	}
	// No other BindDefinitions reference this ServiceAccount
	return false, nil
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

	// Construct namespace list from BindDefinition namespace selectors
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

	// Handle terminating namespaces and check if they have any resources
	for _, ns := range namespaceList.Items {
		if ns.Status.Phase == corev1.NamespaceTerminating {
			log.Info("Namespace is terminating", "Namespace", ns.Name)

			resourcesExist, err := r.namespaceHasResources(ctx, ns.Name)
			if err != nil {
				log.Error(err, "Failed to check if namespace has resources", "Namespace", ns.Name)
				return ctrl.Result{}, err
			}

			// Handle RoleBinding finalizers for resources in namespace
			if resourcesExist {
				log.Info("Namespace still has resources, will not remove RoleBinding finalizers", "Namespace", ns.Name)
				continue
			} else {
				log.Info("Namespace has no more resources, will remove RoleBinding finalizers", "Namespace", ns.Name)
				roleBindingList := &rbacv1.RoleBindingList{}
				listOpts := []client.ListOption{
					client.InNamespace(ns.Name),
					client.MatchingLabels(bindDefinition.ObjectMeta.Labels),
				}
				err := r.Client.List(ctx, roleBindingList, listOpts...)
				if err != nil {
					log.Error(err, "Failed to list RoleBindings", "Namespace", ns.Name)
					return ctrl.Result{}, err
				}
				for _, roleBinding := range roleBindingList.Items {
					if controllerutil.ContainsFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
						controllerutil.RemoveFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer)
						if err := r.Update(ctx, &roleBinding); err != nil {
							log.Error(err, "Failed to remove finalizer from RoleBinding", "RoleBinding", roleBinding.Name, "Namespace", ns.Name)
							return ctrl.Result{}, err
						}
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "FinalizerRemoved", "Removed finalizer from RoleBinding %s in namespace %s", roleBinding.Name, ns.Name)
					}
				}
			}
		}
	}

	// Check if BindDefinition is marked to be deleted
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
		log.Info("Deleting generated ServiceAccounts, ClusterRoleBindings and RoleBindings for the BindDefinition, as it is marked for deletion")
		conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		err = r.Status().Update(ctx, bindDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		if controllerutil.ContainsFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer) {
			// Delete ServiceAccounts specified in Subjects if we have an OwnerRef for them
			for _, subject := range bindDefinition.Spec.Subjects {
				if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
					sa := &corev1.ServiceAccount{}
					err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						} else {
							log.Error(err, "Unable to fetch ServiceAccount from Kubernetes API")
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					}

					isReferenced, err := r.isSAReferencedByOtherBindDefs(ctx, bindDefinition.Name, sa.Name, sa.Namespace)
					if err != nil {
						return ctrl.Result{}, err
					}

					if !isReferenced {
						if controllerutil.HasControllerReference(sa) {
							r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s/%s in namespace %s", subject.Kind, subject.Name, subject.Namespace)
							err = r.Client.Delete(ctx, sa)
							if err != nil {
								conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
								err = r.Status().Update(ctx, bindDefinition)
								if err != nil {
									return ctrl.Result{}, err
								}
								return ctrl.Result{}, err
							}
						} else {
							r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", subject.Kind, subject.Name, subject.Namespace)
						}
					}
				}
			}

			// Delete generated ClusterRoleBindings
			for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
				clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
				clusterRoleBindingName := bindDefinition.Spec.TargetName + clusterRoleRef.Name + "-binding"
				err := r.Client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						continue
					} else {
						log.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API")
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
				if controllerutil.HasControllerReference(clusterRoleBinding) {
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s %s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
					err = r.Client.Delete(ctx, clusterRoleBinding)
					if err != nil {
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				} else {
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s because we do not have OwnerRef set for it", clusterRoleBinding.Kind, clusterRoleBinding.Name)
				}
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
						} else {
							log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					}
					if controllerutil.HasControllerReference(roleBinding) {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
						err = r.Client.Delete(ctx, roleBinding)
						if err != nil {
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					} else {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
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
						} else {
							log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					}
					if controllerutil.HasControllerReference(roleBinding) {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
						err = r.Client.Delete(ctx, roleBinding)
						if err != nil {
							conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
							err = r.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
					} else {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					}
				}
			}

			conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
			conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
			err = r.Status().Update(ctx, bindDefinition)
			if err != nil {
				return ctrl.Result{}, err
			}

			controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.Update(ctx, bindDefinition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

// Reconcile BindDefinition method
func (r *BindDefinitionReconciler) reconcileCreate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Construct namespace list from BindDefinition namespace selectors
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

	activeNamespaces := []corev1.Namespace{}
	for _, ns := range namespaceList.Items {
		if ns.Status.Phase != corev1.NamespaceTerminating {
			activeNamespaces = append(activeNamespaces, ns)
		} else {
			log.Info("Skipping creation in terminating namespace", "Namespace", ns.Name)
		}
	}

	saSubjects := []rbacv1.Subject{}
	automountToken := true
	// Create ServiceAccount resources
	for _, subject := range bindDefinition.Spec.Subjects {
		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			// Check if subject namespace is existing or terminating, if so skip creation
			saNamespace := &corev1.Namespace{}
			err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Namespace not found", "Namespace", subject.Namespace)
					continue
				} else {
					log.Error(err, "Unable to fetch Namespace from Kubernetes API")
					return ctrl.Result{}, err
				}
			}
			if saNamespace.Status.Phase == corev1.NamespaceTerminating {
				log.Info("Skipping creation of ServiceAccount in terminating namespace", "Namespace", subject.Namespace)
				continue
			}

			sa := &corev1.ServiceAccount{}
			err = r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
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
					if err := r.Client.Create(ctx, sa); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "ServiceAccount", sa.Name, "Namespace", sa.Namespace)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", sa.Kind, sa.Name, sa.Namespace)

					// Append the ServiceAccount subject to the status of BindDefinition
					if !helpers.SubjectExists(bindDefinition.Status.GeneratedServiceAccounts, subject) {
						saSubjects = append(saSubjects, subject)
					}

					// Update GeneratedServiceAccounts status
					bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(bindDefinition.Status.GeneratedServiceAccounts, saSubjects)
					err := r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
				} else {
					log.Error(err, "Unable to fetch ServiceAccount from Kubernetes API")
					conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
			}
		}
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
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			} else {
				log.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API")
				conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
				err = r.Status().Update(ctx, bindDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
		}
	}

	// For each namespace create RoleBinding resources
	for _, ns := range activeNamespaces {
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
					if !controllerutil.AddFinalizer(roleBinding, authnv1alpha1.RoleBindingFinalizer) {
						log.Info("Failed to initialize RoleBinding")
					}
					if err := r.Client.Create(ctx, roleBinding); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "RoleBinding", roleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
				} else {
					log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
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
					if !controllerutil.AddFinalizer(roleBinding, authnv1alpha1.RoleBindingFinalizer) {
						log.Info("Failed to initialize RoleBinding")
					}
					if err := r.Client.Create(ctx, roleBinding); err != nil {
						return ctrl.Result{}, err
					}
					log.Info("Created", "RoleBinding", roleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
				} else {
					log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
			}
		}
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	err = r.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *BindDefinitionReconciler) reconcileUpdate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Construct namespace list from BindDefinition namespace selectors
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

	activeNamespaces := []corev1.Namespace{}
	for _, ns := range namespaceList.Items {
		if ns.Status.Phase != corev1.NamespaceTerminating {
			activeNamespaces = append(activeNamespaces, ns)
		} else {
			log.Info("Skipping creation in terminating namespace", "Namespace", ns.Name)
		}
	}

	automountToken := true
	// Update ServiceAccount resources
	for _, subject := range bindDefinition.Spec.Subjects {
		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			// Check if subject namespace is existing or terminating, if so skip update
			saNamespace := &corev1.Namespace{}
			err := r.Client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Namespace not found", "Namespace", subject.Namespace)
					continue
				} else {
					log.Error(err, "Unable to fetch Namespace from Kubernetes API")
					return ctrl.Result{}, err
				}
			}
			if saNamespace.Status.Phase == corev1.NamespaceTerminating {
				log.Info("Skipping creation of ServiceAccount in terminating namespace", "Namespace", subject.Namespace)
				continue
			}

			existingSa := &corev1.ServiceAccount{}
			// Construct the ServiceAccount we expect
			expectedSa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      subject.Name,
					Namespace: subject.Namespace,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				AutomountServiceAccountToken: &automountToken,
			}
			if err := controllerutil.SetControllerReference(bindDefinition, expectedSa, r.Scheme); err != nil {
				log.Error(err, "Unable to construct an Expected SA in reconcile Update function")
				return ctrl.Result{}, err
			}
			// Fetch the ServiceAccount from the API
			err = r.Client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSa)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("IsNotFound", "ServiceAccount", subject.Name, "Namespace", subject.Namespace)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unable to fetch ServiceAccount from Kubernetes API")
					return ctrl.Result{}, err
				}
			}
			// Check if we are owners of this ServiceAccount
			if controllerutil.HasControllerReference(existingSa) {
				// Compare the ServiceAccount from K8s API and our constructed one
				if !helpers.ServiceAccountsEqual(existingSa, expectedSa) {
					existingSa.Labels = expectedSa.Labels
					existingSa.AutomountServiceAccountToken = expectedSa.AutomountServiceAccountToken
					if err := r.Client.Update(ctx, existingSa); err != nil {
						log.Error(err, "Could not update resource", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
						return ctrl.Result{}, err
					}
					log.Info("Updated", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingSa.Kind, existingSa.Name, existingSa.Namespace)
				}
			} else {
				log.Info("We are not owners of the existing ServiceAccount. The targeted ServiceAccount will not be updated")
			}
		}
	}

	// Update ClusterRoleBinding resources
	for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
		existingClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		// Construct the ClusterRoleBinding we expect
		expectedClusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   clusterRoleBindingName,
				Labels: bindDefinition.ObjectMeta.Labels,
			},
			Subjects: bindDefinition.Spec.Subjects,
			RoleRef:  clusterRoleRef,
		}
		if err := controllerutil.SetControllerReference(bindDefinition, expectedClusterRoleBinding, r.Scheme); err != nil {
			log.Error(err, "Unable to construct an Expected ClusterRoleBinding in reconcile Update function")
		}
		// Fetch the ClusterRoleBinding from the API
		err := r.Client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, existingClusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("IsNotFound", "ClusterRoleBinding", clusterRoleBindingName)
				return ctrl.Result{}, err
			} else {
				log.Error(err, "Unable to fetch ClusterRoleBinding from Kubernetes API")
				return ctrl.Result{}, err
			}
		}
		// Check if we are owners of this ClusterRoleBinding
		if controllerutil.HasControllerReference(existingClusterRoleBinding) {
			if !helpers.ClusterRoleBindsEqual(existingClusterRoleBinding, expectedClusterRoleBinding) {
				existingClusterRoleBinding.Labels = expectedClusterRoleBinding.Labels
				existingClusterRoleBinding.Subjects = expectedClusterRoleBinding.Subjects
				existingClusterRoleBinding.RoleRef = expectedClusterRoleBinding.RoleRef
				if err := r.Client.Update(ctx, existingClusterRoleBinding); err != nil {
					log.Error(err, "Could not update resource", "ClusterRoleBinding", existingClusterRoleBinding.Name)
					return ctrl.Result{}, err
				}
				log.Info("Updated", "ClusterRoleBinding", existingClusterRoleBinding.Name)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s", existingClusterRoleBinding.Kind, existingClusterRoleBinding.Name)
			}
		} else {
			log.Info("We are not owners of the existing ClusterRoleBinding. The targeted ClusterRoleBinding will not be updated")
		}
	}

	// For each namespace
	for _, ns := range activeNamespaces {
		for _, clusterRoleRef := range bindDefinition.Spec.RoleBindings.ClusterRoleRefs {
			roleBindingName := bindDefinition.Spec.TargetName + "-" + clusterRoleRef.Name + "-binding"
			existingRoleBinding := &rbacv1.RoleBinding{}
			// Construct the RoleBinding we expect
			expectedRoleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleBindingName,
					Namespace: ns.Name,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				Subjects: bindDefinition.Spec.Subjects,
				RoleRef:  clusterRoleRef,
			}
			if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.Scheme); err != nil {
				log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
			}
			// Fetch the RoleBinding from the API
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("IsNotFound", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					return ctrl.Result{}, err
				}
			}
			// Check if we are owners of this RoleBinding
			if controllerutil.HasControllerReference(existingRoleBinding) {
				if !helpers.RoleBindsEqual(existingRoleBinding, expectedRoleBinding) {
					existingRoleBinding.Labels = expectedRoleBinding.Labels
					existingRoleBinding.Subjects = expectedRoleBinding.Subjects
					existingRoleBinding.RoleRef = expectedRoleBinding.RoleRef
					if err := r.Client.Update(ctx, existingRoleBinding); err != nil {
						log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
						return ctrl.Result{}, err
					}
					log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
				}
			} else {
				log.Info("We are not owners of the existing RoleBinding. The targeted RoleBinding will not be updated")
			}
		}

		for _, roleRef := range bindDefinition.Spec.RoleBindings.RoleRefs {
			roleBindingName := bindDefinition.Spec.TargetName + "-" + roleRef.Name + "-binding"
			existingRoleBinding := &rbacv1.RoleBinding{}
			// Construct the RoleBinding we expect
			expectedRoleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      roleBindingName,
					Namespace: ns.Name,
					Labels:    bindDefinition.ObjectMeta.Labels,
				},
				Subjects: bindDefinition.Spec.Subjects,
				RoleRef:  roleRef,
			}
			if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.Scheme); err != nil {
				log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
			}
			// Fetch the RoleBinding from the API
			err := r.Client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("IsNotFound", "RoleBinding", roleBindingName)
					return ctrl.Result{}, err
				} else {
					log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
					return ctrl.Result{}, err
				}
			}
			// Check if we are owners of this RoleBinding
			if controllerutil.HasControllerReference(existingRoleBinding) {
				if !helpers.RoleBindsEqual(existingRoleBinding, expectedRoleBinding) {
					existingRoleBinding.Labels = expectedRoleBinding.Labels
					existingRoleBinding.Subjects = expectedRoleBinding.Subjects
					existingRoleBinding.RoleRef = expectedRoleBinding.RoleRef
					if err := r.Client.Update(ctx, existingRoleBinding); err != nil {
						log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
						return ctrl.Result{}, err
					}
					log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
				}
			} else {
				log.Info("We are not owners of the existing RoleBinding. The targeted RoleBinding will not be updated")
			}
		}
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}
