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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	conditions "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/conditions"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/discovery"
	helpers "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/helpers"
)

const (
	// DefaultRequeueInterval is the interval at which resources are requeued
	// to ensure drift from manual modifications is corrected
	DefaultRequeueInterval = 60 * time.Second
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=*
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=*
// +kubebuilder:rbac:groups="coordination.k8s.io",resources=leases,verbs=get;list;update;create;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;delete;deletecollection;get;list;patch;update;watch

// bindDefinitionReconciler defines the reconciler for BindDefinition and reconciles a BindDefinition object.
type bindDefinitionReconciler struct {
	client                client.Client
	scheme                *runtime.Scheme
	roleBindingTerminator *roleBindingTerminator
	recorder              record.EventRecorder
}

func NewBindDefinitionReconciler(
	config *rest.Config,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	resourceTracker *discovery.ResourceTracker,
) (*bindDefinitionReconciler, error) {
	client, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %w", err)
	}
	rbTerminator, err := NewRoleBindingTerminator(config, scheme, recorder, resourceTracker)
	if err != nil {
		return nil, fmt.Errorf("unable to create rolebinding terminator: %w", err)
	}

	return &bindDefinitionReconciler{
		client:                client,
		scheme:                scheme,
		recorder:              recorder,
		roleBindingTerminator: rbTerminator,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for namespace creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of namespace, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller
func (r *bindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	if r.roleBindingTerminator == nil {
		return fmt.Errorf("roleBindingTerminator is nil - use NewBindDefinitionReconciler to create the reconciler")
	}
	if err := r.roleBindingTerminator.SetupWithManager(mgr, concurrency); err != nil {
		return fmt.Errorf("unable to set up RoleBinding terminator: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// control BindDefinitions
		For(&authnv1alpha1.BindDefinition{}).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			MaxConcurrentReconciles: concurrency,
		}).
		// watch namespaces to:
		// - refresh bindings when labels change
		// - remove finalizers of owned resources during termination
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.namespaceToBindDefinitionRequests)).

		// watch RoleBindings and enqueue BindDefinition owner
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &authnv1alpha1.BindDefinition{}, handler.OnlyControllerOwner())).
		Complete(r)
}

// namespaceToBindDefinitionRequests() implements the MapFunc type and makes it possible to return an EventHandler
// for any object implementing client.Object. Used it to fan-out updates to all RoleDefinitions on new CRD create
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#EnqueueRequestsFromMapFunc
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#MapFunc
func (r *bindDefinitionReconciler) namespaceToBindDefinitionRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	logger.V(2).Info("DEBUG: namespaceToBindDefinitionRequests triggered", "objectName", obj.GetName(), "objectNamespace", obj.GetNamespace())

	// Type assertion to ensure obj is a Namespace
	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", reflect.TypeOf(obj))
		return nil
	}

	logger.V(2).Info("DEBUG: Processing namespace event", "namespace", namespace.Name, "phase", namespace.Status.Phase)

	// List all RoleDefinition resources
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.client.List(ctx, bindDefList)
	if err != nil {
		logger.Error(err, "ERROR: Failed to list BindDefinition resources", "namespace", namespace.Name)
		return nil
	}

	logger.V(3).Info("DEBUG: Found BindDefinitions", "namespace", namespace.Name, "bindDefinitionCount", len(bindDefList.Items))

	requests := make([]reconcile.Request, len(bindDefList.Items))
	for i, bindDef := range bindDefList.Items {
		logger.V(3).Info("DEBUG: Enqueuing BindDefinition reconciliation", "namespace", namespace.Name, "bindDefinition", bindDef.Name, "bindDefinitionNamespace", bindDef.Namespace, "index", i)
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      bindDef.Name,
				Namespace: bindDef.Namespace,
			},
		}
	}
	logger.V(2).Info("DEBUG: Returning reconciliation requests", "namespace", namespace.Name, "requestCount", len(requests))
	return requests
}

// For checking if terminating BindDefinition refers a ServiceAccount
// that other non-terminating BindDefinitions reference
func (r *bindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
	// List all BindDefinitions
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.client.List(ctx, bindDefList)
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

func (r *bindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetching the RoleDefinition custom resource from Kubernetes API
	bindDefinition := &authnv1alpha1.BindDefinition{}
	err := r.client.Get(ctx, req.NamespacedName, bindDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		} else {
			log.Error(err, "Unable to fetch BindDefinition resource from Kubernetes API")
			return ctrl.Result{}, err
		}
	}

	// Check if controller should reconcile BindDefinition delete
	if !bindDefinition.DeletionTimestamp.IsZero() {
		resultDelete, err := r.reconcileDelete(ctx, bindDefinition)
		if err != nil {
			log.Error(err, "Error occurred in reconcileDelete function")
			return resultDelete, err
		}
	} else {
		if !controllerutil.ContainsFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer) {
			controllerutil.AddFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
			if err := r.client.Update(ctx, bindDefinition); err != nil {
				return ctrl.Result{}, err
			}
			r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Finalizer", "Adding finalizer to BindDefinition %s", bindDefinition.Name)
		}
		conditions.MarkTrue(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		if err := r.client.Status().Update(ctx, bindDefinition); err != nil {
			return ctrl.Result{}, err
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
	}

	return ctrl.Result{}, nil
}

func (r *bindDefinitionReconciler) reconcileDelete(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting reconcileDelete", "bindDefinition", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// RoleDefinition is marked to be deleted
	log.V(1).Info("DEBUG: BindDefinition marked for deletion - deleting generated ServiceAccounts, ClusterRoleBindings and RoleBindings", "bindDefinitionName", bindDefinition.Name)
	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	err := r.client.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Delete ServiceAccounts specified in Subjects if we have an OwnerRef for them
	log.V(2).Info("DEBUG: Processing subjects for deletion", "bindDefinitionName", bindDefinition.Name, "subjectCount", len(bindDefinition.Spec.Subjects))

	for idx, subject := range bindDefinition.Spec.Subjects {
		log.V(3).Info("DEBUG: Processing subject", "bindDefinitionName", bindDefinition.Name, "index", idx, "kind", subject.Kind, "name", subject.Name, "namespace", subject.Namespace)

		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			sa := &corev1.ServiceAccount{}
			err := r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.V(2).Info("DEBUG: ServiceAccount not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					continue
				} else {
					log.Error(err, "ERROR: Unable to fetch ServiceAccount from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					return ctrl.Result{}, err
				}
			}

			isReferenced, err := r.isSAReferencedByOtherBindDefs(ctx, bindDefinition.Name, sa.Name, sa.Namespace)
			if err != nil {
				log.Error(err, "ERROR: Failed to check if ServiceAccount is referenced by other BindDefinitions", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
				return ctrl.Result{}, err
			}

			if !isReferenced {
				log.V(2).Info("DEBUG: ServiceAccount is not referenced by other BindDefinitions", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)

				if controllerutil.HasControllerReference(sa) {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s/%s in namespace %s", subject.Kind, subject.Name, subject.Namespace)
					log.V(1).Info("DEBUG: Cleanup ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					// Generated service account doesn't have auth-operator finalizer
					err = r.client.Delete(ctx, sa)
					if err != nil {
						if apierrors.IsNotFound(err) {
							log.V(2).Info("DEBUG: ServiceAccount already deleted during deletion attempt", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
							continue
						}
						log.Error(err, "ERROR: Failed to delete ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
						return ctrl.Result{}, err
					}
					log.V(1).Info("DEBUG: Successfully deleted ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
				} else {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", subject.Kind, subject.Name, subject.Namespace)
					log.V(1).Info("DEBUG: Cannot delete ServiceAccount - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
				}
			} else {
				log.V(2).Info("DEBUG: ServiceAccount is referenced by other BindDefinitions - NOT deleting", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
			}
		}
	}

	// Delete generated ClusterRoleBindings
	log.V(2).Info("DEBUG: Processing ClusterRoleBindings for deletion", "bindDefinitionName", bindDefinition.Name, "clusterRoleRefCount", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs))

	for idx, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		clusterRoleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
		log.V(3).Info("DEBUG: Looking up ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "index", idx, "clusterRoleBindingName", clusterRoleBindingName)

		err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.V(2).Info("DEBUG: ClusterRoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				continue
			} else {
				log.Error(err, "ERROR: Unable to fetch ClusterRoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
				errStatus := r.client.Status().Update(ctx, bindDefinition)
				if errStatus != nil {
					return ctrl.Result{}, errStatus
				}
				return ctrl.Result{}, err
			}
		}
		if controllerutil.HasControllerReference(clusterRoleBinding) {
			r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s %s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			log.V(1).Info("DEBUG: Cleanup ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBinding.Name)
			// Generated ClusterRoleBinding doesn't have finalizer, delete is enough
			err = r.client.Delete(ctx, clusterRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.V(2).Info("DEBUG: ClusterRoleBinding already deleted", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
					continue
				}
				log.Error(err, "ERROR: Failed to delete ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				return ctrl.Result{}, err
			}
			log.V(1).Info("DEBUG: Successfully deleted ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
		} else {
			r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s because we do not have OwnerRef set for it", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			log.V(1).Info("DEBUG: Cannot delete ClusterRoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
		}
	}

	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to collect namespaces for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name)
		return ctrl.Result{}, err
	}

	// For each namespace cleanup rolebindings referenced in the BindDefinition
	log.V(2).Info("DEBUG: Processing namespaces for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name, "namespaceCount", len(namespaceSet))
	for nsIdx, ns := range namespaceSet {
		log.V(2).Info("DEBUG: Processing namespace for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "index", nsIdx)

		for rbIdx, roleBinding := range bindDefinition.Spec.RoleBindings {
			log.V(3).Info("DEBUG: Processing RoleBinding spec", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "rbIndex", rbIdx, "clusterRoleRefCount", len(roleBinding.ClusterRoleRefs), "roleRefCount", len(roleBinding.RoleRefs))

			// Delete RoleBindings for ClusterRoleRefs
			for crIdx, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
				log.V(3).Info("DEBUG: Looking up RoleBinding (ClusterRoleRef)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "crIndex", crIdx, "roleBindingName", roleBindingName)

				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						log.V(2).Info("DEBUG: RoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						continue
					} else {
						log.Error(err, "ERROR: Unable to fetch RoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						errStatus := r.client.Status().Update(ctx, bindDefinition)
						if errStatus != nil {
							return ctrl.Result{}, errStatus
						}
						return ctrl.Result{}, err
					}
				}
				if controllerutil.HasControllerReference(roleBinding) {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cleanup RoleBinding based on ClusterRoleRefs", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", roleBinding.Namespace)

					err = r.client.Delete(ctx, roleBinding)
					if err != nil {
						if apierrors.IsNotFound(err) {
							log.V(2).Info("DEBUG: RoleBinding already deleted during deletion attempt", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
							continue
						}
						log.Error(err, "ERROR: Failed to delete RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
						return ctrl.Result{}, err
					}
					log.V(1).Info("DEBUG: Successfully deleted RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				} else {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cannot delete RoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				}
			}
		}

		for _, roleBinding := range bindDefinition.Spec.RoleBindings {
			// Delete RoleBindings for RoleRefs
			for rrIdx, roleRef := range roleBinding.RoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, roleRef, "binding")
				log.V(3).Info("DEBUG: Looking up RoleBinding (RoleRef)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "rrIndex", rrIdx, "roleBindingName", roleBindingName)

				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						log.V(2).Info("DEBUG: RoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						continue
					} else {
						log.Error(err, "ERROR: Unable to fetch RoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						errStatus := r.client.Status().Update(ctx, bindDefinition)
						if errStatus != nil {
							return ctrl.Result{}, errStatus
						}
						return ctrl.Result{}, err
					}
				}
				if controllerutil.HasControllerReference(roleBinding) {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cleanup RoleBinding based on RoleRefs", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", roleBinding.Namespace)

					err = r.client.Delete(ctx, roleBinding)
					if err != nil {
						if apierrors.IsNotFound(err) {
							log.V(2).Info("DEBUG: RoleBinding already deleted during deletion attempt", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
							continue
						}
						log.Error(err, "ERROR: Failed to delete RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
						return ctrl.Result{}, err
					}
					log.V(1).Info("DEBUG: Successfully deleted RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				} else {
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cannot delete RoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				}
			}
		}
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
	err = r.client.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	log.V(2).Info("DEBUG: Removing BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)
	controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
	if err := r.client.Update(ctx, bindDefinition); err != nil {
		log.Error(err, "ERROR: Failed to remove BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)
		return ctrl.Result{}, err
	}
	log.V(1).Info("DEBUG: reconcileDelete completed successfully", "bindDefinitionName", bindDefinition.Name)

	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// Reconcile BindDefinition method
func (r *bindDefinitionReconciler) reconcileCreate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting reconcileCreate", "bindDefinitionName", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Unable to collect namespaces in reconcile Update function")
		return ctrl.Result{}, err
	}

	activeNamespaces := []corev1.Namespace{}
	log.V(2).Info("DEBUG: Filtering terminating namespaces", "bindDefinitionName", bindDefinition.Name, "totalNamespaceCount", len(namespaceSet))

	for _, ns := range namespaceSet {
		if ns.Status.Phase != corev1.NamespaceTerminating {
			log.V(3).Info("DEBUG: Namespace is active - adding to activeNamespaces", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
			activeNamespaces = append(activeNamespaces, ns)
		} else {
			log.V(1).Info("DEBUG: Skipping update in terminating namespace", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
			// Emit event on the namespace to inform users about pending deletions
			nsObj := &corev1.Namespace{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
				r.recorder.Eventf(nsObj, corev1.EventTypeWarning, "DeletionPending", "Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
			}
		}
	}
	log.V(2).Info("DEBUG: Active namespaces count", "bindDefinitionName", bindDefinition.Name, "activeNamespaceCount", len(activeNamespaces))

	saSubjects := []rbacv1.Subject{}
	automountToken := true
	// Create ServiceAccount resources
	log.V(2).Info("DEBUG: Processing subjects for ServiceAccount creation", "bindDefinitionName", bindDefinition.Name, "subjectCount", len(bindDefinition.Spec.Subjects))

	for idx, subject := range bindDefinition.Spec.Subjects {
		log.V(3).Info("DEBUG: Processing subject", "bindDefinitionName", bindDefinition.Name, "index", idx, "kind", subject.Kind, "name", subject.Name, "namespace", subject.Namespace)

		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			// Check if subject namespace is existing or terminating, if so skip creation
			saNamespace := &corev1.Namespace{}
			err := r.client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.V(2).Info("DEBUG: ServiceAccount target namespace not found - skipping ServiceAccount creation", "bindDefinitionName", bindDefinition.Name, "namespace", subject.Namespace)
					continue
				} else {
					log.Error(err, "ERROR: Unable to fetch Namespace from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "namespace", subject.Namespace)
					return ctrl.Result{}, err
				}
			}
			if saNamespace.Status.Phase == corev1.NamespaceTerminating {
				log.V(1).Info("DEBUG: Skipping creation of ServiceAccount in terminating namespace", "bindDefinitionName", bindDefinition.Name, "namespace", subject.Namespace)
				// Emit event on the namespace to inform users about pending deletions
				r.recorder.Eventf(saNamespace, corev1.EventTypeWarning, "DeletionPending", "Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
				continue
			}

			sa := &corev1.ServiceAccount{}
			err = r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.V(2).Info("DEBUG: ServiceAccount not found - creating new one", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)

					sa = &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      subject.Name,
							Namespace: subject.Namespace,
							Labels:    bindDefinition.Labels,
						},
						AutomountServiceAccountToken: &automountToken,
					}
					if err := controllerutil.SetControllerReference(bindDefinition, sa, r.scheme); err != nil {
						log.Error(err, "ERROR: Unable to set controller reference", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
						err = r.client.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
					if err := r.client.Create(ctx, sa); err != nil {
						log.Error(err, "ERROR: Failed to create ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
						return ctrl.Result{}, err
					}
					log.V(1).Info("DEBUG: Created ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", sa.Kind, sa.Name, sa.Namespace)

					// Append the ServiceAccount subject to the status of BindDefinition
					if !helpers.SubjectExists(bindDefinition.Status.GeneratedServiceAccounts, subject) {
						saSubjects = append(saSubjects, subject)
					}

					// Update GeneratedServiceAccounts status
					bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(bindDefinition.Status.GeneratedServiceAccounts, saSubjects)
					err := r.client.Status().Update(ctx, bindDefinition)
					if err != nil {
						log.Error(err, "ERROR: Failed to update BindDefinition status", "bindDefinitionName", bindDefinition.Name)
						return ctrl.Result{}, err
					}
				} else {
					log.Error(err, "ERROR: Unable to fetch ServiceAccount from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
					err = r.client.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
			} else {
				log.V(3).Info("DEBUG: ServiceAccount already exists", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
			}
		}
	}

	// Create ClusterRoleBinding resources
	log.V(2).Info("DEBUG: Processing ClusterRoleBindings for creation", "bindDefinitionName", bindDefinition.Name, "clusterRoleRefCount", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs))

	for idx, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		clusterRoleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
		log.V(3).Info("DEBUG: Checking ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "index", idx, "clusterRoleBindingName", clusterRoleBindingName)

		err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.V(2).Info("DEBUG: ClusterRoleBinding not found - creating new one", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)

				clusterRoleBinding := &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:   clusterRoleBindingName,
						Labels: bindDefinition.Labels,
					},
					Subjects: bindDefinition.Spec.Subjects,
					RoleRef: rbacv1.RoleRef{
						APIGroup: "rbac.authorization.k8s.io",
						Kind:     "ClusterRole",
						Name:     clusterRoleRef,
					},
				}
				if err := controllerutil.SetControllerReference(bindDefinition, clusterRoleBinding, r.scheme); err != nil {
					log.Error(err, "ERROR: Unable to set controller reference", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
					conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
					err = r.client.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
				log.V(2).Info("DEBUG: Set OwnerRef", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				if err := r.client.Create(ctx, clusterRoleBinding); err != nil {
					log.Error(err, "ERROR: Failed to create ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
					return ctrl.Result{}, err
				}
				log.V(1).Info("DEBUG: Created ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			} else {
				log.Error(err, "ERROR: Unable to fetch ClusterRoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
				err = r.client.Status().Update(ctx, bindDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
		} else {
			log.V(3).Info("DEBUG: ClusterRoleBinding already exists", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
		}
	}
	for _, RoleBinding := range bindDefinition.Spec.RoleBindings {

		// For each namespace create RoleBinding resources
		for _, ns := range activeNamespaces {
			for _, clusterRoleRef := range RoleBinding.ClusterRoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						roleBinding := &rbacv1.RoleBinding{
							ObjectMeta: metav1.ObjectMeta{
								Name:      roleBindingName,
								Namespace: ns.Name,
								Labels:    bindDefinition.Labels,
							},
							Subjects: bindDefinition.Spec.Subjects,
							RoleRef: rbacv1.RoleRef{
								APIGroup: "rbac.authorization.k8s.io",
								Kind:     "ClusterRole",
								Name:     clusterRoleRef,
							},
						}
						if err := controllerutil.SetControllerReference(bindDefinition, roleBinding, r.scheme); err != nil {
							conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
							err = r.client.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
						if err := r.client.Create(ctx, roleBinding); err != nil {
							return ctrl.Result{}, err
						}
						log.Info("Created", "RoleBinding", roleBinding.Name)
						r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					} else {
						log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
						conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
						err = r.client.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
			}
			for _, roleRef := range RoleBinding.RoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, roleRef, "binding")
				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						roleBinding := &rbacv1.RoleBinding{
							ObjectMeta: metav1.ObjectMeta{
								Name:      roleBindingName,
								Namespace: ns.Name,
								Labels:    bindDefinition.Labels,
							},
							Subjects: bindDefinition.Spec.Subjects,
							RoleRef: rbacv1.RoleRef{
								APIGroup: "rbac.authorization.k8s.io",
								Kind:     "Role",
								Name:     roleRef,
							},
						}
						if err := controllerutil.SetControllerReference(bindDefinition, roleBinding, r.scheme); err != nil {
							conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
							err = r.client.Status().Update(ctx, bindDefinition)
							if err != nil {
								return ctrl.Result{}, err
							}
							return ctrl.Result{}, err
						}
						if err := r.client.Create(ctx, roleBinding); err != nil {
							return ctrl.Result{}, err
						}
						log.Info("Created", "RoleBinding", roleBinding.Name)
						r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					} else {
						log.Error(err, "Unable to fetch RoleBinding from Kubernetes API")
						conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
						err = r.client.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
				}
			}
		}
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	err = r.client.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

func (r *bindDefinitionReconciler) collectNamespaces(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (map[string]corev1.Namespace, error) {
	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	for _, RoleBinding := range bindDefinition.Spec.RoleBindings {
		for _, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					return nil, err
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.client.List(ctx, namespaceList, listOpts...)
				if err != nil {
					return nil, err
				}
				// Add namespaces to the set
				for _, ns := range namespaceList.Items {
					namespaceSet[ns.Name] = ns
				}
			}
		}
	}

	return namespaceSet, nil
}

func (r *bindDefinitionReconciler) reconcileUpdate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Unable to collect namespaces in reconcile Update function")
		return ctrl.Result{}, err
	}

	activeNamespaces := []corev1.Namespace{}
	for _, ns := range namespaceSet {
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
			err := r.client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
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
					Labels:    bindDefinition.Labels,
				},
				AutomountServiceAccountToken: &automountToken,
			}
			if err := controllerutil.SetControllerReference(bindDefinition, expectedSa, r.scheme); err != nil {
				log.Error(err, "Unable to construct an Expected SA in reconcile Update function")
				return ctrl.Result{}, err
			}
			// Fetch the ServiceAccount from the API
			err = r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSa)
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
					if err := r.client.Update(ctx, existingSa); err != nil {
						log.Error(err, "Could not update resource", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
						return ctrl.Result{}, err
					}
					log.Info("Updated", "ServiceAccount", existingSa.Name, "Namespace", existingSa.Namespace)
					r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingSa.Kind, existingSa.Name, existingSa.Namespace)
				}
			} else {
				log.Info("We are not owners of the existing ServiceAccount. The targeted ServiceAccount will not be updated")
			}
		}
	}

	// Update ClusterRoleBinding resources
	for _, clusterRoleRef := range bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRoleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
		existingClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		// Construct the ClusterRoleBinding we expect
		expectedClusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   clusterRoleBindingName,
				Labels: bindDefinition.Labels,
			},
			Subjects: bindDefinition.Spec.Subjects,
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRoleRef,
			},
		}
		if err := controllerutil.SetControllerReference(bindDefinition, expectedClusterRoleBinding, r.scheme); err != nil {
			log.Error(err, "Unable to construct an Expected ClusterRoleBinding in reconcile Update function")
		}
		// Fetch the ClusterRoleBinding from the API
		err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, existingClusterRoleBinding)
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
				if err := r.client.Update(ctx, existingClusterRoleBinding); err != nil {
					log.Error(err, "Could not update resource", "ClusterRoleBinding", existingClusterRoleBinding.Name)
					return ctrl.Result{}, err
				}
				log.Info("Updated", "ClusterRoleBinding", existingClusterRoleBinding.Name)
				r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s", existingClusterRoleBinding.Kind, existingClusterRoleBinding.Name)
			}
		} else {
			log.Info("We are not owners of the existing ClusterRoleBinding. The targeted ClusterRoleBinding will not be updated")
		}
	}
	for _, RoleBinding := range bindDefinition.Spec.RoleBindings {

		// For each namespace
		for _, ns := range activeNamespaces {
			for _, clusterRoleRef := range RoleBinding.ClusterRoleRefs {
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
				existingRoleBinding := &rbacv1.RoleBinding{}
				// Construct the RoleBinding we expect
				expectedRoleBinding := &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleBindingName,
						Namespace: ns.Name,
						Labels:    bindDefinition.Labels,
					},
					Subjects: bindDefinition.Spec.Subjects,
					RoleRef: rbacv1.RoleRef{
						APIGroup: "rbac.authorization.k8s.io",
						Kind:     "ClusterRole",
						Name:     clusterRoleRef,
					},
				}
				if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.scheme); err != nil {
					log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
				}
				// Fetch the RoleBinding from the API
				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
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
						if err := r.client.Update(ctx, existingRoleBinding); err != nil {
							log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
							return ctrl.Result{}, err
						}
						log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
						r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
					}
				} else {
					log.Info("We are not owners of the existing RoleBinding. The targeted RoleBinding will not be updated")
				}
			}

			for _, roleRef := range RoleBinding.RoleRefs {
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, roleRef, "binding")
				existingRoleBinding := &rbacv1.RoleBinding{}
				// Construct the RoleBinding we expect
				expectedRoleBinding := &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleBindingName,
						Namespace: ns.Name,
						Labels:    bindDefinition.Labels,
					},
					Subjects: bindDefinition.Spec.Subjects,
					RoleRef: rbacv1.RoleRef{
						APIGroup: "rbac.authorization.k8s.io",
						Kind:     "Role",
						Name:     roleRef,
					},
				}
				if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.scheme); err != nil {
					log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
				}
				// Fetch the RoleBinding from the API
				err := r.client.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
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
						if err := r.client.Update(ctx, existingRoleBinding); err != nil {
							log.Error(err, "Could not update resource", "RoleBinding", existingRoleBinding.Name)
							return ctrl.Result{}, err
						}
						log.Info("Updated", "RoleBinding", existingRoleBinding.Name)
						r.recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Update", "Updated resource %s/%s in namespace %s", existingRoleBinding.Kind, existingRoleBinding.Name, existingRoleBinding.Namespace)
					}
				} else {
					log.Info("We are not owners of the existing RoleBinding. The targeted RoleBinding will not be updated")
				}
			}
		}
	}

	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}
