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
)

const (
	// DefaultRequeueInterval is the interval at which resources are requeued
	// to ensure drift from manual modifications is corrected
	DefaultRequeueInterval = 60 * time.Second
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch
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

// NewBindDefinitionReconciler creates a new BindDefinition reconciler.
// Uses the manager's cached client for improved performance.
func NewBindDefinitionReconciler(
	cachedClient client.Client,
	config *rest.Config,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	resourceTracker *discovery.ResourceTracker,
) (*bindDefinitionReconciler, error) {
	rbTerminator, err := NewRoleBindingTerminator(cachedClient, config, scheme, recorder, resourceTracker)
	if err != nil {
		return nil, fmt.Errorf("unable to create rolebinding terminator: %w", err)
	}

	return &bindDefinitionReconciler{
		client:                cachedClient,
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
	logger.V(2).Info("namespaceToBindDefinitionRequests triggered", "objectName", obj.GetName(), "objectNamespace", obj.GetNamespace())

	// Type assertion to ensure obj is a Namespace
	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", reflect.TypeOf(obj))
		return nil
	}

	logger.V(2).Info("processing namespace event", "namespace", namespace.Name, "phase", namespace.Status.Phase)

	// List all RoleDefinition resources
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.client.List(ctx, bindDefList)
	if err != nil {
		logger.Error(err, "failed to list BindDefinition resources", "namespace", namespace.Name)
		return nil
	}

	logger.V(3).Info("found BindDefinitions", "namespace", namespace.Name, "bindDefinitionCount", len(bindDefList.Items))

	requests := make([]reconcile.Request, len(bindDefList.Items))
	for i, bindDef := range bindDefList.Items {
		logger.V(3).Info("enqueuing BindDefinition reconciliation", "namespace", namespace.Name, "bindDefinition", bindDef.Name, "bindDefinitionNamespace", bindDef.Namespace, "index", i)
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      bindDef.Name,
				Namespace: bindDef.Namespace,
			},
		}
	}
	logger.V(2).Info("returning reconciliation requests", "namespace", namespace.Name, "requestCount", len(requests))
	return requests
}

// For checking if terminating BindDefinition refers a ServiceAccount
// that other non-terminating BindDefinitions reference
func (r *bindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
	// List all BindDefinitions
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.client.List(ctx, bindDefList)
	if err != nil {
		return false, fmt.Errorf("list BindDefinitions: %w", err)
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
		return r.reconcileDelete(ctx, bindDefinition)
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

		// Reconcile create path
		resultCreate, err := r.reconcileCreate(ctx, bindDefinition)
		if err != nil {
			log.Error(err, "Error occurred in reconcileCreate function")
			return resultCreate, err
		}

		// Reconcile update path
		resultUpdate, err := r.reconcileUpdate(ctx, bindDefinition)
		if err != nil {
			log.Error(err, "Error occurred in reconcileUpdate function")
			return resultUpdate, err
		}

		// Preserve requeue requests from sub-reconciles
		return mergeReconcileResults(resultCreate, resultUpdate), nil
	}

}

func mergeReconcileResults(results ...ctrl.Result) ctrl.Result {
	merged := ctrl.Result{}
	for _, res := range results {
		if res.RequeueAfter > 0 && (merged.RequeueAfter == 0 || res.RequeueAfter > merged.RequeueAfter) {
			merged.RequeueAfter = res.RequeueAfter
		}
	}
	return merged
}

func (r *bindDefinitionReconciler) reconcileDelete(
	ctx context.Context,
	bindDefinition *authnv1alpha1.BindDefinition,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("starting reconcileDelete",
		"bindDefinition", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// RoleDefinition is marked to be deleted
	log.V(1).Info("BindDefinition marked for deletion - cleaning up resources",
		"bindDefinitionName", bindDefinition.Name)
	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation,
		authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	if err := r.client.Status().Update(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Delete ServiceAccounts
	if err := r.deleteSubjectServiceAccounts(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Delete ClusterRoleBindings
	if err := r.deleteAllClusterRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Delete RoleBindings
	if err := r.deleteAllRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation,
		authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation,
		authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
	if err := r.client.Status().Update(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	log.V(2).Info("removing BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)
	controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
	if err := r.client.Update(ctx, bindDefinition); err != nil {
		log.Error(err, "Failed to remove BindDefinition finalizer",
			"bindDefinitionName", bindDefinition.Name)
		return ctrl.Result{}, err
	}
	log.V(1).Info("reconcileDelete completed successfully", "bindDefinitionName", bindDefinition.Name)

	return ctrl.Result{}, nil
}

// deleteSubjectServiceAccounts deletes service accounts specified in subjects.
func (r *bindDefinitionReconciler) deleteSubjectServiceAccounts(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)
	log.V(2).Info("processing subjects for deletion",
		"bindDefinitionName", bindDef.Name, "subjectCount", len(bindDef.Spec.Subjects))

	for idx, subject := range bindDef.Spec.Subjects {
		log.V(3).Info("processing subject",
			"bindDefinitionName", bindDef.Name, "index", idx,
			"kind", subject.Kind, "name", subject.Name, "namespace", subject.Namespace)

		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			if _, err := r.deleteServiceAccount(ctx, bindDef, subject.Name, subject.Namespace); err != nil {
				return fmt.Errorf("deleteSubjectServiceAccounts: %w", err)
			}
		}
	}
	return nil
}

// deleteAllClusterRoleBindings deletes all ClusterRoleBindings for the BindDefinition.
func (r *bindDefinitionReconciler) deleteAllClusterRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)
	log.V(2).Info("processing ClusterRoleBindings for deletion",
		"bindDefinitionName", bindDef.Name,
		"clusterRoleRefCount", len(bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs))

	for idx, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		log.V(3).Info("looking up ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "index", idx, "clusterRoleRef", clusterRoleRef)

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, clusterRoleRef)
		if err != nil {
			conditions.MarkFalse(bindDef, authnv1alpha1.DeleteCondition, bindDef.Generation,
				authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
			if errStatus := r.client.Status().Update(ctx, bindDef); errStatus != nil {
				return fmt.Errorf("update status after ClusterRoleBinding %s deletion failure: %w", clusterRoleRef, errStatus)
			}
			return fmt.Errorf("deleteAllClusterRoleBindings: %w", err)
		}
		log.V(3).Info("ClusterRoleBinding delete result",
			"bindDefinitionName", bindDef.Name, "clusterRoleRef", clusterRoleRef, "result", result)
	}
	return nil
}

// deleteAllRoleBindings deletes all RoleBindings for the BindDefinition across all matching namespaces.
func (r *bindDefinitionReconciler) deleteAllRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	log := log.FromContext(ctx)

	namespaceSet, err := r.collectNamespaces(ctx, bindDef)
	if err != nil {
		log.Error(err, "failed to collect namespaces for RoleBinding cleanup",
			"bindDefinitionName", bindDef.Name)
		return fmt.Errorf("deleteAllRoleBindings: collect namespaces: %w", err)
	}

	log.V(2).Info("processing namespaces for RoleBinding cleanup",
		"bindDefinitionName", bindDef.Name, "namespaceCount", len(namespaceSet))

	for nsIdx, ns := range namespaceSet {
		log.V(2).Info("processing namespace for RoleBinding cleanup",
			"bindDefinitionName", bindDef.Name, "namespace", ns.Name, "index", nsIdx)

		for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
			log.V(3).Info("processing RoleBinding spec",
				"bindDefinitionName", bindDef.Name, "namespace", ns.Name, "rbIndex", rbIdx)

			// Delete RoleBindings for ClusterRoleRefs
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.deleteRoleBindingWithStatusUpdate(ctx, bindDef, clusterRoleRef, ns.Name); err != nil {
					return fmt.Errorf("deleteAllRoleBindings: namespace %s, clusterRoleRef %s: %w", ns.Name, clusterRoleRef, err)
				}
			}

			// Delete RoleBindings for RoleRefs
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.deleteRoleBindingWithStatusUpdate(ctx, bindDef, roleRef, ns.Name); err != nil {
					return fmt.Errorf("deleteAllRoleBindings: namespace %s, roleRef %s: %w", ns.Name, roleRef, err)
				}
			}
		}
	}
	return nil
}

// deleteRoleBindingWithStatusUpdate deletes a RoleBinding and updates status on error.
func (r *bindDefinitionReconciler) deleteRoleBindingWithStatusUpdate(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	roleRef, namespace string,
) error {
	_, err := r.deleteRoleBinding(ctx, bindDef, roleRef, namespace)
	if err != nil {
		conditions.MarkFalse(bindDef, authnv1alpha1.DeleteCondition, bindDef.Generation,
			authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		if errStatus := r.client.Status().Update(ctx, bindDef); errStatus != nil {
			return fmt.Errorf("update status after RoleBinding deletion failure: %w", errStatus)
		}
		return err
	}
	return nil
}

// Reconcile BindDefinition method
func (r *bindDefinitionReconciler) reconcileCreate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("starting reconcileCreate", "bindDefinitionName", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		log.Error(err, "Unable to collect namespaces in reconcile Update function")
		return ctrl.Result{}, err
	}

	activeNamespaces := r.filterActiveNamespaces(ctx, bindDefinition, namespaceSet)
	log.V(2).Info("active namespaces count", "bindDefinitionName", bindDefinition.Name, "activeNamespaceCount", len(activeNamespaces))

	// Validate role references exist - set condition but continue processing
	missingRoles := r.validateRoleReferences(ctx, bindDefinition, activeNamespaces)
	if len(missingRoles) > 0 {
		log.Info("Some referenced roles do not exist - bindings will be created but may not be effective",
			"bindDefinitionName", bindDefinition.Name, "missingRoles", missingRoles)
		r.recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "RoleRefNotFound",
			"Referenced roles not found: %v. Bindings will be created but ineffective until roles exist.", missingRoles)
		conditions.MarkFalse(bindDefinition, authnv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authnv1alpha1.RoleRefInvalidReason, authnv1alpha1.RoleRefInvalidMessage)
		if err := r.client.Status().Update(ctx, bindDefinition); err != nil {
			log.Error(err, "Failed to update RoleRefValid condition", "bindDefinitionName", bindDefinition.Name)
		}
	} else {
		conditions.MarkTrue(bindDefinition, authnv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authnv1alpha1.RoleRefValidReason, authnv1alpha1.RoleRefValidMessage)
		if err := r.client.Status().Update(ctx, bindDefinition); err != nil {
			log.Error(err, "Failed to update RoleRefValid condition", "bindDefinitionName", bindDefinition.Name)
		}
	}

	// Create ServiceAccount resources
	log.V(2).Info("processing subjects for ServiceAccount creation", "bindDefinitionName", bindDefinition.Name, "subjectCount", len(bindDefinition.Spec.Subjects))
	saResult := r.createServiceAccounts(ctx, bindDefinition)
	if saResult.err != nil {
		return ctrl.Result{}, saResult.err
	}

	// Create ClusterRoleBinding resources
	log.V(2).Info("processing ClusterRoleBindings for creation", "bindDefinitionName", bindDefinition.Name, "clusterRoleRefCount", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs))
	if err := r.createClusterRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Create RoleBinding resources
	if err := r.createRoleBindings(ctx, bindDefinition, activeNamespaces); err != nil {
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	err = r.client.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// validateRoleReferences checks if all referenced ClusterRoles and Roles exist.
// Returns a list of missing role names. Does not fail the reconciliation.
func (r *bindDefinitionReconciler) validateRoleReferences(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	namespaces []corev1.Namespace,
) []string {
	log := log.FromContext(ctx)
	var missingRoles []string

	// Check ClusterRoleRefs in ClusterRoleBindings
	for _, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRole := &rbacv1.ClusterRole{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleRef}, clusterRole); err != nil {
			if apierrors.IsNotFound(err) {
				log.V(1).Info("ClusterRole not found", "clusterRole", clusterRoleRef)
				missingRoles = append(missingRoles, fmt.Sprintf("ClusterRole/%s", clusterRoleRef))
			}
		}
	}

	// Check ClusterRoleRefs and RoleRefs in RoleBindings
	for _, roleBinding := range bindDef.Spec.RoleBindings {
		// Check ClusterRoleRefs
		for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
			clusterRole := &rbacv1.ClusterRole{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleRef}, clusterRole); err != nil {
				if apierrors.IsNotFound(err) {
					// Only add if not already in the list
					roleName := fmt.Sprintf("ClusterRole/%s", clusterRoleRef)
					if !containsString(missingRoles, roleName) {
						log.V(1).Info("ClusterRole not found", "clusterRole", clusterRoleRef)
						missingRoles = append(missingRoles, roleName)
					}
				}
			}
		}

		// Check RoleRefs in each namespace
		for _, roleRef := range roleBinding.RoleRefs {
			for _, ns := range namespaces {
				role := &rbacv1.Role{}
				if err := r.client.Get(ctx, types.NamespacedName{Name: roleRef, Namespace: ns.Name}, role); err != nil {
					if apierrors.IsNotFound(err) {
						roleName := fmt.Sprintf("Role/%s/%s", ns.Name, roleRef)
						log.V(1).Info("Role not found", "role", roleRef, "namespace", ns.Name)
						missingRoles = append(missingRoles, roleName)
					}
				}
			}
		}
	}

	return missingRoles
}

// containsString checks if a string is in a slice
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func (r *bindDefinitionReconciler) collectNamespaces(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (map[string]corev1.Namespace, error) {
	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	for _, RoleBinding := range bindDefinition.Spec.RoleBindings {
		if RoleBinding.Namespace != "" {
			ns := &corev1.Namespace{}
			err := r.client.Get(ctx, types.NamespacedName{Name: RoleBinding.Namespace}, ns)
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("get namespace %s: %w", RoleBinding.Namespace, err)
			}
			namespaceSet[ns.Name] = *ns
		}
		for _, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					return nil, fmt.Errorf("parse namespace selector: %w", err)
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.client.List(ctx, namespaceList, listOpts...)
				if err != nil {
					return nil, fmt.Errorf("list namespaces with selector %s: %w", selector.String(), err)
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

	// Update ServiceAccount resources
	if err := r.updateServiceAccounts(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Update ClusterRoleBinding resources
	if err := r.updateClusterRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, err
	}

	// Update RoleBinding resources
	if err := r.updateRoleBindings(ctx, bindDefinition, activeNamespaces); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}
