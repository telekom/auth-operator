package authorization

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

const (
	// DefaultRequeueInterval is the interval at which resources are re-reconciled
	// to ensure drift from manual modifications is corrected.
	//
	// This interval serves multiple purposes:
	// 1. Drift Correction: If someone manually modifies a managed RBAC resource,
	//    the next reconciliation will restore the desired state.
	// 2. Namespace Discovery: New namespaces matching selectors will be picked up
	//    within this interval, creating the appropriate bindings.
	// 3. Resilience: Acts as a safety net in case watch events are missed due to
	//    temporary network issues or API server restarts.
	//
	// The 60-second interval balances responsiveness with API server load. For clusters
	// with many resources, this can be tuned via the operator's configuration.
	//
	// Used by: RoleDefinitionReconciler, BindDefinitionReconciler.
	DefaultRequeueInterval = 60 * time.Second

	// RoleRefRequeueInterval is a shorter requeue used when one or more
	// referenced Roles/ClusterRoles do not yet exist. The BindDefinition
	// controller does not watch Roles directly (they are not owned resources),
	// so a faster poll ensures the RoleRefsValid condition self-heals promptly
	// once the missing roles are created (e.g. by a RoleDefinition).
	RoleRefRequeueInterval = 10 * time.Second
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

// BindDefinitionReconciler defines the reconciler for BindDefinition and reconciles a BindDefinition object.
type BindDefinitionReconciler struct {
	client                client.Client
	scheme                *runtime.Scheme
	RoleBindingTerminator *RoleBindingTerminator
	recorder              events.EventRecorder
}

// NewBindDefinitionReconciler creates a new BindDefinition reconciler.
// Uses the manager's cached client for improved performance.
func NewBindDefinitionReconciler(
	cachedClient client.Client,
	config *rest.Config,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	resourceTracker *discovery.ResourceTracker,
) (*BindDefinitionReconciler, error) {
	rbTerminator, err := NewRoleBindingTerminator(cachedClient, config, scheme, recorder, resourceTracker)
	if err != nil {
		return nil, fmt.Errorf("unable to create rolebinding terminator: %w", err)
	}

	return &BindDefinitionReconciler{
		client:                cachedClient,
		scheme:                scheme,
		recorder:              recorder,
		RoleBindingTerminator: rbTerminator,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for namespace creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of namespace, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller.
func (r *BindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	if r.RoleBindingTerminator == nil {
		return fmt.Errorf("RoleBindingTerminator is nil - use NewBindDefinitionReconciler to create the reconciler")
	}
	if err := r.RoleBindingTerminator.SetupWithManager(mgr, concurrency); err != nil {
		return fmt.Errorf("unable to set up RoleBinding terminator: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// control BindDefinitions
		For(&authorizationv1alpha1.BindDefinition{}).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			MaxConcurrentReconciles: concurrency,
		}).
		// watch namespaces to:
		// - refresh bindings when labels change
		// - remove finalizers of owned resources during termination
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.namespaceToBindDefinitionRequests)).

		// watch owned ClusterRoleBindings to detect external drift
		Owns(&rbacv1.ClusterRoleBinding{}).

		// watch owned ServiceAccounts to detect external drift
		Owns(&corev1.ServiceAccount{}).

		// watch RoleBindings and enqueue BindDefinition owner
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &authorizationv1alpha1.BindDefinition{}, handler.OnlyControllerOwner())).
		Complete(r)
}

// namespaceToBindDefinitionRequests() implements the MapFunc type and makes it possible to return an EventHandler
// for any object implementing client.Object. Used it to fan-out updates to all RoleDefinitions on new CRD create
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#EnqueueRequestsFromMapFunc
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#MapFunc
func (r *BindDefinitionReconciler) namespaceToBindDefinitionRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	logger.V(2).Info("namespaceToBindDefinitionRequests triggered", "objectName", obj.GetName(), "objectNamespace", obj.GetNamespace())

	// Type assertion to ensure obj is a Namespace
	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", fmt.Sprintf("%T", obj))
		return nil
	}

	logger.V(2).Info("processing namespace event", "namespace", namespace.Name, "phase", namespace.Status.Phase)

	// List all RoleDefinition resources
	bindDefList := &authorizationv1alpha1.BindDefinitionList{}
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
// that other non-terminating BindDefinitions reference.
func (r *BindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
	// List all BindDefinitions
	bindDefList := &authorizationv1alpha1.BindDefinitionList{}
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
			if subject.Kind == authorizationv1alpha1.BindSubjectServiceAccount &&
				subject.Name == saName &&
				subject.Namespace == saNamespace {
				return true, nil
			}
		}
	}
	// No other BindDefinitions reference this ServiceAccount
	return false, nil
}

// Reconcile handles the reconciliation loop for BindDefinition resources.
// It manages the lifecycle of role bindings based on the BindDefinition spec.
// Status updates use Server-Side Apply (SSA) to avoid race conditions.
func (r *BindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	// === RECONCILE START ===
	logger.V(1).Info("=== Reconcile START ===",
		"bindDefinition", req.Name,
		"namespace", req.Namespace)

	// Track reconcile duration on exit
	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerBindDefinition).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===",
			"bindDefinition", req.Name,
			"duration", duration.String())
	}()

	// Fetching the BindDefinition custom resource from Kubernetes API
	logger.V(2).Info("Fetching BindDefinition from API",
		"bindDefinition", req.Name)
	bindDefinition := &authorizationv1alpha1.BindDefinition{}
	err := r.client.Get(ctx, req.NamespacedName, bindDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("BindDefinition not found (deleted), skipping reconcile",
				"bindDefinition", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to fetch BindDefinition",
			"bindDefinition", req.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch BindDefinition %s: %w", req.NamespacedName, err)
	}

	logger.V(2).Info("BindDefinition fetched successfully",
		"bindDefinition", bindDefinition.Name,
		"generation", bindDefinition.Generation,
		"resourceVersion", bindDefinition.ResourceVersion,
		"isDeleting", !bindDefinition.DeletionTimestamp.IsZero(),
		"subjectCount", len(bindDefinition.Spec.Subjects),
		"clusterRoleRefCount", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs),
		"roleBindingCount", len(bindDefinition.Spec.RoleBindings))

	// Check if controller should reconcile BindDefinition delete
	if !bindDefinition.DeletionTimestamp.IsZero() {
		logger.V(1).Info("BindDefinition marked for deletion, starting delete reconcile",
			"bindDefinition", bindDefinition.Name,
			"deletionTimestamp", bindDefinition.DeletionTimestamp)
		result, err := r.reconcileDelete(ctx, bindDefinition)
		if err != nil {
			logger.Error(err, "Delete reconcile failed",
				"bindDefinition", bindDefinition.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		} else {
			logger.V(1).Info("Delete reconcile completed successfully",
				"bindDefinition", bindDefinition.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultFinalized).Inc()
			// Clean up per-BD gauge series so they don't linger with stale values.
			metrics.DeleteManagedResourceSeries(metrics.ControllerBindDefinition, bindDefinition.Name)
			metrics.RoleRefsMissing.DeleteLabelValues(bindDefinition.Name)
			metrics.NamespacesActive.DeleteLabelValues(bindDefinition.Name)
			metrics.ExternalSAsReferenced.DeleteLabelValues(bindDefinition.Name)
		}
		return result, err
	}

	// Mark as Reconciling (kstatus) - this will be batched with final status update via SSA
	logger.V(2).Info("Marking BindDefinition as Reconciling",
		"bindDefinition", bindDefinition.Name,
		"generation", bindDefinition.Generation)
	conditions.MarkReconciling(bindDefinition, bindDefinition.Generation,
		authorizationv1alpha1.ReconcilingReasonProgressing, authorizationv1alpha1.ReconcilingMessageProgressing)
	bindDefinition.Status.ObservedGeneration = bindDefinition.Generation

	if !controllerutil.ContainsFinalizer(bindDefinition, authorizationv1alpha1.BindDefinitionFinalizer) {
		logger.V(2).Info("Adding finalizer to BindDefinition",
			"bindDefinition", bindDefinition.Name)
		old := bindDefinition.DeepCopy()
		controllerutil.AddFinalizer(bindDefinition, authorizationv1alpha1.BindDefinitionFinalizer)
		if err := r.client.Patch(ctx, bindDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			logger.Error(err, "Failed to add finalizer",
				"bindDefinition", bindDefinition.Name)
			r.markStalled(ctx, bindDefinition, err)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
			return ctrl.Result{}, fmt.Errorf("add finalizer to BindDefinition %s: %w", bindDefinition.Name, err)
		}
		r.recorder.Eventf(bindDefinition, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonFinalizer, authorizationv1alpha1.EventActionFinalizerAdd, "Adding finalizer to BindDefinition %s", bindDefinition.Name)
	}

	// Batch condition - finalizer set
	conditions.MarkTrue(bindDefinition, authorizationv1alpha1.FinalizerCondition, bindDefinition.Generation, authorizationv1alpha1.FinalizerReason, authorizationv1alpha1.FinalizerMessage)

	// Collect namespaces once for both create and update paths.
	// This avoids duplicate API calls to list namespaces.
	logger.V(2).Info("Collecting namespaces for BindDefinition",
		"bindDefinition", bindDefinition.Name)
	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		logger.Error(err, "Unable to collect namespaces", "bindDefinitionName", bindDefinition.Name)
		r.markStalled(ctx, bindDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("collect namespaces for BindDefinition %s: %w", bindDefinition.Name, err)
	}
	logger.V(2).Info("Namespaces collected",
		"bindDefinition", bindDefinition.Name,
		"totalNamespaces", len(namespaceSet))

	activeNamespaces := r.filterActiveNamespaces(ctx, bindDefinition, namespaceSet)
	logger.V(2).Info("Active namespaces filtered",
		"bindDefinition", bindDefinition.Name,
		"activeNamespaceCount", len(activeNamespaces),
		"activeNamespaces", activeNamespaces)
	metrics.NamespacesActive.WithLabelValues(bindDefinition.Name).Set(float64(len(activeNamespaces)))

	// Reconcile all resources using ensure pattern (create-or-update via SSA)
	logger.V(2).Info("Starting resource reconciliation",
		"bindDefinition", bindDefinition.Name,
		"subjects", len(bindDefinition.Spec.Subjects),
		"clusterRoleRefs", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs),
		"roleBindings", len(bindDefinition.Spec.RoleBindings))
	missingRoleRefs, err := r.reconcileResources(ctx, bindDefinition, activeNamespaces)
	if err != nil {
		logger.Error(err, "Error occurred in reconcileResources",
			"bindDefinition", bindDefinition.Name)
		r.markStalled(ctx, bindDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	logger.V(2).Info("Resource reconciliation completed",
		"bindDefinition", bindDefinition.Name,
		"missingRoleRefCount", missingRoleRefs)

	// Mark Ready and apply final status via SSA (kstatus)
	logger.V(2).Info("Marking BindDefinition as Ready and applying status",
		"bindDefinition", bindDefinition.Name,
		"generation", bindDefinition.Generation,
		"missingRoleRefs", missingRoleRefs)
	bindDefinition.Status.BindReconciled = true
	r.markReady(ctx, bindDefinition)

	// Apply status via SSA and surface errors so the controller retries if status patch fails
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		logger.Error(err, "Failed to apply BindDefinition status",
			"bindDefinition", bindDefinition.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	logger.V(2).Info("Status applied successfully",
		"bindDefinition", bindDefinition.Name,
		"observedGeneration", bindDefinition.Status.ObservedGeneration)

	// Use a shorter requeue when role references are missing so the condition
	// self-heals quickly once the referenced roles are created.
	if missingRoleRefs > 0 {
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultDegraded).Inc()
		logger.Info("Requeuing with shorter interval due to missing role references",
			"bindDefinition", bindDefinition.Name,
			"missingCount", missingRoleRefs,
			"requeueAfter", RoleRefRequeueInterval)
		return ctrl.Result{RequeueAfter: RoleRefRequeueInterval}, nil
	}

	logger.V(1).Info("Reconcile completed successfully",
		"bindDefinition", bindDefinition.Name,
		"requeueAfter", DefaultRequeueInterval)
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// reconcileResources ensures all resources managed by the BindDefinition exist
// and are up-to-date.  It returns the number of role references that could not
// be resolved (0 = all valid).  The caller uses this to choose a shorter
// requeue interval so the RoleRefsValid condition self-heals.
func (r *BindDefinitionReconciler) reconcileResources(
	ctx context.Context,
	bindDefinition *authorizationv1alpha1.BindDefinition,
	activeNamespaces []corev1.Namespace,
) (int, error) {
	logger := log.FromContext(ctx)

	logger.V(2).Info("reconcileResources: Starting",
		"bindDefinition", bindDefinition.Name,
		"activeNamespaceCount", len(activeNamespaces))

	// Validate role references exist - set condition but continue processing
	logger.V(3).Info("reconcileResources: Validating role references",
		"bindDefinition", bindDefinition.Name)
	missingRoles := r.validateRoleReferences(ctx, bindDefinition, activeNamespaces)
	missingCount := len(missingRoles)
	metrics.RoleRefsMissing.WithLabelValues(bindDefinition.Name).Set(float64(missingCount))
	bindDefinition.Status.MissingRoleRefs = missingRoles // Store names in status
	logger.V(2).Info("reconcileResources: Role reference validation complete",
		"bindDefinition", bindDefinition.Name,
		"missingCount", missingCount,
		"missingRoles", missingRoles)
	if missingCount > 0 {
		logger.Info("Some referenced roles do not exist - bindings will be created but may not be effective",
			"bindDefinitionName", bindDefinition.Name, "missingRoles", missingRoles)
		r.recorder.Eventf(bindDefinition, nil, corev1.EventTypeWarning, authorizationv1alpha1.EventReasonRoleRefNotFound, authorizationv1alpha1.EventActionValidate,
			"Referenced roles not found: %v. Bindings will be created but ineffective until roles exist. Will requeue in %s.", missingRoles, RoleRefRequeueInterval)
		conditions.MarkFalse(bindDefinition, authorizationv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authorizationv1alpha1.RoleRefInvalidReason, authorizationv1alpha1.RoleRefInvalidMessage, missingRoles)
	} else {
		conditions.MarkTrue(bindDefinition, authorizationv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authorizationv1alpha1.RoleRefValidReason, authorizationv1alpha1.RoleRefValidMessage)
	}

	// Ensure ServiceAccounts
	logger.V(2).Info("reconcileResources: Ensuring ServiceAccounts",
		"bindDefinition", bindDefinition.Name,
		"subjectCount", len(bindDefinition.Spec.Subjects))
	generatedSAs, externalSAs, err := r.ensureServiceAccounts(ctx, bindDefinition)
	if err != nil {
		return 0, fmt.Errorf("ensure ServiceAccounts: %w", err)
	}
	logger.V(2).Info("reconcileResources: ServiceAccounts ensured",
		"bindDefinition", bindDefinition.Name,
		"generatedCount", len(generatedSAs),
		"externalCount", len(externalSAs))
	// Update status with generated ServiceAccounts
	if len(generatedSAs) > 0 {
		bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(
			bindDefinition.Status.GeneratedServiceAccounts, generatedSAs)
	}
	// Update status with external (pre-existing) ServiceAccounts
	bindDefinition.Status.ExternalServiceAccounts = externalSAs
	// Update metric for external SAs count
	metrics.ExternalSAsReferenced.WithLabelValues(bindDefinition.Name).Set(float64(len(externalSAs)))

	// Ensure ClusterRoleBindings (uses SSA - handles both create and update)
	logger.V(2).Info("reconcileResources: Ensuring ClusterRoleBindings",
		"bindDefinition", bindDefinition.Name,
		"clusterRoleRefCount", len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs))
	if err := r.ensureClusterRoleBindings(ctx, bindDefinition); err != nil {
		return 0, fmt.Errorf("ensure ClusterRoleBindings: %w", err)
	}
	logger.V(2).Info("reconcileResources: ClusterRoleBindings ensured",
		"bindDefinition", bindDefinition.Name)

	// Ensure RoleBindings (uses SSA - handles both create and update)
	logger.V(2).Info("reconcileResources: Ensuring RoleBindings",
		"bindDefinition", bindDefinition.Name,
		"roleBindingSpecCount", len(bindDefinition.Spec.RoleBindings))
	if err := r.ensureRoleBindings(ctx, bindDefinition); err != nil {
		return 0, fmt.Errorf("ensure RoleBindings: %w", err)
	}
	logger.V(2).Info("reconcileResources: RoleBindings ensured",
		"bindDefinition", bindDefinition.Name)

	conditions.MarkTrue(bindDefinition, authorizationv1alpha1.CreateCondition, bindDefinition.Generation,
		authorizationv1alpha1.CreateReason, authorizationv1alpha1.CreateMessage)

	// Update managed resource gauges. These counts reflect the spec-declared
	// resources that were applied during this reconciliation, not a live count.
	crbCount := len(bindDefinition.Spec.ClusterRoleBindings.ClusterRoleRefs)
	var rbCount int
	for _, rb := range bindDefinition.Spec.RoleBindings {
		rbCount += (len(rb.ClusterRoleRefs) + len(rb.RoleRefs)) * len(activeNamespaces)
	}
	metrics.ManagedResources.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResourceClusterRoleBinding, bindDefinition.Name).Set(float64(crbCount))
	logger.V(2).Info("reconcileResources: Complete",
		"bindDefinition", bindDefinition.Name,
		"crbCount", crbCount,
		"rbCount", rbCount,
		"generatedSACount", len(generatedSAs),
		"missingRoleRefs", missingCount)
	metrics.ManagedResources.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResourceRoleBinding, bindDefinition.Name).Set(float64(rbCount))
	metrics.ManagedResources.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResourceServiceAccount, bindDefinition.Name).Set(float64(len(generatedSAs)))

	return missingCount, nil
}

// ensureClusterRoleBindings ensures all ClusterRoleBindings for the BindDefinition exist and are up-to-date.
// Uses Server-Side Apply (SSA) to create or update bindings in a single operation.
// This replaces the separate createClusterRoleBindings and updateClusterRoleBindings functions.
func (r *BindDefinitionReconciler) ensureClusterRoleBindings(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)

	for _, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		crbName := helpers.BuildBindingName(bindDef.Spec.TargetName, clusterRoleRef)

		// Build the ClusterRoleBinding using SSA ApplyConfiguration
		ac := pkgssa.ClusterRoleBindingWithSubjectsAndRoleRef(
			crbName,
			helpers.BuildResourceLabels(bindDef.Labels),
			bindDef.Spec.Subjects,
			rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     clusterRoleRef,
			},
		)

		// Add owner reference and source-tracing annotations
		ac.WithOwnerReferences(ownerRefForBindDefinition(bindDef)).
			WithAnnotations(helpers.BuildResourceAnnotations("BindDefinition", bindDef.Name))

		// Apply using SSA - creates if not exists, updates if different
		if err := pkgssa.ApplyClusterRoleBinding(ctx, r.client, ac); err != nil {
			logger.Error(err, "Failed to ensure ClusterRoleBinding",
				"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
			conditions.MarkFalse(bindDef, authorizationv1alpha1.CreateCondition, bindDef.Generation,
				authorizationv1alpha1.CreateReason, authorizationv1alpha1.CreateMessage)
			r.applyStatusNonFatal(ctx, bindDef)
			return fmt.Errorf("ensure ClusterRoleBinding %s: %w", crbName, err)
		}

		logger.V(2).Info("Ensured ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "clusterRoleBindingName", crbName)
		metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceClusterRoleBinding).Inc()
	}

	return nil
}

// ensureRoleBindings ensures all RoleBindings for the BindDefinition exist and are up-to-date.
// Uses Server-Side Apply (SSA) to create or update bindings in a single operation.
func (r *BindDefinitionReconciler) ensureRoleBindings(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)

	for _, roleBinding := range bindDef.Spec.RoleBindings {
		// Resolve namespaces for this specific roleBinding
		targetNamespaces, err := r.resolveRoleBindingNamespaces(ctx, roleBinding)
		if err != nil {
			return fmt.Errorf("resolve namespaces for roleBinding: %w", err)
		}

		for _, ns := range targetNamespaces {
			// Skip terminating namespaces
			if conditions.IsNamespaceTerminating(&ns) {
				logger.V(1).Info("Skipping RoleBinding in terminating namespace",
					"bindDefinitionName", bindDef.Name, "namespace", ns.Name)
				continue
			}

			// Create RoleBindings for ClusterRoleRefs
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, clusterRoleRef, "ClusterRole"); err != nil {
					return fmt.Errorf("ensure RoleBinding for ClusterRole %s in namespace %s: %w", clusterRoleRef, ns.Name, err)
				}
			}

			// Create RoleBindings for RoleRefs
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.ensureSingleRoleBinding(ctx, bindDef, ns.Name, roleRef, "Role"); err != nil {
					return fmt.Errorf("ensure RoleBinding for Role %s in namespace %s: %w", roleRef, ns.Name, err)
				}
			}
		}
	}

	logger.V(2).Info("RoleBindings reconciliation completed", "bindDefinitionName", bindDef.Name)
	return nil
}

// ensureSingleRoleBinding ensures a single RoleBinding exists and is up-to-date.
func (r *BindDefinitionReconciler) ensureSingleRoleBinding(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
	namespace, roleRef, roleKind string,
) error {
	logger := log.FromContext(ctx)
	rbName := helpers.BuildBindingName(bindDef.Spec.TargetName, roleRef)

	// Build the RoleBinding using SSA ApplyConfiguration
	ac := pkgssa.RoleBindingWithSubjectsAndRoleRef(
		rbName,
		namespace,
		helpers.BuildResourceLabels(bindDef.Labels),
		bindDef.Spec.Subjects,
		rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     roleKind,
			Name:     roleRef,
		},
	)

	// Add owner reference and source-tracing annotations
	ac.WithOwnerReferences(ownerRefForBindDefinition(bindDef)).
		WithAnnotations(helpers.BuildResourceAnnotations("BindDefinition", bindDef.Name))

	// Apply using SSA - creates if not exists, updates if different
	if err := pkgssa.ApplyRoleBinding(ctx, r.client, ac); err != nil {
		logger.Error(err, "Failed to ensure RoleBinding",
			"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
		conditions.MarkFalse(bindDef, authorizationv1alpha1.CreateCondition, bindDef.Generation,
			authorizationv1alpha1.CreateReason, authorizationv1alpha1.CreateMessage)
		r.applyStatusNonFatal(ctx, bindDef)
		return fmt.Errorf("ensure RoleBinding %s/%s: %w", namespace, rbName, err)
	}

	logger.V(2).Info("Ensured RoleBinding",
		"bindDefinitionName", bindDef.Name, "roleBindingName", rbName, "namespace", namespace)
	metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceRoleBinding).Inc()
	return nil
}

// validateServiceAccountNamespace checks if the namespace exists and is not terminating.
// Returns the namespace if valid, nil if not found or terminating (with appropriate logging).
func (r *BindDefinitionReconciler) validateServiceAccountNamespace(
	ctx context.Context,
	bindDefName string,
	namespace string,
) (*corev1.Namespace, error) {
	logger := log.FromContext(ctx)

	ns := &corev1.Namespace{}
	err := r.client.Get(ctx, types.NamespacedName{Name: namespace}, ns)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("ServiceAccount target namespace not found",
				"bindDefinitionName", bindDefName, "namespace", namespace)
			return nil, nil //nolint:nilnil // nil,nil indicates namespace not found (skip condition)
		}
		return nil, fmt.Errorf("get namespace %s: %w", namespace, err)
	}

	if conditions.IsNamespaceTerminating(ns) {
		logger.V(1).Info("Skipping ServiceAccount in terminating namespace",
			"bindDefinitionName", bindDefName, "namespace", namespace)
		return nil, nil //nolint:nilnil // nil,nil indicates namespace terminating (skip condition)
	}

	return ns, nil
}

// applyServiceAccount applies a ServiceAccount using SSA, creating or updating it declaratively.
// Uses per-BD FieldOwner to ensure multiple BDs can independently manage ownerReferences
// on shared ServiceAccounts without overwriting each other's entries.
// The source-names annotation tracks all BDs managing this SA (comma-separated).
func (r *BindDefinitionReconciler) applyServiceAccount(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
	subject rbacv1.Subject,
	automountToken bool,
) error {
	logger := log.FromContext(ctx)

	// Read existing SA to merge source-names annotation (if SA already exists)
	existingSA := &corev1.ServiceAccount{}
	var sourceNames string
	err := r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSA)
	switch {
	case err == nil:
		// SA exists - merge our BD name into existing source-names
		existing := existingSA.Annotations[helpers.SourceNamesAnnotation]
		sourceNames = helpers.MergeSourceNames(existing, bindDef.Name)
	case apierrors.IsNotFound(err):
		// New SA - just our BD name
		sourceNames = bindDef.Name
	default:
		// Unexpected error
		return fmt.Errorf("get existing ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
	}

	ac := pkgssa.ServiceAccountWith(subject.Name, subject.Namespace,
		helpers.BuildResourceLabels(bindDef.Labels), automountToken).
		WithOwnerReferences(saOwnerRefForBindDefinition(bindDef)).
		WithAnnotations(helpers.BuildManagedSAAnnotations(sourceNames))

	// Use per-BD FieldOwner so each BD's ownerRef is tracked independently.
	// Without this, SSA would remove BD-A's ownerRef when BD-B applies its ownerRef.
	fieldOwner := pkgssa.FieldOwnerForBD(bindDef.Name)
	if err := pkgssa.ApplyServiceAccountWithFieldOwner(ctx, r.client, ac, fieldOwner); err != nil {
		logger.Error(err, "Failed to apply ServiceAccount",
			"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name)
		return fmt.Errorf("apply ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
	}

	logger.V(1).Info("Applied ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace,
		"sourceNames", sourceNames)
	metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceServiceAccount).Inc()
	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authorizationv1alpha1.EventReasonUpdate, authorizationv1alpha1.EventActionReconcile,
		"Applied resource ServiceAccount/%s in namespace %s", subject.Name, subject.Namespace)

	return nil
}

// ensureServiceAccounts ensures all ServiceAccounts for the BindDefinition exist and are up-to-date.
// Uses Server-Side Apply (SSA) so that create-or-update is handled declaratively.
// Pre-existing ServiceAccounts (those not owned by any BindDefinition) are left
// untouched — the controller will NOT add an OwnerReference to them.
// SAs already owned by another BindDefinition ARE updated via SSA to add this BD's
// ownerRef, enabling shared ownership so that the SA survives individual BD deletions.
// Returns the list of generated/managed SAs and the list of external (pre-existing) SAs.
func (r *BindDefinitionReconciler) ensureServiceAccounts(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) ([]rbacv1.Subject, []string, error) {
	logger := log.FromContext(ctx)
	var generatedSAs []rbacv1.Subject
	var externalSAs []string

	// Use the configured value from spec, defaulting to true for backward compatibility
	automountToken := ptr.Deref(bindDef.Spec.AutomountServiceAccountToken, true)

	for _, subject := range bindDef.Spec.Subjects {
		if subject.Kind != authorizationv1alpha1.BindSubjectServiceAccount {
			continue
		}

		// Validate namespace
		ns, err := r.validateServiceAccountNamespace(ctx, bindDef.Name, subject.Namespace)
		if err != nil {
			return nil, nil, err
		}
		if ns == nil {
			continue // Namespace not found or terminating, logged in validateServiceAccountNamespace
		}

		// Check if the ServiceAccount already exists and whether any BindDefinition owns it.
		// Pre-existing SAs (created outside of any BindDefinition) must NOT be
		// adopted — we skip SSA so we never add an OwnerReference to them.
		// SAs owned by another BindDefinition are updated via SSA to add this BD's
		// ownerRef, enabling shared ownership for proper GC lifecycle.
		existing := &corev1.ServiceAccount{}
		err = r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existing)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("get ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
		}

		saExists := err == nil
		if saExists && !isOwnedByBindDefinition(existing.OwnerReferences) {
			// SA exists but is not owned by any BD — do not adopt it.
			saRef := fmt.Sprintf("%s/%s", subject.Namespace, subject.Name)
			externalSAs = append(externalSAs, saRef)
			logger.V(1).Info("Skipping pre-existing ServiceAccount (not owned by any BindDefinition)",
				"bindDefinitionName", bindDef.Name,
				"serviceAccount", subject.Name, "namespace", subject.Namespace)
			metrics.ServiceAccountSkippedPreExisting.WithLabelValues(bindDef.Name).Inc()
			r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal,
				authorizationv1alpha1.EventReasonServiceAccountPreExisting, authorizationv1alpha1.EventActionReconcile,
				"Using pre-existing ServiceAccount %s/%s (not managed by any BindDefinition)",
				subject.Namespace, subject.Name)
			// Add tracking annotation to external SA
			if err := r.addExternalSAReference(ctx, existing, bindDef.Name); err != nil {
				logger.Error(err, "Failed to add tracking annotation to external ServiceAccount",
					"serviceAccount", subject.Name, "namespace", subject.Namespace)
				// Non-fatal: continue reconciliation even if annotation update fails
			}
			continue
		}

		// If SA exists and is owned by another BD, emit a shared-ownership event
		if saExists && !hasOwnerRef(existing, bindDef) {
			logger.V(1).Info("ServiceAccount is owned by another BindDefinition, adding shared ownership",
				"bindDefinitionName", bindDef.Name,
				"serviceAccount", subject.Name, "namespace", subject.Namespace)
			r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal,
				authorizationv1alpha1.EventReasonServiceAccountShared, authorizationv1alpha1.EventActionReconcile,
				"Adding shared ownership to ServiceAccount %s/%s (already owned by another BindDefinition)",
				subject.Namespace, subject.Name)
		}

		// Apply ServiceAccount via SSA — creates or updates declaratively
		if err := r.applyServiceAccount(ctx, bindDef, subject, automountToken); err != nil {
			return nil, nil, err
		}

		if !helpers.SubjectExists(generatedSAs, subject) {
			generatedSAs = append(generatedSAs, subject)
		}
	}

	logger.V(1).Info("ServiceAccount reconciliation complete",
		"bindDefinitionName", bindDef.Name, "generatedSAs", len(generatedSAs), "externalSAs", len(externalSAs))

	return generatedSAs, externalSAs, nil
}

// applyStatus applies status updates using Server-Side Apply (SSA).
// This eliminates race conditions from stale object versions and batches all condition updates.
func (r *BindDefinitionReconciler) applyStatus(ctx context.Context, bindDefinition *authorizationv1alpha1.BindDefinition) error {
	return ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDefinition)
}

//nolint:unparam // result is intentionally always nil - requeue via error propagation
func (r *BindDefinitionReconciler) reconcileDelete(
	ctx context.Context,
	bindDefinition *authorizationv1alpha1.BindDefinition,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("starting reconcileDelete",
		"bindDefinition", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// RoleDefinition is marked to be deleted.
	logger.V(1).Info("BindDefinition marked for deletion - cleaning up resources",
		"bindDefinitionName", bindDefinition.Name)

	// Remove per-BD gauge metrics so they don't persist after deletion.
	metrics.RoleRefsMissing.DeleteLabelValues(bindDefinition.Name)
	metrics.NamespacesActive.DeleteLabelValues(bindDefinition.Name)
	metrics.ExternalSAsReferenced.DeleteLabelValues(bindDefinition.Name)

	conditions.MarkTrue(bindDefinition, authorizationv1alpha1.DeleteCondition, bindDefinition.Generation,
		authorizationv1alpha1.DeleteReason, authorizationv1alpha1.DeleteMessage)
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply delete condition for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	// Clean up tracking annotations from external ServiceAccounts
	r.cleanupExternalSAReferences(ctx, bindDefinition)

	// Delete ServiceAccounts
	if err := r.deleteSubjectServiceAccounts(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("delete ServiceAccounts for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	// Delete ClusterRoleBindings
	if err := r.deleteAllClusterRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("delete ClusterRoleBindings for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	// Delete RoleBindings
	if err := r.deleteAllRoleBindings(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("delete RoleBindings for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	// Mark finalizer as removed (DeleteCondition already set at start of deletion)
	conditions.MarkFalse(bindDefinition, authorizationv1alpha1.FinalizerCondition, bindDefinition.Generation,
		authorizationv1alpha1.FinalizerReason, authorizationv1alpha1.FinalizerMessage)
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply status after cleanup for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	logger.V(2).Info("removing BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)

	// Re-fetch to get the latest ResourceVersion after SSA status updates
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(bindDefinition), bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("re-fetch BindDefinition %s before finalizer removal: %w", bindDefinition.Name, err)
	}
	old := bindDefinition.DeepCopy()
	controllerutil.RemoveFinalizer(bindDefinition, authorizationv1alpha1.BindDefinitionFinalizer)
	if err := r.client.Patch(ctx, bindDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer from BindDefinition %s: %w", bindDefinition.Name, err)
	}
	logger.V(1).Info("reconcileDelete completed successfully", "bindDefinitionName", bindDefinition.Name)

	return ctrl.Result{}, nil
}

// deleteSubjectServiceAccounts deletes service accounts specified in subjects.
func (r *BindDefinitionReconciler) deleteSubjectServiceAccounts(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)
	logger.V(2).Info("processing subjects for deletion",
		"bindDefinitionName", bindDef.Name, "subjectCount", len(bindDef.Spec.Subjects))

	for idx, subject := range bindDef.Spec.Subjects {
		logger.V(3).Info("processing subject",
			"bindDefinitionName", bindDef.Name, "index", idx,
			"kind", subject.Kind, "name", subject.Name, "namespace", subject.Namespace)

		if subject.Kind == authorizationv1alpha1.BindSubjectServiceAccount {
			if _, err := r.deleteServiceAccount(ctx, bindDef, subject.Name, subject.Namespace); err != nil {
				return fmt.Errorf("deleteSubjectServiceAccounts: %w", err)
			}
		}
	}
	return nil
}

// deleteAllClusterRoleBindings deletes all ClusterRoleBindings for the BindDefinition.
func (r *BindDefinitionReconciler) deleteAllClusterRoleBindings(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)
	logger.V(2).Info("processing ClusterRoleBindings for deletion",
		"bindDefinitionName", bindDef.Name,
		"clusterRoleRefCount", len(bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs))

	for idx, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		logger.V(3).Info("looking up ClusterRoleBinding",
			"bindDefinitionName", bindDef.Name, "index", idx, "clusterRoleRef", clusterRoleRef)

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, clusterRoleRef)
		if err != nil {
			conditions.MarkFalse(bindDef, authorizationv1alpha1.DeleteCondition, bindDef.Generation,
				authorizationv1alpha1.DeleteReason, authorizationv1alpha1.DeleteMessage)
			if errStatus := r.applyStatus(ctx, bindDef); errStatus != nil {
				return fmt.Errorf("apply status after ClusterRoleBinding %s deletion failure: %w", clusterRoleRef, errStatus)
			}
			return fmt.Errorf("deleteAllClusterRoleBindings: %w", err)
		}
		logger.V(3).Info("ClusterRoleBinding delete result",
			"bindDefinitionName", bindDef.Name, "clusterRoleRef", clusterRoleRef, "result", result)
	}
	return nil
}

// deleteAllRoleBindings deletes all RoleBindings for the BindDefinition across all matching namespaces.
func (r *BindDefinitionReconciler) deleteAllRoleBindings(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)

	namespaceSet, err := r.collectNamespaces(ctx, bindDef)
	if err != nil {
		logger.Error(err, "failed to collect namespaces for RoleBinding cleanup",
			"bindDefinitionName", bindDef.Name)
		return fmt.Errorf("deleteAllRoleBindings: collect namespaces: %w", err)
	}

	logger.V(2).Info("processing namespaces for RoleBinding cleanup",
		"bindDefinitionName", bindDef.Name, "namespaceCount", len(namespaceSet))

	for nsIdx, ns := range namespaceSet {
		logger.V(2).Info("processing namespace for RoleBinding cleanup",
			"bindDefinitionName", bindDef.Name, "namespace", ns.Name, "index", nsIdx)

		for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
			logger.V(3).Info("processing RoleBinding spec",
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
func (r *BindDefinitionReconciler) deleteRoleBindingWithStatusUpdate(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
	roleRef, namespace string,
) error {
	_, err := r.deleteRoleBinding(ctx, bindDef, roleRef, namespace)
	if err != nil {
		conditions.MarkFalse(bindDef, authorizationv1alpha1.DeleteCondition, bindDef.Generation,
			authorizationv1alpha1.DeleteReason, authorizationv1alpha1.DeleteMessage)
		if errStatus := r.applyStatus(ctx, bindDef); errStatus != nil {
			return fmt.Errorf("apply status after RoleBinding deletion failure: %w", errStatus)
		}
		return err
	}
	return nil
}

// validateRoleReferences checks if all referenced ClusterRoles and Roles exist.
// Returns a list of missing role names. Does not fail the reconciliation.
func (r *BindDefinitionReconciler) validateRoleReferences(
	ctx context.Context,
	bindDef *authorizationv1alpha1.BindDefinition,
	namespaces []corev1.Namespace,
) []string {
	logger := log.FromContext(ctx)
	var missingRoles []string

	// Check ClusterRoleRefs in ClusterRoleBindings
	for _, clusterRoleRef := range bindDef.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRole := &rbacv1.ClusterRole{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleRef}, clusterRole); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("ClusterRole not found", "clusterRole", clusterRoleRef)
				missingRoles = append(missingRoles, fmt.Sprintf("ClusterRole/%s", clusterRoleRef))
			} else {
				logger.Error(err, "Failed to check ClusterRole existence", "clusterRole", clusterRoleRef)
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
					if !slices.Contains(missingRoles, roleName) {
						logger.V(1).Info("ClusterRole not found", "clusterRole", clusterRoleRef)
						missingRoles = append(missingRoles, roleName)
					}
				} else {
					logger.Error(err, "Failed to check ClusterRole existence", "clusterRole", clusterRoleRef)
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
						logger.V(1).Info("Role not found", "role", roleRef, "namespace", ns.Name)
						missingRoles = append(missingRoles, roleName)
					} else {
						logger.Error(err, "Failed to check Role existence", "role", roleRef, "namespace", ns.Name)
					}
				}
			}
		}
	}

	slices.Sort(missingRoles)

	return missingRoles
}

func (r *BindDefinitionReconciler) collectNamespaces(ctx context.Context, bindDefinition *authorizationv1alpha1.BindDefinition) (map[string]corev1.Namespace, error) {
	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	for _, roleBinding := range bindDefinition.Spec.RoleBindings {
		if roleBinding.Namespace != "" {
			ns := &corev1.Namespace{}
			err := r.client.Get(ctx, types.NamespacedName{Name: roleBinding.Namespace}, ns)
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("get namespace %s: %w", roleBinding.Namespace, err)
			}
			namespaceSet[ns.Name] = *ns
		}
		for _, nsSelector := range roleBinding.NamespaceSelector {
			if len(nsSelector.MatchLabels) == 0 && len(nsSelector.MatchExpressions) == 0 {
				continue
			}
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
			// Add namespaces to the set.
			for _, ns := range namespaceList.Items {
				namespaceSet[ns.Name] = ns
			}
		}
	}

	return namespaceSet, nil
}
