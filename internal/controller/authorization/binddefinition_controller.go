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

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

const (
	// DefaultRequeueInterval is the interval at which BindDefinition resources are
	// re-reconciled to ensure drift from manual modifications is corrected.
	//
	// This interval serves multiple purposes:
	// 1. Drift Correction: If someone manually modifies a ClusterRoleBinding, RoleBinding,
	//    or ServiceAccount managed by the operator, the next reconciliation will restore
	//    the desired state defined in the BindDefinition.
	// 2. Namespace Discovery: New namespaces matching the BindDefinition's selector will
	//    be picked up within this interval, creating the appropriate RoleBindings.
	// 3. Resilience: Acts as a safety net in case watch events are missed due to
	//    temporary network issues or API server restarts.
	//
	// The 60-second interval balances responsiveness with API server load. For clusters
	// with many BindDefinitions, this can be tuned via the operator's configuration.
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
		For(&authnv1alpha1.BindDefinition{}).
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
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &authnv1alpha1.BindDefinition{}, handler.OnlyControllerOwner())).
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
// that other non-terminating BindDefinitions reference.
func (r *BindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
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

// Reconcile handles the reconciliation loop for BindDefinition resources.
// It manages the lifecycle of role bindings based on the BindDefinition spec.
// Status updates use Server-Side Apply (SSA) to avoid race conditions.
func (r *BindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	// Track reconcile duration on exit
	defer func() {
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerBindDefinition).Observe(time.Since(startTime).Seconds())
	}()

	// Fetching the BindDefinition custom resource from Kubernetes API
	bindDefinition := &authnv1alpha1.BindDefinition{}
	err := r.client.Get(ctx, req.NamespacedName, bindDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch BindDefinition %s: %w", req.NamespacedName, err)
	}

	// Check if controller should reconcile BindDefinition delete
	if !bindDefinition.DeletionTimestamp.IsZero() {
		result, err := r.reconcileDelete(ctx, bindDefinition)
		if err != nil {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		} else {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultFinalized).Inc()
		}
		return result, err
	}

	// Mark as Reconciling (kstatus) - this will be batched with final status update via SSA
	conditions.MarkReconciling(bindDefinition, bindDefinition.Generation,
		authnv1alpha1.ReconcilingReasonProgressing, authnv1alpha1.ReconcilingMessageProgressing)
	bindDefinition.Status.ObservedGeneration = bindDefinition.Generation

	if !controllerutil.ContainsFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer) {
		old := bindDefinition.DeepCopy()
		controllerutil.AddFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
		if err := r.client.Patch(ctx, bindDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			r.markStalled(ctx, bindDefinition, err)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
			return ctrl.Result{}, fmt.Errorf("add finalizer to BindDefinition %s: %w", bindDefinition.Name, err)
		}
		r.recorder.Eventf(bindDefinition, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonFinalizer, authnv1alpha1.EventActionFinalizerAdd, "Adding finalizer to BindDefinition %s", bindDefinition.Name)
	}

	// Batch condition - finalizer set
	conditions.MarkTrue(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)

	// Collect namespaces once for both create and update paths.
	// This avoids duplicate API calls to list namespaces.
	namespaceSet, err := r.collectNamespaces(ctx, bindDefinition)
	if err != nil {
		logger.Error(err, "Unable to collect namespaces", "bindDefinitionName", bindDefinition.Name)
		r.markStalled(ctx, bindDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("collect namespaces for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	activeNamespaces := r.filterActiveNamespaces(ctx, bindDefinition, namespaceSet)

	// Reconcile all resources using ensure pattern (create-or-update via SSA)
	if err := r.reconcileResources(ctx, bindDefinition, activeNamespaces); err != nil {
		logger.Error(err, "Error occurred in reconcileResources")
		r.markStalled(ctx, bindDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	// Mark Ready and apply final status via SSA (kstatus)
	bindDefinition.Status.BindReconciled = true
	r.markReady(ctx, bindDefinition)

	// Apply status via SSA and surface errors so the controller retries if status patch fails
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		logger.Error(err, "Failed to apply BindDefinition status")
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerBindDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// reconcileResources ensures all resources managed by the BindDefinition exist and are up-to-date.
// Uses the "ensure" pattern with Server-Side Apply (SSA) to handle both create and update in one pass.
// This replaces the separate reconcileCreate and reconcileUpdate functions.
func (r *BindDefinitionReconciler) reconcileResources(
	ctx context.Context,
	bindDefinition *authnv1alpha1.BindDefinition,
	activeNamespaces []corev1.Namespace,
) error {
	logger := log.FromContext(ctx)

	// Validate role references exist - set condition but continue processing
	missingRoles := r.validateRoleReferences(ctx, bindDefinition, activeNamespaces)
	if len(missingRoles) > 0 {
		logger.Info("Some referenced roles do not exist - bindings will be created but may not be effective",
			"bindDefinitionName", bindDefinition.Name, "missingRoles", missingRoles)
		r.recorder.Eventf(bindDefinition, nil, corev1.EventTypeWarning, authnv1alpha1.EventReasonRoleRefNotFound, authnv1alpha1.EventActionValidate,
			"Referenced roles not found: %v. Bindings will be created but ineffective until roles exist.", missingRoles)
		conditions.MarkFalse(bindDefinition, authnv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authnv1alpha1.RoleRefInvalidReason, authnv1alpha1.RoleRefInvalidMessage)
	} else {
		conditions.MarkTrue(bindDefinition, authnv1alpha1.RoleRefValidCondition, bindDefinition.Generation,
			authnv1alpha1.RoleRefValidReason, authnv1alpha1.RoleRefValidMessage)
	}

	// Ensure ServiceAccounts
	generatedSAs, err := r.ensureServiceAccounts(ctx, bindDefinition)
	if err != nil {
		return fmt.Errorf("ensure ServiceAccounts: %w", err)
	}
	// Update status with generated ServiceAccounts
	if len(generatedSAs) > 0 {
		bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(
			bindDefinition.Status.GeneratedServiceAccounts, generatedSAs)
	}

	// Ensure ClusterRoleBindings (uses SSA - handles both create and update)
	if err := r.ensureClusterRoleBindings(ctx, bindDefinition); err != nil {
		return fmt.Errorf("ensure ClusterRoleBindings: %w", err)
	}

	// Ensure RoleBindings (uses SSA - handles both create and update)
	if err := r.ensureRoleBindings(ctx, bindDefinition); err != nil {
		return fmt.Errorf("ensure RoleBindings: %w", err)
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation,
		authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)

	return nil
}

// ensureClusterRoleBindings ensures all ClusterRoleBindings for the BindDefinition exist and are up-to-date.
// Uses Server-Side Apply (SSA) to create or update bindings in a single operation.
// This replaces the separate createClusterRoleBindings and updateClusterRoleBindings functions.
func (r *BindDefinitionReconciler) ensureClusterRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
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
			conditions.MarkFalse(bindDef, authnv1alpha1.CreateCondition, bindDef.Generation,
				authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
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
	bindDef *authnv1alpha1.BindDefinition,
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
	bindDef *authnv1alpha1.BindDefinition,
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
		conditions.MarkFalse(bindDef, authnv1alpha1.CreateCondition, bindDef.Generation,
			authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
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
func (r *BindDefinitionReconciler) applyServiceAccount(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
	subject rbacv1.Subject,
	automountToken bool,
) error {
	logger := log.FromContext(ctx)

	ac := pkgssa.ServiceAccountWith(subject.Name, subject.Namespace,
		helpers.BuildResourceLabels(bindDef.Labels), automountToken).
		WithOwnerReferences(ownerRefForBindDefinition(bindDef)).
		WithAnnotations(helpers.BuildResourceAnnotations("BindDefinition", bindDef.Name))

	if err := pkgssa.ApplyServiceAccount(ctx, r.client, ac); err != nil {
		logger.Error(err, "Failed to apply ServiceAccount",
			"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name)
		return fmt.Errorf("apply ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
	}

	logger.V(1).Info("Applied ServiceAccount",
		"bindDefinitionName", bindDef.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
	metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceServiceAccount).Inc()
	r.recorder.Eventf(bindDef, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonUpdate, authnv1alpha1.EventActionReconcile,
		"Applied resource ServiceAccount/%s in namespace %s", subject.Name, subject.Namespace)

	return nil
}

// ensureServiceAccounts ensures all ServiceAccounts for the BindDefinition exist and are up-to-date.
// Uses Server-Side Apply (SSA) so that create-or-update is handled declaratively.
func (r *BindDefinitionReconciler) ensureServiceAccounts(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) ([]rbacv1.Subject, error) {
	logger := log.FromContext(ctx)
	var generatedSAs []rbacv1.Subject

	// Use the configured value from spec, defaulting to true for backward compatibility
	automountToken := ptr.Deref(bindDef.Spec.AutomountServiceAccountToken, true)

	for _, subject := range bindDef.Spec.Subjects {
		if subject.Kind != authnv1alpha1.BindSubjectServiceAccount {
			continue
		}

		// Validate namespace
		ns, err := r.validateServiceAccountNamespace(ctx, bindDef.Name, subject.Namespace)
		if err != nil {
			return nil, err
		}
		if ns == nil {
			continue // Namespace not found or terminating, logged in validateServiceAccountNamespace
		}

		// Apply ServiceAccount via SSA — creates or updates declaratively
		if err := r.applyServiceAccount(ctx, bindDef, subject, automountToken); err != nil {
			return nil, err
		}

		if !helpers.SubjectExists(generatedSAs, subject) {
			generatedSAs = append(generatedSAs, subject)
		}
	}

	logger.V(1).Info("ServiceAccount reconciliation complete",
		"bindDefinitionName", bindDef.Name, "generatedSAs", len(generatedSAs))

	return generatedSAs, nil
}

// applyStatus applies status updates using Server-Side Apply (SSA).
// This eliminates race conditions from stale object versions and batches all condition updates.
func (r *BindDefinitionReconciler) applyStatus(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) error {
	return ssa.ApplyBindDefinitionStatus(ctx, r.client, bindDefinition)
}

//nolint:unparam // result is intentionally always nil - requeue via error propagation
func (r *BindDefinitionReconciler) reconcileDelete(
	ctx context.Context,
	bindDefinition *authnv1alpha1.BindDefinition,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("starting reconcileDelete",
		"bindDefinition", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// RoleDefinition is marked to be deleted.
	logger.V(1).Info("BindDefinition marked for deletion - cleaning up resources",
		"bindDefinitionName", bindDefinition.Name)
	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation,
		authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply delete condition for BindDefinition %s: %w", bindDefinition.Name, err)
	}

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
	conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation,
		authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
	if err := r.applyStatus(ctx, bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply status after cleanup for BindDefinition %s: %w", bindDefinition.Name, err)
	}

	logger.V(2).Info("removing BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)

	// Re-fetch to get the latest ResourceVersion after SSA status updates
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(bindDefinition), bindDefinition); err != nil {
		return ctrl.Result{}, fmt.Errorf("re-fetch BindDefinition %s before finalizer removal: %w", bindDefinition.Name, err)
	}
	old := bindDefinition.DeepCopy()
	controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
	if err := r.client.Patch(ctx, bindDefinition, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer from BindDefinition %s: %w", bindDefinition.Name, err)
	}
	logger.V(1).Info("reconcileDelete completed successfully", "bindDefinitionName", bindDefinition.Name)

	return ctrl.Result{}, nil
}

// deleteSubjectServiceAccounts deletes service accounts specified in subjects.
func (r *BindDefinitionReconciler) deleteSubjectServiceAccounts(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
) error {
	logger := log.FromContext(ctx)
	logger.V(2).Info("processing subjects for deletion",
		"bindDefinitionName", bindDef.Name, "subjectCount", len(bindDef.Spec.Subjects))

	for idx, subject := range bindDef.Spec.Subjects {
		logger.V(3).Info("processing subject",
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
func (r *BindDefinitionReconciler) deleteAllClusterRoleBindings(
	ctx context.Context,
	bindDef *authnv1alpha1.BindDefinition,
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
			conditions.MarkFalse(bindDef, authnv1alpha1.DeleteCondition, bindDef.Generation,
				authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
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
	bindDef *authnv1alpha1.BindDefinition,
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
	bindDef *authnv1alpha1.BindDefinition,
	roleRef, namespace string,
) error {
	_, err := r.deleteRoleBinding(ctx, bindDef, roleRef, namespace)
	if err != nil {
		conditions.MarkFalse(bindDef, authnv1alpha1.DeleteCondition, bindDef.Generation,
			authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
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
	bindDef *authnv1alpha1.BindDefinition,
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

	return missingRoles
}

func (r *BindDefinitionReconciler) collectNamespaces(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (map[string]corev1.Namespace, error) {
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
