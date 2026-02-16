package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/metrics"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;escalate;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete;escalate;bind
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// Note: The controller requires broad read access to discover all API resources for dynamic role generation.
// This is inherent to the controller's purpose of creating roles based on API discovery.
// +kubebuilder:rbac:groups=*,resources=*,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups="coordination.k8s.io",resources=leases,verbs=get;list;update;create;delete
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=create;patch;update

// RoleDefinitionReconciler reconciles a RoleDefinition object.
type RoleDefinitionReconciler struct {
	client          client.Client
	scheme          *runtime.Scheme
	recorder        events.EventRecorder
	resourceTracker *discovery.ResourceTracker
	trackerEvents   chan event.TypedGenericEvent[client.Object]
}

// NewRoleDefinitionReconciler creates a new RoleDefinition reconciler.
// Uses the manager's cached client for improved performance.
func NewRoleDefinitionReconciler(cachedClient client.Client, scheme *runtime.Scheme, recorder events.EventRecorder, resourceTracker *discovery.ResourceTracker) (*RoleDefinitionReconciler, error) {
	if resourceTracker == nil {
		return nil, fmt.Errorf("resourceTracker cannot be nil")
	}
	trackerEvents := make(chan event.TypedGenericEvent[client.Object], 100)
	trackerCallback := func() error {
		// store empty generic event as we only care about the event to trigger reconciliation (and we don't know exactly what changed)
		trackerEvents <- event.TypedGenericEvent[client.Object]{}
		return nil
	}
	resourceTracker.AddSignalFunc(trackerCallback)

	return &RoleDefinitionReconciler{
		client:          cachedClient,
		scheme:          scheme,
		recorder:        recorder,
		resourceTracker: resourceTracker,
		trackerEvents:   trackerEvents,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for CRD creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of CRD, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller.
func (r *RoleDefinitionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, concurrency int) error {
	// Channel to watch for CRD events to trigger re-reconcile of all RoleDefinitions
	crdTrackerChannel := source.Channel(r.trackerEvents, handler.EnqueueRequestsFromMapFunc(r.queueAll()))

	return ctrl.NewControllerManagedBy(mgr).
		// Watch RoleDefinitions with generation predicate (skip status-only updates)
		For(&authnv1alpha1.RoleDefinition{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Watch owned ClusterRoles and Roles to detect external drift.
		// Note: GenerationChangedPredicate is NOT applied here because RBAC
		// resources do not increment metadata.generation on spec changes.
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.Role{}).
		WatchesRawSource(crdTrackerChannel).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

func (r *RoleDefinitionReconciler) queueAll() handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithName("roleDefinitionReconciler.queueAll")

		// List all RoleDefinition resources
		roleDefList := &authnv1alpha1.RoleDefinitionList{}
		err := r.client.List(ctx, roleDefList)
		if err != nil {
			logger.Error(err, "failed to list RoleDefinition resources")
			return nil
		}

		logger.V(3).Info("found RoleDefinitions", "roleDefinitionCount", len(roleDefList.Items))

		requests := make([]reconcile.Request, len(roleDefList.Items))
		for i, roleDef := range roleDefList.Items {
			logger.V(3).Info("enqueuing RoleDefinition reconciliation", "roleDefinition", roleDef.Name, "index", i)
			requests[i] = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      roleDef.Name,
					Namespace: roleDef.Namespace,
				},
			}
		}
		logger.V(2).Info("returning reconciliation requests", "requestCount", len(requests))
		return requests
	}
}

// Reconcile handles the reconciliation loop for RoleDefinition resources.
// It manages the lifecycle of cluster roles and roles based on the RoleDefinition spec.
// Status updates are batched and applied using Server-Side Apply (SSA) to avoid race conditions.
//
// The reconciliation flow follows these steps:
//  1. Fetch resource (return early if not found)
//  2. Handle deletion (if marked for deletion)
//  3. Ensure finalizer exists
//  4. Discover and filter API resources to build policy rules
//  5. Ensure the target role exists with computed rules
//  6. Apply final status
func (r *RoleDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	// === RECONCILE START ===
	logger.V(1).Info("=== Reconcile START ===",
		"roleDefinition", req.Name,
		"namespace", req.Namespace)

	// Track reconcile duration on exit
	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerRoleDefinition).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===",
			"roleDefinition", req.Name,
			"duration", duration.String())
	}()

	// Step 1: Fetch the RoleDefinition
	logger.V(2).Info("Fetching RoleDefinition from API",
		"roleDefinition", req.Name)
	roleDefinition, err := r.fetchRoleDefinition(ctx, req.NamespacedName)
	if err != nil || roleDefinition == nil {
		if err != nil {
			logger.Error(err, "Failed to fetch RoleDefinition",
				"roleDefinition", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		} else {
			logger.V(1).Info("RoleDefinition not found (deleted), skipping reconcile",
				"roleDefinition", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultSkipped).Inc()
		}
		return ctrl.Result{}, err
	}

	logger.V(2).Info("RoleDefinition fetched successfully",
		"roleDefinition", roleDefinition.Name,
		"generation", roleDefinition.Generation,
		"resourceVersion", roleDefinition.ResourceVersion,
		"isDeleting", !roleDefinition.DeletionTimestamp.IsZero(),
		"targetName", roleDefinition.Spec.TargetName)

	// Initialize status for reconciliation
	conditions.MarkReconciling(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.ReconcilingReasonProgressing, authnv1alpha1.ReconcilingMessageProgressing)
	roleDefinition.Status.ObservedGeneration = roleDefinition.Generation

	// Build initial role object for validation and deletion handling
	logger.V(2).Info("Building role object",
		"roleDefinition", roleDefinition.Name)
	role, err := r.buildRoleObject(roleDefinition)
	if err != nil {
		logger.Error(err, "invalid RoleDefinition spec", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeValidation).Inc()
		return ctrl.Result{}, err
	}

	// Step 2: Handle deletion
	if !roleDefinition.DeletionTimestamp.IsZero() {
		logger.V(1).Info("RoleDefinition marked for deletion, starting delete reconcile",
			"roleDefinition", roleDefinition.Name,
			"deletionTimestamp", roleDefinition.DeletionTimestamp)
		result, err := r.handleDeletion(ctx, roleDefinition, role)
		if err != nil {
			logger.Error(err, "Delete reconcile failed",
				"roleDefinition", roleDefinition.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		} else {
			logger.V(1).Info("Delete reconcile completed successfully",
				"roleDefinition", roleDefinition.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultFinalized).Inc()
		}
		return result, err
	}

	// Step 3: Ensure finalizer
	logger.V(2).Info("Ensuring finalizer",
		"roleDefinition", roleDefinition.Name)
	if err := r.ensureFinalizer(ctx, roleDefinition); err != nil {
		logger.Error(err, "Failed to ensure finalizer",
			"roleDefinition", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	conditions.MarkTrue(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation,
		authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)

	// Step 4: Discover and filter resources to build policy rules
	logger.V(2).Info("Discovering and filtering resources",
		"roleDefinition", roleDefinition.Name)
	finalRules, result, err := r.discoverAndFilterResources(ctx, roleDefinition)
	if err != nil || result.RequeueAfter > 0 {
		logger.V(2).Info("Discovery phase returned early",
			"roleDefinition", roleDefinition.Name,
			"error", err,
			"requeueAfter", result.RequeueAfter)
		return result, err
	}
	logger.V(2).Info("Discovery complete",
		"roleDefinition", roleDefinition.Name,
		"ruleCount", len(finalRules))

	// Step 5: Ensure the target role exists with computed rules
	logger.V(2).Info("Ensuring role with computed rules",
		"roleDefinition", roleDefinition.Name,
		"ruleCount", len(finalRules))
	if err := r.ensureRole(ctx, roleDefinition, finalRules); err != nil {
		logger.Error(err, "Failed to ensure role",
			"roleDefinition", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	logger.V(2).Info("Role ensured successfully",
		"roleDefinition", roleDefinition.Name)

	// Step 6: Apply final status
	logger.V(2).Info("Applying final status",
		"roleDefinition", roleDefinition.Name,
		"generation", roleDefinition.Generation)
	roleDefinition.Status.RoleReconciled = true
	if err := r.applyStatus(ctx, roleDefinition); err != nil {
		logger.Error(err, "failed to apply final status", "roleDefinitionName", roleDefinition.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	logger.V(1).Info("Reconcile completed successfully",
		"roleDefinition", roleDefinition.Name,
		"requeueAfter", DefaultRequeueInterval)
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// fetchRoleDefinition retrieves a RoleDefinition by name.
// Returns nil (without error) if the resource was not found (already deleted).
func (r *RoleDefinitionReconciler) fetchRoleDefinition(
	ctx context.Context,
	namespacedName types.NamespacedName,
) (*authnv1alpha1.RoleDefinition, error) {
	logger := log.FromContext(ctx)

	roleDefinition := &authnv1alpha1.RoleDefinition{}
	if err := r.client.Get(ctx, namespacedName, roleDefinition); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RoleDefinition not found - already deleted", "roleDefinitionName", namespacedName.Name)
			return nil, nil //nolint:nilnil // Standard K8s pattern: nil,nil signals resource not found (already deleted)
		}
		logger.Error(err, "unable to fetch RoleDefinition", "roleDefinitionName", namespacedName.Name)
		return nil, err
	}

	logger.V(2).Info("RoleDefinition retrieved",
		"roleDefinitionName", roleDefinition.Name,
		"targetRole", roleDefinition.Spec.TargetRole,
		"targetName", roleDefinition.Spec.TargetName)

	return roleDefinition, nil
}

// discoverAndFilterResources performs API discovery, filters resources based on the
// RoleDefinition spec, and builds the final sorted policy rules.
//
// This function encapsulates:
//   - Getting API resources from the resource tracker
//   - Filtering based on RestrictedAPIs, RestrictedResources, and RestrictedVerbs
//   - Building and sorting the final policy rules
//
// Returns the policy rules, a requeue result (if the tracker is not ready), and any error.
func (r *RoleDefinitionReconciler) discoverAndFilterResources(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
) ([]rbacv1.PolicyRule, ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Set API discovery condition
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIDiscoveryCondition, roleDefinition.Generation,
		authnv1alpha1.APIDiscoveryReason, authnv1alpha1.APIDiscoveryMessage)

	// Get API resources from tracker
	apiResources, err := r.resourceTracker.GetAPIResources()
	if errors.Is(err, discovery.ErrResourceTrackerNotStarted) {
		logger.V(1).Info("ResourceTracker not started yet - requeuing", "roleDefinitionName", roleDefinition.Name)
		if statusErr := r.applyStatus(ctx, roleDefinition); statusErr != nil {
			logger.Error(statusErr, "failed to apply status before requeue", "roleDefinitionName", roleDefinition.Name)
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultRequeue).Inc()
		return nil, ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		logger.Error(err, "failed to get API resources", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return nil, ctrl.Result{}, err
	}

	// Filter API resources based on RoleDefinition spec
	rulesByAPIGroupAndVerbs, err := r.filterAPIResourcesForRoleDefinition(ctx, roleDefinition, apiResources)
	if err != nil {
		logger.Error(err, "failed to filter API resources", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleDefinition, metrics.ErrorTypeInternal).Inc()
		return nil, ctrl.Result{}, err
	}

	// Build sorted final rules
	finalRules := r.buildFinalRules(roleDefinition, rulesByAPIGroupAndVerbs)

	// Mark discovery and filtering conditions as complete
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIFilteredCondition, roleDefinition.Generation,
		authnv1alpha1.APIFilteredReason, authnv1alpha1.APIFilteredMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceDiscoveryCondition, roleDefinition.Generation,
		authnv1alpha1.ResourceDiscoveryReason, authnv1alpha1.ResourceDiscoveryMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceFilteredCondition, roleDefinition.Generation,
		authnv1alpha1.ResourceFilteredReason, authnv1alpha1.ResourceFilteredMessage)

	logger.V(2).Info("resource discovery and filtering completed",
		"roleDefinitionName", roleDefinition.Name, "rulesCount", len(finalRules))

	return finalRules, ctrl.Result{}, nil
}

// applyStatus applies status updates using Server-Side Apply (SSA).
// This eliminates race conditions from stale object versions and batches all condition updates.
func (r *RoleDefinitionReconciler) applyStatus(ctx context.Context, roleDefinition *authnv1alpha1.RoleDefinition) error {
	return ssa.ApplyRoleDefinitionStatus(ctx, r.client, roleDefinition)
}

func (r *RoleDefinitionReconciler) filterAPIResourcesForRoleDefinition(
	_ context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	apiResources discovery.APIResourcesByGroupVersion,
) (map[string]*rbacv1.PolicyRule, error) {
	rulesByAPIGroupAndVerbs := make(map[string]*rbacv1.PolicyRule)

	// Filter API Resources based on RoleDefinition spec
	for gv, apiResources := range apiResources {
		groupVersion, err := schema.ParseGroupVersion(gv)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GroupVersion %q: %w", gv, err)
		}

		// NOTE: Currently filters by API group name only. The Versions field in metav1.APIGroup
		// is accepted but ignored - specifying a group restricts ALL versions of that group.
		// TODO(#75): Implement version-specific filtering to respect the Versions field in RestrictedAPIs.
		// When Versions is empty, restrict all versions; when specified, restrict only those versions.
		apiIsRestricted := slices.ContainsFunc(roleDefinition.Spec.RestrictedAPIs, func(ag metav1.APIGroup) bool { return ag.Name == groupVersion.Group })
		// Skip restricted API groups
		if apiIsRestricted {
			continue
		}
		resourceIsRestrictedByRuleFunc := func(res metav1.APIResource) func(metav1.APIResource) bool {
			return func(rule metav1.APIResource) bool {
				return res.Name == rule.Name && groupVersion.Group == rule.Group
			}
		}

		for _, res := range apiResources {
			// Skip restricted resources
			resourceIsRestricted := slices.ContainsFunc(roleDefinition.Spec.RestrictedResources, resourceIsRestrictedByRuleFunc(res))
			if resourceIsRestricted {
				continue
			}

			// Filter namespaced scope
			if res.Namespaced && !roleDefinition.Spec.ScopeNamespaced {
				continue
			}

			// Filter verbs
			verbs := make([]string, 0)
			for _, verb := range res.Verbs {
				if !slices.Contains(roleDefinition.Spec.RestrictedVerbs, verb) {
					verbs = append(verbs, verb)
				}
			}
			if len(verbs) == 0 {
				continue
			}
			key := fmt.Sprintf("%s|%v", gv, verbs)
			existingRule, exists := rulesByAPIGroupAndVerbs[key]
			if !exists {
				existingRule = &rbacv1.PolicyRule{
					APIGroups: []string{groupVersion.Group},
					Verbs:     verbs,
				}
				rulesByAPIGroupAndVerbs[key] = existingRule
			}

			existingRule.Resources = append(existingRule.Resources, res.Name)
		}
	}
	return rulesByAPIGroupAndVerbs, nil
}
