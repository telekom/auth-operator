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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
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
	recorder        record.EventRecorder
	resourceTracker *discovery.ResourceTracker
	trackerEvents   chan event.TypedGenericEvent[client.Object]
}

// NewRoleDefinitionReconciler creates a new RoleDefinition reconciler.
// Uses the manager's cached client for improved performance.
func NewRoleDefinitionReconciler(cachedClient client.Client, scheme *runtime.Scheme, recorder record.EventRecorder, resourceTracker *discovery.ResourceTracker) (*RoleDefinitionReconciler, error) {
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
// reconcile requeue and does not require immediate action from controller
func (r *RoleDefinitionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, concurrency int) error {
	// Channel to watch for CRD events to trigger re-reconcile of all RoleDefinitions
	crdTrackerChannel := source.Channel(r.trackerEvents, handler.EnqueueRequestsFromMapFunc(r.queueAll()))

	return ctrl.NewControllerManagedBy(mgr).
		For(&authnv1alpha1.RoleDefinition{}).
		WatchesRawSource(crdTrackerChannel).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
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
func (r *RoleDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("starting RoleDefinition reconciliation", "roleDefinitionName", req.Name, "namespace", req.Namespace)

	// Fetch the RoleDefinition
	roleDefinition := &authnv1alpha1.RoleDefinition{}
	err := r.client.Get(ctx, req.NamespacedName, roleDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("RoleDefinition not found - already deleted", "roleDefinitionName", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch RoleDefinition", "roleDefinitionName", req.Name)
		return ctrl.Result{}, err
	}

	log.V(2).Info("RoleDefinition retrieved", "roleDefinitionName", roleDefinition.Name,
		"targetRole", roleDefinition.Spec.TargetRole, "targetName", roleDefinition.Spec.TargetName)

	// Mark as Reconciling (kstatus) - this will be batched with final status update via SSA
	conditions.MarkReconciling(roleDefinition, roleDefinition.Generation,
		authnv1alpha1.ReconcilingReasonProgressing, authnv1alpha1.ReconcilingMessageProgressing)
	roleDefinition.Status.ObservedGeneration = roleDefinition.Generation

	// Build initial role object for deletion handling
	role, err := r.buildRoleObject(roleDefinition)
	if err != nil {
		log.Error(err, "invalid RoleDefinition spec", "roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole)
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !roleDefinition.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, roleDefinition, role)
	}

	// Ensure finalizer
	if err := r.ensureFinalizer(ctx, roleDefinition); err != nil {
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	// Batch condition updates - set finalizer condition
	conditions.MarkTrue(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation,
		authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)

	// Set API discovery condition
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIDiscoveryCondition, roleDefinition.Generation,
		authnv1alpha1.APIDiscoveryReason, authnv1alpha1.APIDiscoveryMessage)

	apiResources, err := r.resourceTracker.GetAPIResources()
	if errors.Is(err, discovery.ErrResourceTrackerNotStarted) {
		log.V(1).Info("ResourceTracker not started yet - requeuing", "roleDefinitionName", roleDefinition.Name)
		// Apply status before requeuing to persist conditions
		if statusErr := r.applyStatus(ctx, roleDefinition); statusErr != nil {
			log.Error(statusErr, "failed to apply status before requeue", "roleDefinitionName", roleDefinition.Name)
		}
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		log.Error(err, "failed to get API resources", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	// Filter and build rules
	rulesByAPIGroupAndVerbs, err := r.filterAPIResourcesForRoleDefinition(ctx, roleDefinition, apiResources)
	if err != nil {
		log.Error(err, "failed to filter API resources for RoleDefinition", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}
	finalRules := r.buildFinalRules(roleDefinition, rulesByAPIGroupAndVerbs)

	// Batch more conditions - resource discovery and filtering completed
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIFilteredCondition, roleDefinition.Generation,
		authnv1alpha1.APIFilteredReason, authnv1alpha1.APIFilteredMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceDiscoveryCondition, roleDefinition.Generation,
		authnv1alpha1.ResourceDiscoveryReason, authnv1alpha1.ResourceDiscoveryMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceFilteredCondition, roleDefinition.Generation,
		authnv1alpha1.ResourceFilteredReason, authnv1alpha1.ResourceFilteredMessage)

	log.V(2).Info("resource discovery and filtering completed",
		"roleDefinitionName", roleDefinition.Name, "rulesCount", len(finalRules))

	// Build role with rules
	roleWithRules, existingRole := r.buildRoleWithRules(roleDefinition, finalRules)

	// Check if role exists
	log.V(2).Info("checking if role exists", "roleDefinitionName", roleDefinition.Name,
		"roleName", roleDefinition.Spec.TargetName, "policyRuleCount", len(finalRules))

	err = r.client.Get(ctx, types.NamespacedName{
		Name:      roleDefinition.Spec.TargetName,
		Namespace: roleDefinition.Spec.TargetNamespace,
	}, existingRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.createRole(ctx, roleDefinition, roleWithRules)
		}
		log.Error(err, "Failed to get existing role", "roleDefinitionName", roleDefinition.Name)
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	// Update existing role if needed
	if err := r.updateRole(ctx, roleDefinition, existingRole, finalRules); err != nil {
		r.markStalled(ctx, roleDefinition, err)
		return ctrl.Result{}, err
	}

	// Final status update using SSA - batch all conditions together
	roleDefinition.Status.RoleReconciled = true
	if err := r.applyStatus(ctx, roleDefinition); err != nil {
		log.Error(err, "failed to apply final status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	log.V(1).Info("RoleDefinition reconciliation completed successfully", "roleDefinitionName", roleDefinition.Name)
	return ctrl.Result{}, nil
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
