package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	conditions "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/conditions"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/discovery"
	helpers "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/helpers"
)

// roleDefinitionReconciler reconciles a RoleDefinition object
type roleDefinitionReconciler struct {
	client          client.WithWatch
	scheme          *runtime.Scheme
	recorder        record.EventRecorder
	resourceTracker *discovery.ResourceTracker
	trackerEvents   chan event.TypedGenericEvent[client.Object]
}

func NewRoleDefinitionReconciler(config *rest.Config, scheme *runtime.Scheme, recorder record.EventRecorder) (*roleDefinitionReconciler, error) {
	withWatch, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("unable to create client with watch: %w", err)
	}
	trackerEvents := make(chan event.TypedGenericEvent[client.Object], 100)
	trackerCallback := func() error {
		// store empty generic event as we only care about the event to trigger reconciliation (and we don't know exactly what changed)
		trackerEvents <- event.TypedGenericEvent[client.Object]{}
		return nil
	}
	return &roleDefinitionReconciler{
		client:          withWatch,
		scheme:          scheme,
		recorder:        recorder,
		resourceTracker: discovery.NewResourceTracker(scheme, config, trackerCallback),
		trackerEvents:   trackerEvents,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for CRD creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of CRD, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller
func (r *roleDefinitionReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.Add(r.resourceTracker); err != nil {
		return err
	}

	// Channel to watch for CRD events to trigger re-reconcile of all RoleDefinitions
	crdTrackerChannel := source.Channel(r.trackerEvents, handler.EnqueueRequestsFromMapFunc(r.queueAll()))

	return ctrl.NewControllerManagedBy(mgr).
		For(&authnv1alpha1.RoleDefinition{}).
		WatchesRawSource(crdTrackerChannel).
		WithOptions(controller.TypedOptions[reconcile.Request]{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *roleDefinitionReconciler) queueAll() handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithName("roleDefinitionReconciler.queueAll")

		// List all RoleDefinition resources
		roleDefList := &authnv1alpha1.RoleDefinitionList{}
		err := r.client.List(ctx, roleDefList)
		if err != nil {
			logger.Error(err, "ERROR: Failed to list RoleDefinition resources")
			return nil
		}

		logger.V(3).Info("DEBUG: Found RoleDefinitions", "roleDefinitionCount", len(roleDefList.Items))

		requests := make([]reconcile.Request, len(roleDefList.Items))
		for i, roleDef := range roleDefList.Items {
			logger.V(3).Info("DEBUG: Enqueuing RoleDefinition reconciliation", "roleDefinition", roleDef.Name, "index", i)
			requests[i] = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      roleDef.Name,
					Namespace: roleDef.Namespace,
				},
			}
		}
		logger.V(2).Info("DEBUG: Returning reconciliation requests", "requestCount", len(requests))
		return requests
	}
}

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
func (r *roleDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting RoleDefinition reconciliation", "roleDefinitionName", req.Name, "namespace", req.Namespace)

	// Fetching the RoleDefinition custom resource from Kubernetes API
	roleDefinition := &authnv1alpha1.RoleDefinition{}
	err := r.client.Get(ctx, req.NamespacedName, roleDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("DEBUG: RoleDefinition not found - already deleted", "roleDefinitionName", req.Name, "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
		log.Error(err, "ERROR: Unable to fetch RoleDefinition resource from Kubernetes API", "roleDefinitionName", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, err
	}

	log.V(2).Info("DEBUG: RoleDefinition retrieved", "roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole, "targetName", roleDefinition.Spec.TargetName)

	// Declare the role early so we can work with it later
	var role client.Object
	var existingRole client.Object
	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		role = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: roleDefinition.Labels,
			},
		}
	case authnv1alpha1.DefinitionNamespacedRole:
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    roleDefinition.Labels,
			},
		}
	}

	// Check if RoleDefinition is marked to be deleted
	if roleDefinition.DeletionTimestamp.IsZero() {
		log.V(2).Info("DEBUG: RoleDefinition not marked for deletion - checking finalizer", "roleDefinitionName", roleDefinition.Name)

		if !controllerutil.ContainsFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer) {
			log.V(2).Info("DEBUG: Adding finalizer to RoleDefinition", "roleDefinitionName", roleDefinition.Name)
			controllerutil.AddFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.client.Update(ctx, roleDefinition); err != nil {
				log.Error(err, "ERROR: Failed to add finalizer", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Finalizer", "Adding finalizer to RoleDefinition %s", roleDefinition.Name)
		}
		conditions.MarkTrue(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		if err := r.client.Status().Update(ctx, roleDefinition); err != nil {
			log.Error(err, "ERROR: Failed to update FinalizerCondition status", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
	} else {
		// RoleDefinition is marked to be deleted
		log.V(1).Info("DEBUG: RoleDefinition marked for deletion - cleaning up resources", "roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole, "targetName", roleDefinition.Spec.TargetName)
		conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		err = r.client.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update DeleteCondition status", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		r.recorder.Eventf(roleDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		role.SetName(roleDefinition.Spec.TargetName)
		role.SetNamespace(roleDefinition.Spec.TargetNamespace)

		log.V(2).Info("DEBUG: Attempting to delete role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "roleType", roleDefinition.Spec.TargetRole)
		if err := r.client.Delete(ctx, role); apierrors.IsNotFound(err) {
			// If the resource is not found, we can safely remove the finalizer
			log.V(2).Info("DEBUG: Role not found - removing finalizer", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			controllerutil.RemoveFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.client.Update(ctx, roleDefinition); err != nil {
				log.Error(err, "ERROR: Failed to remove finalizer", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			log.V(1).Info("DEBUG: RoleDefinition deletion completed successfully", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, nil
		} else if err != nil {
			// If there is an error deleting the resource, requeue the request
			log.Error(err, "ERROR: Failed to delete role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			conditions.MarkFalse(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, "error deleting resource: %s", err.Error())
			if updateErr := r.client.Status().Update(ctx, roleDefinition); updateErr != nil {
				log.Error(updateErr, "ERROR: Failed to update status after deletion error", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, fmt.Errorf("deletion failed with error %s and a second error was found during update of role definition status: %w", err.Error(), updateErr)
			}
			return ctrl.Result{}, err
		}
		// requeue as the object is being deleted
		log.V(2).Info("DEBUG: Requeuing RoleDefinition deletion", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{Requeue: true}, nil
	}

	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIDiscoveryCondition, roleDefinition.Generation, authnv1alpha1.APIDiscoveryReason, authnv1alpha1.APIDiscoveryMessage)
	err = r.client.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update APIDiscoveryCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}
	apiResources, err := r.resourceTracker.GetAPIResources()
	if errors.Is(err, discovery.ResourceTrackerNotStartedError) {
		log.V(1).Info("DEBUG: ResourceTracker not started yet - requeuing reconciliation", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if err != nil {
		log.Error(err, "ERROR: Failed to get API resources from ResourceTracker", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	rulesByAPIGroupAndVerbs, err := r.filterAPIResourcesForRoleDefinition(ctx, roleDefinition, apiResources)
	if err != nil {
		log.Error(err, "ERROR: Failed to filter API resources for RoleDefinition", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIFilteredCondition, roleDefinition.Generation, authnv1alpha1.APIFilteredReason, authnv1alpha1.APIFilteredMessage)
	err = r.client.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update APIFilteredCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceDiscoveryCondition, roleDefinition.Generation, authnv1alpha1.ResourceDiscoveryReason, authnv1alpha1.ResourceDiscoveryMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceFilteredCondition, roleDefinition.Generation, authnv1alpha1.ResourceFilteredReason, authnv1alpha1.ResourceFilteredMessage)

	log.V(2).Info("DEBUG: Resource discovery and filtering completed", "roleDefinitionName", roleDefinition.Name, "rulesCount", len(rulesByAPIGroupAndVerbs), "scopeNamespaced", roleDefinition.Spec.ScopeNamespaced)

	err = r.client.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update status after resource discovery", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	// Create a slice of PolicyRules
	log.V(3).Info("DEBUG: Creating policy rules from filtered resources", "roleDefinitionName", roleDefinition.Name, "rulesCount", len(rulesByAPIGroupAndVerbs))

	// Convert the map back to a slice of PolicyRules
	finalRules := make([]rbacv1.PolicyRule, 0, len(rulesByAPIGroupAndVerbs))
	for _, rule := range rulesByAPIGroupAndVerbs {
		finalRules = append(finalRules, *rule)
	}
	// if we have a namespaced role, we add the nonResourceURL rule for metrics
	if roleDefinition.Spec.ScopeNamespaced && !slices.Contains(roleDefinition.Spec.RestrictedVerbs, "get") {
		finalRules = append(finalRules, rbacv1.PolicyRule{
			NonResourceURLs: []string{"/metrics"},
			Verbs:           []string{"get"},
		})
	}
	// Sort the resources within each PolicyRule
	for i := range finalRules {
		sort.Strings(finalRules[i].Resources)
		sort.Strings(finalRules[i].Verbs)
	}

	// Sort the finalRules slice for consistent ordering
	sort.Slice(finalRules, func(i, j int) bool {
		iRule := finalRules[i]
		jRule := finalRules[j]

		// Compare by APIGroup, then by Verbs
		if strings.Join(iRule.APIGroups, ",") != strings.Join(jRule.APIGroups, ",") {
			return strings.Join(iRule.APIGroups, ",") < strings.Join(jRule.APIGroups, ",")
		}
		return strings.Join(iRule.Verbs, ",") < strings.Join(jRule.Verbs, ",")
	})

	switch roleDefinition.Spec.TargetRole {
	case authnv1alpha1.DefinitionClusterRole:
		role = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: roleDefinition.Labels,
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.ClusterRole{}
	case authnv1alpha1.DefinitionNamespacedRole:
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    roleDefinition.Labels,
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.Role{}
	}

	// Create ClusterRole or Role
	log.V(2).Info("DEBUG: Checking if role exists", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "roleType", roleDefinition.Spec.TargetRole, "policyRuleCount", len(finalRules))

	err = r.client.Get(ctx, types.NamespacedName{Name: roleDefinition.Spec.TargetName, Namespace: roleDefinition.Spec.TargetNamespace}, existingRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("DEBUG: Role does not exist - creating new role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "roleType", roleDefinition.Spec.TargetRole)

			conditions.MarkUnknown(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.client.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update CreateCondition status", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			if err := controllerutil.SetControllerReference(roleDefinition, role, r.scheme); err != nil {
				log.Error(err, "ERROR: Failed to set controller reference", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				conditions.MarkFalse(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
				err = r.client.Status().Update(ctx, roleDefinition)
				if err != nil {
					log.Error(err, "ERROR: Failed to update status after OwnerRef error", "roleDefinitionName", roleDefinition.Name)
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

			if err := r.client.Create(ctx, role); err != nil {
				log.Error(err, "ERROR: Failed to create role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				return ctrl.Result{}, err
			}
			log.V(1).Info("DEBUG: Role created successfully", "roleDefinitionName", roleDefinition.Name, "roleName", role.GetName(), "roleType", roleDefinition.Spec.TargetRole)

			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.client.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update status after role creation", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}

			r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Creation", "Created target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		}
		return ctrl.Result{}, nil
	}

	// Update ClusterRole or Role
	var existingRules []rbacv1.PolicyRule
	switch t := existingRole.(type) {
	case *rbacv1.ClusterRole:
		existingRules = t.Rules
	case *rbacv1.Role:
		existingRules = t.Rules
	}

	rulesEqual := helpers.PolicyRulesEqual(existingRules, finalRules)
	if !rulesEqual {
		log.V(2).Info("DEBUG: Role rules differ - updating role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "existingRuleCount", len(existingRules), "newRuleCount", len(finalRules))

		switch t := existingRole.(type) {
		case *rbacv1.ClusterRole:
			t.Rules = finalRules
		case *rbacv1.Role:
			t.Rules = finalRules
		}

		if !controllerutil.HasControllerReference(existingRole) {
			log.V(2).Info("DEBUG: Role missing controller reference - setting it", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

			if err := controllerutil.SetControllerReference(roleDefinition, existingRole, r.scheme); err != nil {
				log.Error(err, "ERROR: Failed to set controller reference during update", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				err = r.client.Status().Update(ctx, roleDefinition)
				if err != nil {
					log.Error(err, "ERROR: Failed to update status after OwnerRef error during update", "roleDefinitionName", roleDefinition.Name)
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			err = r.client.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update status after OwnerRef set", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		}
		if err := r.client.Update(ctx, existingRole); err != nil {
			log.Error(err, "ERROR: Failed to update role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return ctrl.Result{}, err
		}
		log.V(1).Info("DEBUG: Role updated successfully", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

		conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation, authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
		conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
		err = r.client.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update status after role update", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		log.V(1).Info("DEBUG: Role updated successfully", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

		conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation, authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
		conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
		err = r.client.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update status after role update", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		r.recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Update", "Updated target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

		//for _, change := range changes {
		//	r.Recorder.Eventf(existingRole, corev1.EventTypeNormal, "RBACUpdate", "Updating RBAC rules for %s - %s", existingRole.GetName(), change)
		//}
	} else {
		log.V(3).Info("DEBUG: Role rules already up-to-date - no update needed", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
	}

	log.V(1).Info("DEBUG: RoleDefinition reconciliation completed successfully", "roleDefinitionName", roleDefinition.Name)
	return ctrl.Result{}, nil
}

func (r *roleDefinitionReconciler) filterAPIResourcesForRoleDefinition(
	ctx context.Context,
	roleDefinition *authnv1alpha1.RoleDefinition,
	apiResources discovery.APIResourcesByGroupVersion,
) (map[string]*rbacv1.PolicyRule, error) {
	log := log.FromContext(ctx)

	rulesByAPIGroupAndVerbs := make(map[string]*rbacv1.PolicyRule)

	// Filter API Resources based on RoleDefinition spec
	for gv, apiResources := range apiResources {
		groupVersion, err := schema.ParseGroupVersion(gv)
		if err != nil {
			log.Error(err, "ERROR: Failed to parse GroupVersion", "groupVersion", gv)
			continue
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
