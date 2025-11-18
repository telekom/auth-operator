package authorization

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
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

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	conditions "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/conditions"
	helpers "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/helpers"
)

// RoleDefinitionReconciler reconciles a RoleDefinition object
type RoleDefinitionReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	DiscoveryClient discovery.DiscoveryInterface
	Recorder        record.EventRecorder
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for CRD creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of CRD, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller
func (r *RoleDefinitionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authnv1alpha1.RoleDefinition{}).
		Watches(&apiextensionsv1.CustomResourceDefinition{},
			handler.EnqueueRequestsFromMapFunc(r.crdToRoleDefinitionRequests),
			builder.WithPredicates(predicate.Funcs{DeleteFunc: func(e event.DeleteEvent) bool { return false }})).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
func (r *RoleDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting RoleDefinition reconciliation", "roleDefinitionName", req.Name, "namespace", req.Namespace)

	// Fetching the RoleDefinition custom resource from Kubernetes API
	roleDefinition := &authnv1alpha1.RoleDefinition{}
	err := r.Get(ctx, req.NamespacedName, roleDefinition)
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
			if err := r.Update(ctx, roleDefinition); err != nil {
				log.Error(err, "ERROR: Failed to add finalizer", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Finalizer", "Adding finalizer to RoleDefinition %s", roleDefinition.Name)
		}
		conditions.MarkTrue(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		if err := r.Status().Update(ctx, roleDefinition); err != nil {
			log.Error(err, "ERROR: Failed to update FinalizerCondition status", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
	} else {
		// RoleDefinition is marked to be deleted
		log.V(1).Info("DEBUG: RoleDefinition marked for deletion - cleaning up resources", "roleDefinitionName", roleDefinition.Name, "targetRole", roleDefinition.Spec.TargetRole, "targetName", roleDefinition.Spec.TargetName)
		conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update DeleteCondition status", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(roleDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		role.SetName(roleDefinition.Spec.TargetName)
		role.SetNamespace(roleDefinition.Spec.TargetNamespace)

		log.V(2).Info("DEBUG: Attempting to delete role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "roleType", roleDefinition.Spec.TargetRole)
		if err := r.Delete(ctx, role); apierrors.IsNotFound(err) {
			// If the resource is not found, we can safely remove the finalizer
			log.V(2).Info("DEBUG: Role not found - removing finalizer", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			controllerutil.RemoveFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.Update(ctx, roleDefinition); err != nil {
				log.Error(err, "ERROR: Failed to remove finalizer", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			log.V(1).Info("DEBUG: RoleDefinition deletion completed successfully", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, nil
		} else if err != nil {
			// If there is an error deleting the resource, requeue the request
			log.Error(err, "ERROR: Failed to delete role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			conditions.MarkFalse(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, "error deleting resource: %s", err.Error())
			if updateErr := r.Status().Update(ctx, roleDefinition); updateErr != nil {
				log.Error(updateErr, "ERROR: Failed to update status after deletion error", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, fmt.Errorf("deletion failed with error %s and a second error was found during update of role definition status: %w", err.Error(), updateErr)
			}
			return ctrl.Result{}, err
		}
		// requeue as the object is being deleted
		log.V(2).Info("DEBUG: Requeuing RoleDefinition deletion", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{Requeue: true}, nil
	}

	// Fetch all existing API Groups and filter them against RestrictedAPIs
	log.V(2).Info("DEBUG: Starting API discovery", "roleDefinitionName", roleDefinition.Name)

	discoveredApiGroups, err := r.DiscoveryClient.ServerGroups()
	if err != nil {
		log.Error(err, "ERROR: Failed to discover API groups", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}
	log.V(2).Info("DEBUG: Discovered API groups", "roleDefinitionName", roleDefinition.Name, "groupCount", len(discoveredApiGroups.Groups))

	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIDiscoveryCondition, roleDefinition.Generation, authnv1alpha1.APIDiscoveryReason, authnv1alpha1.APIDiscoveryMessage)
	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update APIDiscoveryCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	var filteredApiGroups []metav1.APIGroup
	restrictedCount := 0
	for _, group := range discoveredApiGroups.Groups {
		restricted := false
		for _, restrictedAPI := range roleDefinition.Spec.RestrictedAPIs {
			if group.Name == restrictedAPI.Name {
				restricted = true
				restrictedCount++
				break
			}
		}
		if !restricted {
			log.V(3).Info("DEBUG: Including API group", "roleDefinitionName", roleDefinition.Name, "apiGroup", group.Name)
			filteredApiGroups = append(filteredApiGroups, group)
		} else {
			log.V(3).Info("DEBUG: Filtering out restricted API group", "roleDefinitionName", roleDefinition.Name, "apiGroup", group.Name)
		}
	}
	log.V(2).Info("DEBUG: API groups filtered", "roleDefinitionName", roleDefinition.Name, "includedCount", len(filteredApiGroups), "restrictedCount", restrictedCount)

	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIFilteredCondition, roleDefinition.Generation, authnv1alpha1.APIFilteredReason, authnv1alpha1.APIFilteredMessage)
	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update APIFilteredCondition status", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	// Fetch all existing API Resources and filter them against RestrictedResources
	var filteredApiResources []metav1.APIResource
	for _, filteredApiGroup := range filteredApiGroups {
		for _, filteredApiGroupVersion := range filteredApiGroup.Versions {
			discoveredApiResources, err := r.DiscoveryClient.ServerResourcesForGroupVersion(filteredApiGroupVersion.GroupVersion)
			if err != nil {
				return ctrl.Result{}, err
			}
			switch {
			// There are certain resources that are not know to the APIServer (and thus the DiscoveryClient) but are important to end up in the RoleDefinition.
			// These are added here manually.
			// nodes/metrics in the core group are not filtered by the RestrictedResources, as they are not part of the API discovery.
			case filteredApiGroup.Name == "" && filteredApiGroupVersion.Version == "v1":
				discoveredApiResources.APIResources = append(discoveredApiResources.APIResources, metav1.APIResource{
					Name:         "nodes/metrics",
					Namespaced:   false,
					Kind:         "node/metrics",
					Group:        "",
					Verbs:        []string{"get", "list", "watch"},
					ShortNames:   []string{"no"},
					SingularName: "node/metrics",
				})
			case filteredApiGroup.Name == "metrics.k8s.io" && filteredApiGroupVersion.Version == "v1":
				discoveredApiResources.APIResources = append(discoveredApiResources.APIResources, metav1.APIResource{
					Name:         "pods",
					Namespaced:   false,
					Kind:         "PodMetrics",
					Group:        "metrics.k8s.io",
					Verbs:        []string{"get", "list", "watch"},
					ShortNames:   []string{"po"},
					SingularName: "pod",
				})
				// there are also some verbs that are not part of the API discovery, but are important to end up in the RoleDefinition.
				// namely the "bind" and"escalate" verbs for roles and rolebindings
			case filteredApiGroup.Name == "rbac.authorization.k8s.io" && filteredApiGroupVersion.Version == "v1":
				discoveredApiResources.APIResources = append(discoveredApiResources.APIResources, metav1.APIResource{
					Name:         "roles",
					Namespaced:   true,
					Kind:         "Role",
					Group:        "rbac.authorization.k8s.io",
					Verbs:        []string{"get", "list", "watch", "create", "update", "patch", "delete", "bind", "escalate"},
					ShortNames:   []string{"role"},
					SingularName: "role",
				})
				discoveredApiResources.APIResources = append(discoveredApiResources.APIResources, metav1.APIResource{
					Name:         "rolebindings",
					Namespaced:   true,
					Kind:         "RoleBinding",
					Group:        "rbac.authorization.k8s.io",
					Verbs:        []string{"get", "list", "watch", "create", "update", "patch", "delete", "bind"},
					ShortNames:   []string{"rb"},
					SingularName: "rolebinding",
				})
			}

			for _, resource := range discoveredApiResources.APIResources {
				resource.Group = filteredApiGroup.Name
				if resource.Namespaced != roleDefinition.Spec.ScopeNamespaced {
					continue
				}
				// For things that end in /status or /finalizer, we append list and watch verbs for convenience, the verbs are not part of the API discovery and the apiserver has no behavior for them
				if strings.HasSuffix(resource.Name, "/status") || strings.HasSuffix(resource.Name, "/finalizer") {
					resource.Verbs = append(resource.Verbs, "list", "watch")
				}
				restricted := false
				for _, restrictedResource := range roleDefinition.Spec.RestrictedResources {
					if resource.Name == restrictedResource.Name && resource.Group == restrictedResource.Group {
						restricted = true
						break
					}
				}
				if !restricted {
					// Filter out restricted verbs based on RestrictedVerbs
					filteredVerbs := []string{}
					for _, verb := range resource.Verbs {
						verbRestricted := false
						for _, restrictedVerb := range roleDefinition.Spec.RestrictedVerbs {
							if verb == restrictedVerb {
								verbRestricted = true
								break
							}
						}
						if !verbRestricted {
							filteredVerbs = append(filteredVerbs, verb)
						}
					}
					// Only add the resource if there are remaining verbs after filtering
					if len(filteredVerbs) > 0 {
						resource.Verbs = filteredVerbs
						filteredApiResources = append(filteredApiResources, resource)
					}
				}
			}
		}
	}
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceDiscoveryCondition, roleDefinition.Generation, authnv1alpha1.ResourceDiscoveryReason, authnv1alpha1.ResourceDiscoveryMessage)
	conditions.MarkTrue(roleDefinition, authnv1alpha1.ResourceFilteredCondition, roleDefinition.Generation, authnv1alpha1.ResourceFilteredReason, authnv1alpha1.ResourceFilteredMessage)

	log.V(2).Info("DEBUG: Resource discovery and filtering completed", "roleDefinitionName", roleDefinition.Name, "filteredResourceCount", len(filteredApiResources), "scopeNamespaced", roleDefinition.Spec.ScopeNamespaced)

	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
		log.Error(err, "ERROR: Failed to update status after resource discovery", "roleDefinitionName", roleDefinition.Name)
		return ctrl.Result{}, err
	}

	// Create a slice of PolicyRules
	log.V(3).Info("DEBUG: Creating policy rules from filtered resources", "roleDefinitionName", roleDefinition.Name, "resourceCount", len(filteredApiResources))

	rules := []rbacv1.PolicyRule{}
	for _, resource := range filteredApiResources {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{resource.Group},
			Resources: []string{resource.Name},
			Verbs:     resource.Verbs,
		})
	}

	// Group PolicyRules by API groups and verbs
	groupedRules := make(map[string]*rbacv1.PolicyRule)
	for _, rule := range rules {
		// Create a unique key based on API groups and verbs
		key := fmt.Sprintf("%v|%v", rule.APIGroups, rule.Verbs)
		// Check if there is already a PolicyRule with the same API groups and verbs
		if existingRule, exists := groupedRules[key]; exists {
			// If exists, append the resources to the existing rule
			for _, resource := range rule.Resources {
				if !slices.Contains(existingRule.Resources, resource) {
					existingRule.Resources = append(existingRule.Resources, resource)
				}
			}
		} else {
			// If not, create a new entry in the map
			groupedRules[key] = &rbacv1.PolicyRule{
				APIGroups: rule.APIGroups,
				Resources: rule.Resources,
				Verbs:     rule.Verbs,
			}
		}
	}
	// Convert the map back to a slice of PolicyRules
	finalRules := make([]rbacv1.PolicyRule, 0, len(groupedRules))
	for _, rule := range groupedRules {
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
	}

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

	err = r.Get(ctx, types.NamespacedName{Name: roleDefinition.Spec.TargetName, Namespace: roleDefinition.Spec.TargetNamespace}, existingRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("DEBUG: Role does not exist - creating new role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName, "roleType", roleDefinition.Spec.TargetRole)

			conditions.MarkUnknown(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update CreateCondition status", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			if err := controllerutil.SetControllerReference(roleDefinition, role, r.Scheme); err != nil {
				log.Error(err, "ERROR: Failed to set controller reference", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				conditions.MarkFalse(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					log.Error(err, "ERROR: Failed to update status after OwnerRef error", "roleDefinitionName", roleDefinition.Name)
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

			if err := r.Create(ctx, role); err != nil {
				log.Error(err, "ERROR: Failed to create role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				return ctrl.Result{}, err
			}
			log.V(1).Info("DEBUG: Role created successfully", "roleDefinitionName", roleDefinition.Name, "roleName", role.GetName(), "roleType", roleDefinition.Spec.TargetRole)

			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update status after role creation", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}

			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Creation", "Created target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
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

			if err := controllerutil.SetControllerReference(roleDefinition, existingRole, r.Scheme); err != nil {
				log.Error(err, "ERROR: Failed to set controller reference during update", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					log.Error(err, "ERROR: Failed to update status after OwnerRef error during update", "roleDefinitionName", roleDefinition.Name)
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
				log.Error(err, "ERROR: Failed to update status after OwnerRef set", "roleDefinitionName", roleDefinition.Name)
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		}
		if err := r.Update(ctx, existingRole); err != nil {
			log.Error(err, "ERROR: Failed to update role", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
			return ctrl.Result{}, err
		}
		log.V(1).Info("DEBUG: Role updated successfully", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

		conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation, authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
		conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update status after role update", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		log.V(1).Info("DEBUG: Role updated successfully", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)

		conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation, authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
		conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			log.Error(err, "ERROR: Failed to update status after role update", "roleDefinitionName", roleDefinition.Name)
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Update", "Updated target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

		//for _, change := range changes {
		//	r.Recorder.Eventf(existingRole, corev1.EventTypeNormal, "RBACUpdate", "Updating RBAC rules for %s - %s", existingRole.GetName(), change)
		//}
	} else {
		log.V(3).Info("DEBUG: Role rules already up-to-date - no update needed", "roleDefinitionName", roleDefinition.Name, "roleName", roleDefinition.Spec.TargetName)
	}

	log.V(1).Info("DEBUG: RoleDefinition reconciliation completed successfully", "roleDefinitionName", roleDefinition.Name)
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// crdToRoleDefinitionRequests() implements the MapFunc type and makes it possible to return an EventHandler
// for any object implementing client.Object. Used it to fan-out updates to all RoleDefinitions on new CRD create
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#EnqueueRequestsFromMapFunc
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#MapFunc
func (r *RoleDefinitionReconciler) crdToRoleDefinitionRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	logger.V(2).Info("DEBUG: crdToRoleDefinitionRequests triggered", "objectName", obj.GetName())

	// Type assertion to ensure obj is a CRD
	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "ERROR: Expected *CustomResourceDefinition", "got", fmt.Sprintf("%T", obj))
		return nil
	}

	logger.V(2).Info("DEBUG: Processing CRD event", "crdName", crd.Name)

	// List all RoleDefinition resources
	roleDefList := &authnv1alpha1.RoleDefinitionList{}
	err := r.List(ctx, roleDefList)
	if err != nil {
		logger.Error(err, "ERROR: Failed to list RoleDefinition resources", "crdName", crd.Name)
		return nil
	}

	logger.V(3).Info("DEBUG: Found RoleDefinitions", "crdName", crd.Name, "roleDefinitionCount", len(roleDefList.Items))

	requests := make([]reconcile.Request, len(roleDefList.Items))
	for i, roleDef := range roleDefList.Items {
		logger.V(3).Info("DEBUG: Enqueuing RoleDefinition reconciliation", "crdName", crd.Name, "roleDefinition", roleDef.Name, "index", i)
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      roleDef.Name,
				Namespace: roleDef.Namespace,
			},
		}
	}
	logger.V(2).Info("DEBUG: Returning reconciliation requests", "crdName", crd.Name, "requestCount", len(requests))
	return requests
}
