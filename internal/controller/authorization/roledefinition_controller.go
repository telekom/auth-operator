package authorization

import (
	"context"
	"fmt"
	"sort"
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

	authnv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	conditions "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/conditions"
	helpers "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/helpers"
)

// RoleDefinitionReconciler reconciles a RoleDefinition object
type RoleDefinitionReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	DiscoveryClient discovery.DiscoveryInterface
	Recorder        record.EventRecorder
}

// crdToRoleDefinitionRequests() implements the MapFunc type and makes it possible to return an EventHandler
// for any object implementing client.Object. Used it to fan-out updates to all RoleDefinitions on new CRD create
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#EnqueueRequestsFromMapFunc
// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#MapFunc
func (r *RoleDefinitionReconciler) crdToRoleDefinitionRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	// Type assertion to ensure obj is a CRD
	_, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		log.FromContext(ctx).Error(fmt.Errorf("unexpected type"), "Expected *CustomResourceDefinition", "got", obj)
		return nil
	}

	// List all RoleDefinition resources
	roleDefList := &authnv1alpha1.RoleDefinitionList{}
	err := r.Client.List(ctx, roleDefList)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to list RoleDefinition resources")
		return nil
	}
	requests := make([]reconcile.Request, len(roleDefList.Items))
	for i, roleDef := range roleDefList.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      roleDef.Name,
				Namespace: roleDef.Namespace,
			},
		}
	}
	return requests
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

	// Fetching the RoleDefinition custom resource from Kubernetes API
	roleDefinition := &authnv1alpha1.RoleDefinition{}
	err := r.Get(ctx, req.NamespacedName, roleDefinition)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Unable to fetch RoleDefinition resource from Kubernetes API")
		return ctrl.Result{}, err
	}

	// Declare the role early so we can work with it later
	var role client.Object
	var existingRole client.Object
	if roleDefinition.Spec.TargetRole == authnv1alpha1.DefinitionClusterRole {
		role = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: roleDefinition.ObjectMeta.Labels,
			},
		}
	} else if roleDefinition.Spec.TargetRole == authnv1alpha1.DefinitionNamespacedRole {
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    roleDefinition.ObjectMeta.Labels,
			},
		}
	}

	// Check if RoleDefinition is marked to be deleted
	if roleDefinition.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer) {
			controllerutil.AddFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.Update(ctx, roleDefinition); err != nil {
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Finalizer", "Adding finalizer to RoleDefinition %s", roleDefinition.Name)
		}
		conditions.MarkTrue(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		if err := r.Status().Update(ctx, roleDefinition); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// RoleDefinition is marked to be deleted
		log.Info("Deleting generated ClusterRole/Role for the RoleDefinition, as it is marked for deletion")
		conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(roleDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		if controllerutil.ContainsFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer) {
			if err := r.Client.Get(ctx, types.NamespacedName{Name: roleDefinition.Spec.TargetName, Namespace: roleDefinition.Spec.TargetNamespace}, role); err != nil {
				if apierrors.IsNotFound(err) {
					conditions.MarkUnknown(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
					err = r.Status().Update(ctx, roleDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, nil
				}
				conditions.MarkFalse(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			err := r.Client.Delete(ctx, role)
			if err != nil {
				conditions.MarkTrue(roleDefinition, authnv1alpha1.DeleteCondition, roleDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(roleDefinition, authnv1alpha1.RoleDefinitionFinalizer)
			if err := r.Update(ctx, roleDefinition); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		conditions.MarkFalse(roleDefinition, authnv1alpha1.FinalizerCondition, roleDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Fetch all existing API Groups and filter them against RestrictedAPIs
	discoveredApiGroups, err := r.DiscoveryClient.ServerGroups()
	if err != nil {
		return ctrl.Result{}, err
	}
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIDiscoveryCondition, roleDefinition.Generation, authnv1alpha1.APIDiscoveryReason, authnv1alpha1.APIDiscoveryMessage)
	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	var filteredApiGroups []metav1.APIGroup
	for _, group := range discoveredApiGroups.Groups {
		restricted := false
		for _, restrictedAPI := range roleDefinition.Spec.RestrictedAPIs {
			if group.Name == restrictedAPI.Name {
				restricted = true
				break
			}
		}
		if !restricted {
			filteredApiGroups = append(filteredApiGroups, group)
		}
	}
	conditions.MarkTrue(roleDefinition, authnv1alpha1.APIFilteredCondition, roleDefinition.Generation, authnv1alpha1.APIFilteredReason, authnv1alpha1.APIFilteredMessage)
	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
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

			for _, resource := range discoveredApiResources.APIResources {
				resource.Group = filteredApiGroup.Name
				restricted := false
				for _, restrictedResource := range roleDefinition.Spec.RestrictedResources {
					if resource.Name == restrictedResource.Name && resource.Group == restrictedResource.Group {
						restricted = true
						break
					} else if resource.Namespaced != roleDefinition.Spec.ScopeNamespaced {
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
	err = r.Status().Update(ctx, roleDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create a slice of PolicyRules
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
			existingRule.Resources = append(existingRule.Resources, rule.Resources...)
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
	// Sort the resources within each PolicyRule
	for i := range finalRules {
		sort.Strings(finalRules[i].Resources)
	}

	if roleDefinition.Spec.TargetRole == authnv1alpha1.DefinitionClusterRole {
		role = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   roleDefinition.Spec.TargetName,
				Labels: roleDefinition.ObjectMeta.Labels,
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.ClusterRole{}
	} else if roleDefinition.Spec.TargetRole == authnv1alpha1.DefinitionNamespacedRole {
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleDefinition.Spec.TargetName,
				Namespace: roleDefinition.Spec.TargetNamespace,
				Labels:    roleDefinition.ObjectMeta.Labels,
			},
			Rules: finalRules,
		}
		existingRole = &rbacv1.Role{}
	}

	// Create ClusterRole or Role
	err = r.Client.Get(ctx, types.NamespacedName{Name: roleDefinition.Spec.TargetName, Namespace: roleDefinition.Spec.TargetNamespace}, existingRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			conditions.MarkUnknown(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
				return ctrl.Result{}, err
			}
			if err := controllerutil.SetControllerReference(roleDefinition, role, r.Scheme); err != nil {
				conditions.MarkFalse(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
			if err := r.Client.Create(ctx, role); err != nil {
				return ctrl.Result{}, err
			}
			log.Info("Created ClusterRole/Role", "ClusterRole/Role", role)
			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			conditions.MarkTrue(roleDefinition, authnv1alpha1.CreateCondition, roleDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
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
		switch t := existingRole.(type) {
		case *rbacv1.ClusterRole:
			t.Rules = finalRules
		case *rbacv1.Role:
			t.Rules = finalRules
		}

		if !controllerutil.HasControllerReference(existingRole) {
			if err := controllerutil.SetControllerReference(roleDefinition, existingRole, r.Scheme); err != nil {
				err = r.Status().Update(ctx, roleDefinition)
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}
			conditions.MarkTrue(roleDefinition, authnv1alpha1.OwnerRefCondition, roleDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
			err = r.Status().Update(ctx, roleDefinition)
			if err != nil {
				return ctrl.Result{}, err
			}
			r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "OwnerRef", "Setting Owner reference for %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)
		}
		if err := r.Client.Update(ctx, existingRole); err != nil {
			return ctrl.Result{}, err
		}
		conditions.MarkTrue(roleDefinition, authnv1alpha1.UpdateCondition, roleDefinition.Generation, authnv1alpha1.UpdateReason, authnv1alpha1.UpdateMessage)
		conditions.Delete(roleDefinition, authnv1alpha1.CreateCondition)
		err = r.Status().Update(ctx, roleDefinition)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Updated ClusterRole/Role", "ClusterRole/Role", existingRole)
		r.Recorder.Eventf(roleDefinition, corev1.EventTypeNormal, "Update", "Updated target resource %s %s", roleDefinition.Spec.TargetRole, roleDefinition.Spec.TargetName)

		//for _, change := range changes {
		//	r.Recorder.Eventf(existingRole, corev1.EventTypeNormal, "RBACUpdate", "Updating RBAC rules for %s - %s", existingRole.GetName(), change)
		//}
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
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
