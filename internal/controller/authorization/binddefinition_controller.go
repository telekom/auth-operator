package authorization

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
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

// bindDefinitionReconciler defines the reconciler for BindDefinition and reconciles a BindDefinition object.
type bindDefinitionReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	DiscoveryClient discovery.DiscoveryInterface
	DynamicClient   dynamic.Interface
	Recorder        record.EventRecorder
}

func NewBindDefinitionReconciler(
	config *rest.Config,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
) (*bindDefinitionReconciler, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create discovery client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	client, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %w", err)
	}

	return &bindDefinitionReconciler{
		DiscoveryClient: discoveryClient,
		Client:          client,
		DynamicClient:   dynamicClient,
		Scheme:          scheme,
		Recorder:        recorder,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for namespace creation events https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/handler#example-EnqueueRequestsFromMapFunc
// Used a predicate to ignore deletes of namespace, as this can be done in a regular
// reconcile requeue and does not require immediate action from controller
func (r *bindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager) error {
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
	err := r.List(ctx, bindDefList)
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

// ResourceBlocking represents a resource type and the specific instances blocking namespace deletion
type ResourceBlocking struct {
	ResourceType string // e.g., "pods", "persistentvolumeclaims"
	APIGroup     string // e.g., "", "apps"
	Count        int
	Names        []string // List of specific resource names
}

// For checking if terminating namespace has deleting resources
// Needed for RoleBinding finalizer removal
// Returns: hasResources (bool), blockingResources ([]ResourceBlocking), error
func (r *bindDefinitionReconciler) namespaceHasResources(ctx context.Context, namespace string) (bool, []ResourceBlocking, error) {
	log := log.FromContext(ctx)
	log.V(2).Info("DEBUG: Starting namespace resource check", "namespace", namespace)

	// Get all namespaced api resources
	apiResourceLists, err := r.DiscoveryClient.ServerPreferredNamespacedResources()
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			log.Info("Warning: partial discovery failure. Some APIs may be skipped", "error", err)
		} else {
			return false, nil, fmt.Errorf("unrecoverable discovery error: %w", err)
		}
	}
	log.V(3).Info("DEBUG: Discovery client returned API resource lists", "namespace", namespace, "groupCount", len(apiResourceLists))

	resourcesChecked := 0
	resourcesSkipped := 0
	var blockingResources []ResourceBlocking

	for _, resourceList := range apiResourceLists {
		gv, parseErr := schema.ParseGroupVersion(resourceList.GroupVersion)
		if parseErr != nil {
			// skip malformed group/version
			log.V(4).Info("DEBUG: Skipping malformed GroupVersion", "namespace", namespace, "groupVersion", resourceList.GroupVersion, "error", parseErr)
			resourcesSkipped++
			continue
		}

		for _, resource := range resourceList.APIResources {
			if strings.Contains(resource.Name, "/") || strings.Contains(resource.Name, "rolebindings") {
				// ignore subresources and rolebinding resources
				log.V(4).Info("DEBUG: Skipping subresource or rolebinding", "namespace", namespace, "resource", resource.Name, "groupVersion", resourceList.GroupVersion)
				resourcesSkipped++
				continue
			}

			if !supportsList(resource.Verbs) {
				// if resource does not support "list", skip it
				log.V(4).Info("DEBUG: Skipping resource without list verb", "namespace", namespace, "resource", resource.Name, "groupVersion", resourceList.GroupVersion)
				resourcesSkipped++
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    gv.Group,
				Version:  gv.Version,
				Resource: resource.Name,
			}

			log.V(3).Info("DEBUG: Listing resource in namespace", "namespace", namespace, "gvr", gvr.String())

			// using dynamic client to not instantiate all typed clients
			list, err := r.DynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				log.V(2).Info("DEBUG: Skipping resource due to list error", "namespace", namespace, "resource", gvr.String(), "error", err)
				resourcesSkipped++
				continue
			}

			resourcesChecked++
			if len(list.Items) > 0 {
				log.V(2).Info("DEBUG: Found resources in namespace - will NOT remove finalizers", "namespace", namespace, "gvr", gvr.String(), "itemCount", len(list.Items))

				// Collect names of blocking resources (limit to first 10)
				var resourceNames []string
				for i, item := range list.Items {
					if i < 10 { // Collect up to 10 resource names for event
						resourceNames = append(resourceNames, item.GetName())
						log.V(3).Info("DEBUG: Found resource", "namespace", namespace, "gvr", gvr.String(), "name", item.GetName(), "index", i)
					}
				}

				// Add to blocking resources list
				blockingResources = append(blockingResources, ResourceBlocking{
					ResourceType: resource.Name,
					APIGroup:     gv.Group,
					Count:        len(list.Items),
					Names:        resourceNames,
				})
			}
			log.V(3).Info("DEBUG: No resources found", "namespace", namespace, "gvr", gvr.String())
		}

	}

	// If we found blocking resources, return them all
	if len(blockingResources) > 0 {
		log.V(2).Info("DEBUG: Found blocking resources in namespace", "namespace", namespace, "blockingResourceCount", len(blockingResources))
		return true, blockingResources, nil
	}

	// no resources found
	log.V(2).Info("DEBUG: Namespace has no resources - can remove finalizers", "namespace", namespace, "resourcesChecked", resourcesChecked, "resourcesSkipped", resourcesSkipped)
	return false, nil, nil
}

func supportsList(verbs []string) bool {
	for _, verb := range verbs {
		if verb == "list" {
			return true
		}
	}
	return false
}

// formatBlockingResourcesMessage creates a detailed event message about what resources are blocking namespace deletion
func formatBlockingResourcesMessage(blockingResources []ResourceBlocking) string {
	if len(blockingResources) == 0 {
		return "Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup"
	}

	// Build detailed message
	msg := "Namespace deletion is waiting for: "
	resourceDetails := []string{}

	for _, rb := range blockingResources {
		var resourceType string
		if rb.APIGroup == "" {
			resourceType = rb.ResourceType
		} else {
			resourceType = fmt.Sprintf("%s (%s)", rb.ResourceType, rb.APIGroup)
		}

		if rb.Count == 1 && len(rb.Names) > 0 {
			resourceDetails = append(resourceDetails, fmt.Sprintf("%s: %s", resourceType, rb.Names[0]))
		} else if len(rb.Names) > 0 {
			// Show first few names if multiple
			if len(rb.Names) <= 3 {
				resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d): %s", resourceType, rb.Count, strings.Join(rb.Names, ", ")))
			} else {
				resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d): %s, +%d more", resourceType, rb.Count, strings.Join(rb.Names[:3], ", "), rb.Count-3))
			}
		} else {
			resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d)", resourceType, rb.Count))
		}
	}

	return msg + strings.Join(resourceDetails, "; ")
}

// For checking if terminating BindDefinition refers a ServiceAccount
// that other non-terminating BindDefinitions reference
func (r *bindDefinitionReconciler) isSAReferencedByOtherBindDefs(ctx context.Context, currentBindDefName, saName, saNamespace string) (bool, error) {
	// List all BindDefinitions
	bindDefList := &authnv1alpha1.BindDefinitionList{}
	err := r.List(ctx, bindDefList)
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
func (r *bindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
	if !bindDefinition.DeletionTimestamp.IsZero() {
		resultDelete, err := r.reconcileDelete(ctx, bindDefinition)
		if err != nil {
			log.Error(err, "Error occurred in reconcileDelete function")
			return resultDelete, err
		}
	} else {
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

		// Check if any target namespaces are terminating and need cleanup
		resultTerminating, err := r.reconcileTerminatingNamespaces(ctx, bindDefinition)
		if err != nil {
			log.Error(err, "Error occurred in reconcileTerminatingNamespaces function")
			return resultTerminating, err
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

// reconcileTerminatingNamespaces handles cleanup of RoleBindings when target namespaces are terminating
// This is called when a BindDefinition is being reconciled due to a namespace event where the namespace
// is in Terminating phase. We only remove finalizers if the namespace has no other remaining resources.
func (r *bindDefinitionReconciler) reconcileTerminatingNamespaces(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(2).Info("DEBUG: Starting reconcileTerminatingNamespaces", "bindDefinitionName", bindDefinition.Name)

	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	log.V(2).Info("DEBUG: Processing RoleBindings to find target namespaces", "bindDefinitionName", bindDefinition.Name, "roleBindingCount", len(bindDefinition.Spec.RoleBindings))

	for i, RoleBinding := range bindDefinition.Spec.RoleBindings {
		log.V(3).Info("DEBUG: Processing RoleBinding selector", "bindDefinitionName", bindDefinition.Name, "index", i, "selectorCount", len(RoleBinding.NamespaceSelector))

		for j, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				log.V(3).Info("DEBUG: Found namespace selector", "bindDefinitionName", bindDefinition.Name, "roleBindingIndex", i, "selectorIndex", j)

				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					log.Error(err, "ERROR: Failed to convert namespace selector", "bindDefinitionName", bindDefinition.Name)
					return ctrl.Result{}, err
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.List(ctx, namespaceList, listOpts...)
				if err != nil {
					log.Error(err, "ERROR: Failed to list namespaces", "bindDefinitionName", bindDefinition.Name, "selector", selector)
					return ctrl.Result{}, err
				}
				log.V(2).Info("DEBUG: Found namespaces", "bindDefinitionName", bindDefinition.Name, "selector", selector, "namespaceCount", len(namespaceList.Items))

				// Add terminating namespaces to the set
				for _, ns := range namespaceList.Items {
					if ns.Status.Phase == corev1.NamespaceTerminating {
						log.V(3).Info("DEBUG: Adding terminating namespace to set", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
						namespaceSet[ns.Name] = ns
					}
				}
			}
		}
	}

	// Process terminating namespaces and clean up RoleBindings only if namespace has no other resources
	log.V(2).Info("DEBUG: Processing terminating namespaces for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name, "terminatingNamespaceCount", len(namespaceSet))

	for _, ns := range namespaceSet {
		log.V(2).Info("DEBUG: Checking if terminating namespace has remaining resources", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)

		// Check if namespace has any remaining resources before cleanup
		resourcesExist, blockingResources, err := r.namespaceHasResources(ctx, ns.Name)
		if err != nil {
			log.Error(err, "ERROR: Failed to check if namespace has resources", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
			return ctrl.Result{}, err
		}

		if resourcesExist {
			log.V(1).Info("DEBUG: Terminating namespace still has resources - NOT removing RoleBinding finalizers", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)

			// Log detailed information about blocking resources
			for _, br := range blockingResources {
				resourceType := br.ResourceType
				if br.APIGroup != "" {
					resourceType = fmt.Sprintf("%s.%s", br.ResourceType, br.APIGroup)
				}
				log.V(1).Info("DEBUG: Blocking resource found", "namespace", ns.Name, "resourceType", resourceType, "count", br.Count, "names", br.Names)
			}

			// Emit event on the namespace to inform users about pending deletions with details
			nsObj := &corev1.Namespace{}
			if err := r.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
				// Build detailed message about blocking resources
				eventMsg := formatBlockingResourcesMessage(blockingResources)
				r.Recorder.Eventf(nsObj, corev1.EventTypeWarning, "DeletionPending", eventMsg)
			}
			continue
		}

		log.V(1).Info("DEBUG: Terminating namespace has no more resources - proceeding to remove RoleBinding finalizers", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)

		// List all RoleBindings in the namespace that match this BindDefinition
		roleBindingList := &rbacv1.RoleBindingList{}
		listOpts := []client.ListOption{
			client.InNamespace(ns.Name),
			client.MatchingLabels(bindDefinition.Labels),
		}
		err = r.List(ctx, roleBindingList, listOpts...)
		if err != nil {
			log.Error(err, "ERROR: Failed to list RoleBindings", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
			return ctrl.Result{}, err
		}
		log.V(2).Info("DEBUG: Found RoleBindings to clean up", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingCount", len(roleBindingList.Items))

		for idx, roleBinding := range roleBindingList.Items {
			log.V(3).Info("DEBUG: Processing RoleBinding for finalizer removal", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name, "index", idx)

			if controllerutil.ContainsFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
				log.V(2).Info("DEBUG: Removing finalizer from RoleBinding in terminating namespace", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
				controllerutil.RemoveFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer)
				if err := r.Update(ctx, &roleBinding); err != nil {
					log.Error(err, "ERROR: Failed to remove finalizer from RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBinding", roleBinding.Name, "namespace", ns.Name)
					return ctrl.Result{}, err
				}
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "FinalizerRemoved", "Removed finalizer from RoleBinding %s in terminating namespace %s", roleBinding.Name, ns.Name)
				log.V(1).Info("DEBUG: Successfully removed finalizer from RoleBinding in terminating namespace", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
			} else {
				log.V(3).Info("DEBUG: RoleBinding does not have finalizer", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
			}
		}

		// Emit event on namespace indicating cleanup is complete
		nsObj := &corev1.Namespace{}
		if err := r.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
			r.Recorder.Eventf(nsObj, corev1.EventTypeNormal, "AuthOperatorCleanup", "Auth-operator completed cleanup of RoleBindings in terminating namespace, allowing deletion to proceed")
		}
	}

	log.V(2).Info("DEBUG: reconcileTerminatingNamespaces completed", "bindDefinitionName", bindDefinition.Name)
	return ctrl.Result{}, nil
}

func (r *bindDefinitionReconciler) reconcileDelete(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting reconcileDelete", "bindDefinition", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// Construct namespace list from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	log.V(2).Info("DEBUG: Processing RoleBindings to find target namespaces", "bindDefinitionName", bindDefinition.Name, "roleBindingCount", len(bindDefinition.Spec.RoleBindings))

	for i, RoleBinding := range bindDefinition.Spec.RoleBindings {
		log.V(3).Info("DEBUG: Processing RoleBinding", "bindDefinitionName", bindDefinition.Name, "index", i, "selectorCount", len(RoleBinding.NamespaceSelector))

		for j, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				log.V(3).Info("DEBUG: Found non-empty namespace selector", "bindDefinitionName", bindDefinition.Name, "roleBindingIndex", i, "selectorIndex", j, "selector", nsSelector)

				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					log.Error(err, "ERROR: Failed to convert LabelSelector to Selector", "bindDefinitionName", bindDefinition.Name, "selector", nsSelector)
					return ctrl.Result{}, err
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.List(ctx, namespaceList, listOpts...)
				if err != nil {
					log.Error(err, "ERROR: Failed to list namespaces by selector", "bindDefinitionName", bindDefinition.Name, "selector", selector)
					return ctrl.Result{}, err
				}
				log.V(2).Info("DEBUG: Found namespaces matching selector", "bindDefinitionName", bindDefinition.Name, "selector", selector, "namespaceCount", len(namespaceList.Items))

				for _, ns := range namespaceList.Items {
					log.V(3).Info("DEBUG: Adding namespace to set", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "phase", ns.Status.Phase)
					namespaceSet[ns.Name] = ns
				}
			} else {
				log.V(4).Info("DEBUG: Skipping empty namespace selector", "bindDefinitionName", bindDefinition.Name, "roleBindingIndex", i, "selectorIndex", j)
			}
		}

		// Handle terminating namespaces and check if they have any resources
		log.V(2).Info("DEBUG: Processing namespaces for terminating check", "bindDefinitionName", bindDefinition.Name, "namespaceCount", len(namespaceSet))

		for _, ns := range namespaceSet {
			log.V(3).Info("DEBUG: Checking namespace phase", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "phase", ns.Status.Phase)

			if ns.Status.Phase == corev1.NamespaceTerminating {
				log.V(1).Info("DEBUG: Namespace is terminating - will check for remaining resources", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)

				resourcesExist, blockingResources, err := r.namespaceHasResources(ctx, ns.Name)
				if err != nil {
					log.Error(err, "ERROR: Failed to check if namespace has resources", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
					return ctrl.Result{}, err
				}

				// Handle RoleBinding finalizers for resources in namespace
				if resourcesExist {
					log.V(1).Info("DEBUG: Namespace still has resources - NOT removing RoleBinding finalizers", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
					// Emit event on the namespace to inform users about pending deletions
					nsObj := &corev1.Namespace{}
					if err := r.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
						eventMsg := formatBlockingResourcesMessage(blockingResources)
						r.Recorder.Eventf(nsObj, corev1.EventTypeWarning, "DeletionPending", eventMsg)
					}
					continue
				} else {
					log.V(1).Info("DEBUG: Namespace has no more resources - proceeding to remove RoleBinding finalizers", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)

					roleBindingList := &rbacv1.RoleBindingList{}
					listOpts := []client.ListOption{
						client.InNamespace(ns.Name),
						client.MatchingLabels(bindDefinition.Labels),
					}
					err := r.List(ctx, roleBindingList, listOpts...)
					if err != nil {
						log.Error(err, "ERROR: Failed to list RoleBindings", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name)
						return ctrl.Result{}, err
					}
					log.V(2).Info("DEBUG: Found RoleBindings in namespace", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingCount", len(roleBindingList.Items))

					for idx, roleBinding := range roleBindingList.Items {
						log.V(3).Info("DEBUG: Processing RoleBinding for finalizer removal", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name, "index", idx)

						if controllerutil.ContainsFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
							log.V(2).Info("DEBUG: Removing finalizer from RoleBinding", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
							controllerutil.RemoveFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer)
							if err := r.Update(ctx, &roleBinding); err != nil {
								log.Error(err, "ERROR: Failed to remove finalizer from RoleBinding (terminating namespace cleanup)", "bindDefinitionName", bindDefinition.Name, "roleBinding", roleBinding.Name, "namespace", ns.Name)
								return ctrl.Result{}, err
							}
							r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "FinalizerRemoved", "Removed finalizer from RoleBinding %s in namespace %s", roleBinding.Name, ns.Name)
							log.V(1).Info("DEBUG: Successfully removed finalizer from RoleBinding", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
						} else {
							log.V(3).Info("DEBUG: RoleBinding does not have finalizer", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBinding", roleBinding.Name)
						}
					}
				}
			} else {
				log.V(4).Info("DEBUG: Namespace is not terminating", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "phase", ns.Status.Phase)
			}
		}
	}

	// RoleDefinition is marked to be deleted
	log.V(1).Info("DEBUG: BindDefinition marked for deletion - deleting generated ServiceAccounts, ClusterRoleBindings and RoleBindings", "bindDefinitionName", bindDefinition.Name)
	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	err := r.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Delete ServiceAccounts specified in Subjects if we have an OwnerRef for them
	log.V(2).Info("DEBUG: Processing subjects for deletion", "bindDefinitionName", bindDefinition.Name, "subjectCount", len(bindDefinition.Spec.Subjects))

	for idx, subject := range bindDefinition.Spec.Subjects {
		log.V(3).Info("DEBUG: Processing subject", "bindDefinitionName", bindDefinition.Name, "index", idx, "kind", subject.Kind, "name", subject.Name, "namespace", subject.Namespace)

		if subject.Kind == authnv1alpha1.BindSubjectServiceAccount {
			sa := &corev1.ServiceAccount{}
			err := r.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
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
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s/%s in namespace %s", subject.Kind, subject.Name, subject.Namespace)
					log.V(1).Info("DEBUG: Cleanup ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					// Generated service account doesn't have auth-operator finalizer
					err = r.Delete(ctx, sa)
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
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", subject.Kind, subject.Name, subject.Namespace)
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

		err := r.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				log.V(2).Info("DEBUG: ClusterRoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				continue
			} else {
				log.Error(err, "ERROR: Unable to fetch ClusterRoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
				errStatus := r.Status().Update(ctx, bindDefinition)
				if errStatus != nil {
					return ctrl.Result{}, errStatus
				}
				return ctrl.Result{}, err
			}
		}
		if controllerutil.HasControllerReference(clusterRoleBinding) {
			r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Deleting target resource %s %s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			log.V(1).Info("DEBUG: Cleanup ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBinding.Name)
			// Generated ClusterRoleBinding doesn't have finalizer, delete is enough
			err = r.Delete(ctx, clusterRoleBinding)
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
			r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s because we do not have OwnerRef set for it", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			log.V(1).Info("DEBUG: Cannot delete ClusterRoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
		}
	}

	// For each namespace cleanup rolebindings referenced in the BindDefinition
	log.V(2).Info("DEBUG: Processing namespaces for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name, "namespaceCount", len(namespaceSet))

	for nsIdx, ns := range namespaceSet {
		log.V(2).Info("DEBUG: Processing namespace for RoleBinding cleanup", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "index", nsIdx)

		for rbIdx, RoleBinding := range bindDefinition.Spec.RoleBindings {
			log.V(3).Info("DEBUG: Processing RoleBinding spec", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "rbIndex", rbIdx, "clusterRoleRefCount", len(RoleBinding.ClusterRoleRefs), "roleRefCount", len(RoleBinding.RoleRefs))

			// Delete RoleBindings for ClusterRoleRefs
			for crIdx, clusterRoleRef := range RoleBinding.ClusterRoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, clusterRoleRef, "binding")
				log.V(3).Info("DEBUG: Looking up RoleBinding (ClusterRoleRef)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "crIndex", crIdx, "roleBindingName", roleBindingName)

				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						log.V(2).Info("DEBUG: RoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						continue
					} else {
						log.Error(err, "ERROR: Unable to fetch RoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						errStatus := r.Status().Update(ctx, bindDefinition)
						if errStatus != nil {
							return ctrl.Result{}, errStatus
						}
						return ctrl.Result{}, err
					}
				}
				if controllerutil.HasControllerReference(roleBinding) {
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cleanup RoleBinding based on ClusterRoleRefs", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", roleBinding.Namespace)

					controllerutil.RemoveFinalizer(roleBinding, authnv1alpha1.RoleBindingFinalizer)
					if err = r.Update(ctx, roleBinding); err != nil {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "FinalizerDeletion", "Failed to remove finalizer from resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
						log.Error(err, "ERROR: Failed to remove finalizer from RoleBinding (ClusterRoleRefs cleanup)", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
						return ctrl.Result{}, err
					}
					log.V(2).Info("DEBUG: Removed finalizer from RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)

					err = r.Delete(ctx, roleBinding)
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
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cannot delete RoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				}
			}
		}

		for _, RoleBinding := range bindDefinition.Spec.RoleBindings {
			// Delete RoleBindings for RoleRefs
			for rrIdx, roleRef := range RoleBinding.RoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, roleRef, "binding")
				log.V(3).Info("DEBUG: Looking up RoleBinding (RoleRef)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "rrIndex", rrIdx, "roleBindingName", roleBindingName)

				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
				if err != nil {
					if apierrors.IsNotFound(err) {
						log.V(2).Info("DEBUG: RoleBinding not found (already deleted)", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						continue
					} else {
						log.Error(err, "ERROR: Unable to fetch RoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "roleBindingName", roleBindingName)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
						errStatus := r.Status().Update(ctx, bindDefinition)
						if errStatus != nil {
							return ctrl.Result{}, errStatus
						}
						return ctrl.Result{}, err
					}
				}
				if controllerutil.HasControllerReference(roleBinding) {
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "Deletion", "Deleting target resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cleanup RoleBinding based on RoleRefs", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", roleBinding.Namespace)

					controllerutil.RemoveFinalizer(roleBinding, authnv1alpha1.RoleBindingFinalizer)
					if err = r.Update(ctx, roleBinding); err != nil {
						r.Recorder.Eventf(bindDefinition, corev1.EventTypeWarning, "FinalizerDeletion", "Failed to remove finalizer from resource %s/%s in namespace %s", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
						log.Error(err, "ERROR: Failed to remove finalizer from RoleBinding (RoleRefs cleanup)", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
						return ctrl.Result{}, err
					}
					log.V(2).Info("DEBUG: Removed finalizer from RoleBinding", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)

					err = r.Delete(ctx, roleBinding)
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
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Deletion", "Not deleting target resource %s/%s in namespace %s because we do not have OwnerRef set for it", roleBinding.Kind, roleBinding.Name, roleBinding.Namespace)
					log.V(1).Info("DEBUG: Cannot delete RoleBinding - no OwnerRef", "bindDefinitionName", bindDefinition.Name, "roleBindingName", roleBinding.Name, "namespace", ns.Name)
				}
			}
		}
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.DeleteCondition, bindDefinition.Generation, authnv1alpha1.DeleteReason, authnv1alpha1.DeleteMessage)
	conditions.MarkFalse(bindDefinition, authnv1alpha1.FinalizerCondition, bindDefinition.Generation, authnv1alpha1.FinalizerReason, authnv1alpha1.FinalizerMessage)
	err = r.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	log.V(2).Info("DEBUG: Removing BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)
	controllerutil.RemoveFinalizer(bindDefinition, authnv1alpha1.BindDefinitionFinalizer)
	if err := r.Update(ctx, bindDefinition); err != nil {
		log.Error(err, "ERROR: Failed to remove BindDefinition finalizer", "bindDefinitionName", bindDefinition.Name)
		return ctrl.Result{}, err
	}
	log.V(1).Info("DEBUG: reconcileDelete completed successfully", "bindDefinitionName", bindDefinition.Name)

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// Reconcile BindDefinition method
func (r *bindDefinitionReconciler) reconcileCreate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("DEBUG: Starting reconcileCreate", "bindDefinitionName", bindDefinition.Name, "namespace", bindDefinition.Namespace)

	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	log.V(2).Info("DEBUG: Processing RoleBindings to find target namespaces", "bindDefinitionName", bindDefinition.Name, "roleBindingCount", len(bindDefinition.Spec.RoleBindings))

	for i, RoleBinding := range bindDefinition.Spec.RoleBindings {
		log.V(3).Info("DEBUG: Processing RoleBinding selector", "bindDefinitionName", bindDefinition.Name, "index", i, "selectorCount", len(RoleBinding.NamespaceSelector))

		for j, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				log.V(3).Info("DEBUG: Found namespace selector", "bindDefinitionName", bindDefinition.Name, "roleBindingIndex", i, "selectorIndex", j)

				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					log.Error(err, "ERROR: Failed to convert namespace selector", "bindDefinitionName", bindDefinition.Name)
					return ctrl.Result{}, err
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.List(ctx, namespaceList, listOpts...)
				if err != nil {
					log.Error(err, "ERROR: Failed to list namespaces", "bindDefinitionName", bindDefinition.Name, "selector", selector)
					return ctrl.Result{}, err
				}
				log.V(2).Info("DEBUG: Found namespaces", "bindDefinitionName", bindDefinition.Name, "selector", selector, "namespaceCount", len(namespaceList.Items))

				// Add namespaces to the set
				for _, ns := range namespaceList.Items {
					log.V(3).Info("DEBUG: Adding namespace to set", "bindDefinitionName", bindDefinition.Name, "namespace", ns.Name, "phase", ns.Status.Phase)
					namespaceSet[ns.Name] = ns
				}
			}
		}
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
			if err := r.Get(ctx, types.NamespacedName{Name: ns.Name}, nsObj); err == nil {
				r.Recorder.Eventf(nsObj, corev1.EventTypeWarning, "DeletionPending", "Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
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
			err := r.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
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
				r.Recorder.Eventf(saNamespace, corev1.EventTypeWarning, "DeletionPending", "Namespace deletion is waiting for resources to be deleted before auth-operator can complete cleanup")
				continue
			}

			sa := &corev1.ServiceAccount{}
			err = r.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, sa)
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
					if err := controllerutil.SetControllerReference(bindDefinition, sa, r.Scheme); err != nil {
						log.Error(err, "ERROR: Unable to set controller reference", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name)
						conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
						err = r.Status().Update(ctx, bindDefinition)
						if err != nil {
							return ctrl.Result{}, err
						}
						return ctrl.Result{}, err
					}
					if err := r.Create(ctx, sa); err != nil {
						log.Error(err, "ERROR: Failed to create ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
						return ctrl.Result{}, err
					}
					log.V(1).Info("DEBUG: Created ServiceAccount", "bindDefinitionName", bindDefinition.Name, "serviceAccount", sa.Name, "namespace", sa.Namespace)
					r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s in namespace %s", sa.Kind, sa.Name, sa.Namespace)

					// Append the ServiceAccount subject to the status of BindDefinition
					if !helpers.SubjectExists(bindDefinition.Status.GeneratedServiceAccounts, subject) {
						saSubjects = append(saSubjects, subject)
					}

					// Update GeneratedServiceAccounts status
					bindDefinition.Status.GeneratedServiceAccounts = helpers.MergeSubjects(bindDefinition.Status.GeneratedServiceAccounts, saSubjects)
					err := r.Status().Update(ctx, bindDefinition)
					if err != nil {
						log.Error(err, "ERROR: Failed to update BindDefinition status", "bindDefinitionName", bindDefinition.Name)
						return ctrl.Result{}, err
					}
				} else {
					log.Error(err, "ERROR: Unable to fetch ServiceAccount from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "serviceAccount", subject.Name, "namespace", subject.Namespace)
					conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
					err = r.Status().Update(ctx, bindDefinition)
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

		err := r.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, clusterRoleBinding)
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
				if err := controllerutil.SetControllerReference(bindDefinition, clusterRoleBinding, r.Scheme); err != nil {
					log.Error(err, "ERROR: Unable to set controller reference", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
					conditions.MarkFalse(bindDefinition, authnv1alpha1.OwnerRefCondition, bindDefinition.Generation, authnv1alpha1.OwnerRefReason, authnv1alpha1.OwnerRefMessage)
					err = r.Status().Update(ctx, bindDefinition)
					if err != nil {
						return ctrl.Result{}, err
					}
					return ctrl.Result{}, err
				}
				log.V(2).Info("DEBUG: Set OwnerRef", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				if err := r.Create(ctx, clusterRoleBinding); err != nil {
					log.Error(err, "ERROR: Failed to create ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
					return ctrl.Result{}, err
				}
				log.V(1).Info("DEBUG: Created ClusterRoleBinding", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				r.Recorder.Eventf(bindDefinition, corev1.EventTypeNormal, "Create", "Created resource %s/%s", clusterRoleBinding.Kind, clusterRoleBinding.Name)
			} else {
				log.Error(err, "ERROR: Unable to fetch ClusterRoleBinding from Kubernetes API", "bindDefinitionName", bindDefinition.Name, "clusterRoleBindingName", clusterRoleBindingName)
				conditions.MarkFalse(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
				err = r.Status().Update(ctx, bindDefinition)
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
				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
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
						if err := r.Create(ctx, roleBinding); err != nil {
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
			for _, roleRef := range RoleBinding.RoleRefs {
				roleBinding := &rbacv1.RoleBinding{}
				roleBindingName := fmt.Sprintf("%s-%s-%s", bindDefinition.Spec.TargetName, roleRef, "binding")
				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, roleBinding)
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
						if err := r.Create(ctx, roleBinding); err != nil {
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
	}

	conditions.MarkTrue(bindDefinition, authnv1alpha1.CreateCondition, bindDefinition.Generation, authnv1alpha1.CreateReason, authnv1alpha1.CreateMessage)
	err := r.Status().Update(ctx, bindDefinition)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *bindDefinitionReconciler) reconcileUpdate(ctx context.Context, bindDefinition *authnv1alpha1.BindDefinition) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Construct namespace set from BindDefinition namespace selectors
	namespaceSet := make(map[string]corev1.Namespace)
	for _, RoleBinding := range bindDefinition.Spec.RoleBindings {

		for _, nsSelector := range RoleBinding.NamespaceSelector {
			if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					return ctrl.Result{}, err
				}
				namespaceList := &corev1.NamespaceList{}
				listOpts := []client.ListOption{
					&client.ListOptions{LabelSelector: selector},
				}
				err = r.List(ctx, namespaceList, listOpts...)
				if err != nil {
					return ctrl.Result{}, err
				}
				// Add namespaces to the set
				for _, ns := range namespaceList.Items {
					namespaceSet[ns.Name] = ns
				}
			}
		}
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
			err := r.Get(ctx, types.NamespacedName{Name: subject.Namespace}, saNamespace)
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
			if err := controllerutil.SetControllerReference(bindDefinition, expectedSa, r.Scheme); err != nil {
				log.Error(err, "Unable to construct an Expected SA in reconcile Update function")
				return ctrl.Result{}, err
			}
			// Fetch the ServiceAccount from the API
			err = r.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existingSa)
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
					if err := r.Update(ctx, existingSa); err != nil {
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
		if err := controllerutil.SetControllerReference(bindDefinition, expectedClusterRoleBinding, r.Scheme); err != nil {
			log.Error(err, "Unable to construct an Expected ClusterRoleBinding in reconcile Update function")
		}
		// Fetch the ClusterRoleBinding from the API
		err := r.Get(ctx, types.NamespacedName{Name: clusterRoleBindingName}, existingClusterRoleBinding)
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
				if err := r.Update(ctx, existingClusterRoleBinding); err != nil {
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
				if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.Scheme); err != nil {
					log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
				}
				// Fetch the RoleBinding from the API
				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
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
						if err := r.Update(ctx, existingRoleBinding); err != nil {
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
				if err := controllerutil.SetControllerReference(bindDefinition, expectedRoleBinding, r.Scheme); err != nil {
					log.Error(err, "Unable to construct an Expected RoleBinding in reconcile Update function")
				}
				// Fetch the RoleBinding from the API
				err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: ns.Name}, existingRoleBinding)
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
						if err := r.Update(ctx, existingRoleBinding); err != nil {
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
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}
