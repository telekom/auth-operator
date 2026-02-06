package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authnv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/metrics"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces/status,verbs=get;update
// +kubebuilder:rbac:groups="",resources=events,verbs=*
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=*

const (
	namespaceResourcesCalculationInterval = 10 * time.Second
	// maxConcurrentResourceChecks limits goroutines to avoid overwhelming the API server.
	maxConcurrentResourceChecks = 30
	// terminatingNamespaceRequeueInterval is how often to recheck a terminating namespace.
	terminatingNamespaceRequeueInterval = 15 * time.Second
)

// namespaceDeletionResourceBlocking represents a resource type and the specific instances blocking namespace deletion.
type namespaceDeletionResourceBlocking struct {
	ResourceType string // e.g., "pods", "persistentvolumeclaims"
	APIGroup     string // e.g., "", "apps"
	Count        int
	Names        []string // List of specific resource names
}

// namespaceTerminationStatus caches the blocking resources for a namespace and manages access with a mutex.
// It also includes a rate limiter to control how often the resources are recalculated.
type namespaceTerminationStatus struct {
	blockingResources []namespaceDeletionResourceBlocking
	mutex             sync.Mutex
	lastError         error
	rateLimiter       rate.Sometimes
}

func newNamespaceTerminationStatus() *namespaceTerminationStatus {
	return &namespaceTerminationStatus{
		blockingResources: []namespaceDeletionResourceBlocking{},
		mutex:             sync.Mutex{},
		rateLimiter:       rate.Sometimes{Interval: namespaceResourcesCalculationInterval},
	}
}

// RoleBindingTerminator is responsible for handling finalizers on RoleBindings owned by BindDefinitions.
// During deletion, if the namespace is terminating it checks for remaining resources before removing finalizers; otherwise it removes them directly.
type RoleBindingTerminator struct {
	client                             client.Client
	scheme                             *runtime.Scheme
	dynamicClient                      dynamic.Interface
	resourceTracker                    *discovery.ResourceTracker
	recorder                           events.EventRecorder
	namespaceTerminationResourcesCache sync.Map // map[string]*namespaceTerminationStatus
}

// NewRoleBindingTerminator creates a new RoleBinding terminator.
// Uses the manager's cached client for improved performance.
func NewRoleBindingTerminator(
	cachedClient client.Client,
	config *rest.Config,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	resourceTracker *discovery.ResourceTracker,
) (*RoleBindingTerminator, error) {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &RoleBindingTerminator{
		client:                             cachedClient,
		dynamicClient:                      dynamicClient,
		scheme:                             scheme,
		recorder:                           recorder,
		resourceTracker:                    resourceTracker,
		namespaceTerminationResourcesCache: sync.Map{},
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
// Used to watch for role bindings and handle their finalizers if they are managed by a BindDefinition.
func (r *RoleBindingTerminator) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1.RoleBinding{}).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			MaxConcurrentReconciles: concurrency,
		}).
		Complete(r)
}

// getNamespacedBlockingResources retrieves cached blocking resources for a namespace, recalculating them if the rate limiter allows it.
func (r *RoleBindingTerminator) getNamespacedBlockingResources(ctx context.Context, namespace string) ([]namespaceDeletionResourceBlocking, error) {
	v, _ := r.namespaceTerminationResourcesCache.LoadOrStore(namespace, newNamespaceTerminationStatus())

	// Use rate limiter to avoid frequent checks
	nsTermStatus := v.(*namespaceTerminationStatus)

	nsTermStatus.rateLimiter.Do(func() {
		nsTermStatus.mutex.Lock()
		defer nsTermStatus.mutex.Unlock()

		// Recalculate blocking resources
		nsTermStatus.blockingResources, nsTermStatus.lastError = namespaceHasResources(ctx, r.resourceTracker, r.dynamicClient, namespace)
	})
	return nsTermStatus.blockingResources, nsTermStatus.lastError
}

// For checking if terminating namespace has deleting resources
// Needed for RoleBinding finalizer removal
// Returns: hasResources (bool), blockingResources ([]ResourceBlocking), error.
func namespaceHasResources(ctx context.Context, resourceTracker *discovery.ResourceTracker, dynamicClient dynamic.Interface, namespace string) ([]namespaceDeletionResourceBlocking, error) {
	logger := log.FromContext(ctx)
	logger.V(2).Info("starting namespace resource check", "namespace", namespace)

	var resourcesChecked, resourcesSkipped atomic.Int32

	apiResources, err := resourceTracker.GetAPIResources()
	if errors.Is(err, discovery.ErrResourceTrackerNotStarted) {
		logger.V(1).Info("ResourceTracker not started yet - requeuing reconciliation", "namespace", namespace)
		return nil, err
	}
	if err != nil {
		logger.Error(err, "failed to get API resources from ResourceTracker", "namespace", namespace)
		return nil, err
	}

	// collect resources concurrently
	errGroup := errgroup.Group{}
	errGroup.SetLimit(maxConcurrentResourceChecks)

	// list of blocking resources found - only accessed by collector goroutine
	// until channel is closed and WaitGroup is done
	var blockingResources []namespaceDeletionResourceBlocking

	// channel to collect blocking resources
	blockingResourcesChannel := make(chan namespaceDeletionResourceBlocking, 100)

	// WaitGroup to ensure collector goroutine finishes
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)

	// collect blocking resources from channel
	// No mutex needed: only this goroutine writes to blockingResources,
	// and main goroutine waits for collectorWg before reading
	go func() {
		defer collectorWg.Done()
		for br := range blockingResourcesChannel {
			blockingResources = append(blockingResources, br)
		}
	}()

	for groupVersion, resourceList := range apiResources {
		gv, parseErr := schema.ParseGroupVersion(groupVersion)
		if parseErr != nil {
			// skip malformed group/version
			logger.V(4).Info("skipping malformed GroupVersion", "namespace", namespace, "groupVersion", groupVersion, "error", parseErr)
			resourcesSkipped.Add(1)
			continue
		}

		for i := range resourceList {
			resource := resourceList[i]

			if strings.Contains(resource.Name, "/") || strings.Contains(resource.Name, "rolebindings") {
				// ignore subresources and rolebinding resources
				logger.V(4).Info("skipping subresource or rolebinding", "namespace", namespace, "resource", resource.Name, "groupVersion", groupVersion)
				resourcesSkipped.Add(1)
				continue
			}

			if !supportsList(resource.Verbs) {
				// if resource does not support "list", skip it
				logger.V(4).Info("skipping resource without list verb", "namespace", namespace, "resource", resource.Name, "groupVersion", groupVersion)
				resourcesSkipped.Add(1)
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    gv.Group,
				Version:  gv.Version,
				Resource: resource.Name,
			}

			errGroup.Go(func() error {
				logger.V(3).Info("listing resource in namespace", "namespace", namespace, "gvr", gvr.String())
				// using dynamic client to not instantiate all typed clients
				list, err := dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
				if err != nil {
					logger.V(2).Info("skipping resource due to list error", "namespace", namespace, "resource", gvr.String(), "error", err)
					resourcesSkipped.Add(1)
					return nil
				}

				resourcesChecked.Add(1)
				if len(list.Items) == 0 {
					logger.V(3).Info("no resources found", "namespace", namespace, "gvr", gvr.String())
					return nil
				}

				logger.V(2).Info("found resources in namespace - will NOT remove finalizers", "namespace", namespace, "gvr", gvr.String(), "itemCount", len(list.Items))

				// Collect names of blocking resources (limit to first 10)
				var resourceNames []string
				for i, item := range list.Items {
					if i < 10 { // Collect up to 10 resource names for event
						resourceNames = append(resourceNames, item.GetName())
						logger.V(3).Info("found resource", "namespace", namespace, "gvr", gvr.String(), "name", item.GetName(), "index", i)
					}
				}
				// Add to blocking resources list
				blockingResourcesChannel <- namespaceDeletionResourceBlocking{
					ResourceType: resource.Name,
					APIGroup:     gv.Group,
					Count:        len(list.Items),
					Names:        resourceNames,
				}
				return nil
			})
		}
	}
	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("error listing resources in namespace %s: %w", namespace, err)
	}
	close(blockingResourcesChannel)
	collectorWg.Wait() // Wait for collector goroutine to finish processing all items

	// If we found blocking resources, return them all
	if len(blockingResources) > 0 {
		logger.V(2).Info("found blocking resources in namespace", "namespace", namespace, "blockingResourceCount", len(blockingResources))
		return blockingResources, nil
	}

	// no resources found
	logger.V(2).Info("namespace has no resources - can remove finalizers", "namespace", namespace, "resourcesChecked", resourcesChecked.Load(), "resourcesSkipped", resourcesSkipped.Load())
	return nil, nil
}

func supportsList(verbs []string) bool {
	for _, verb := range verbs {
		if verb == "list" {
			return true
		}
	}
	return false
}

// formatBlockingResourcesMessage creates a detailed event message about what resources are blocking namespace deletion.
func formatBlockingResourcesMessage(blockingResources []namespaceDeletionResourceBlocking) string {
	resourceDetails := []string{}

	for _, rb := range blockingResources {
		var resourceType string
		if rb.APIGroup == "" {
			resourceType = rb.ResourceType
		} else {
			resourceType = fmt.Sprintf("%s (%s)", rb.ResourceType, rb.APIGroup)
		}

		switch {
		case rb.Count == 1 && len(rb.Names) > 0:
			resourceDetails = append(resourceDetails, fmt.Sprintf("%s: %s", resourceType, rb.Names[0]))
		case len(rb.Names) > 0:
			// Show first few names if multiple.
			if len(rb.Names) <= 3 {
				resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d): %s", resourceType, rb.Count, strings.Join(rb.Names, ", ")))
			} else {
				resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d): %s, +%d more", resourceType, rb.Count, strings.Join(rb.Names[:3], ", "), rb.Count-3))
			}
		default:
			resourceDetails = append(resourceDetails, fmt.Sprintf("%s (%d)", resourceType, rb.Count))
		}
	}

	return strings.Join(resourceDetails, "; ")
}

func isOwnedByBindDefinition(ownerReferences []metav1.OwnerReference) bool {
	for _, ownerRef := range ownerReferences {
		if ownerRef.Kind == "BindDefinition" && ownerRef.APIVersion == authnv1alpha1.GroupVersion.String() {
			return true
		}
	}
	return false
}

func (r *RoleBindingTerminator) getOwningBindDefinition(ctx context.Context, ownerReferences []metav1.OwnerReference) (*authnv1alpha1.BindDefinition, error) {
	for _, ownerRef := range ownerReferences {
		if ownerRef.Kind != "BindDefinition" || ownerRef.APIVersion != authnv1alpha1.GroupVersion.String() {
			continue
		}
		bindDefinition := &authnv1alpha1.BindDefinition{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ownerRef.Name}, bindDefinition)
		if err != nil {
			return nil, fmt.Errorf("failed to get BindDefinition %s: %w", ownerRef.Name, err)
		}
		return bindDefinition, nil
	}
	return nil, fmt.Errorf("no BindDefinition owner reference found")
}

// Reconcile handles the reconciliation loop for RoleBinding resources owned by BindDefinitions.
// It manages finalizer cleanup during namespace termination.
func (r *RoleBindingTerminator) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	logger := log.FromContext(ctx).WithValues("roleBinding", req.NamespacedName)

	// Track reconcile duration on exit
	defer func() {
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerRoleBindingTerminator).Observe(time.Since(startTime).Seconds())
	}()

	// Fetching the RoleBinding from Kubernetes API
	roleBinding := rbacv1.RoleBinding{}
	err := r.client.Get(ctx, req.NamespacedName, &roleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Unable to fetch RoleBinding resource from Kubernetes API")
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	// we don't care about RoleBindings not owned by a BindDefinition
	if !isOwnedByBindDefinition(roleBinding.GetOwnerReferences()) {
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultSkipped).Inc()
		return ctrl.Result{}, nil
	}

	// ensure finalizer is there if RB is owned by a BindDefinition and the RoleBinding is not being deleted
	if roleBinding.DeletionTimestamp.IsZero() {
		old := roleBinding.DeepCopy()
		if controllerutil.AddFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
			if err := r.client.Patch(ctx, &roleBinding, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
				logger.Error(err, "failed to add finalizer to RoleBinding")
				metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
				metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
				return ctrl.Result{}, err
			}
			logger.V(1).Info("added finalizer to RoleBinding")
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultSuccess).Inc()
		return ctrl.Result{}, nil
	}

	// role binding is being deleted; fetch the namespace to determine if it's terminating
	var namespace corev1.Namespace
	err = r.client.Get(ctx, types.NamespacedName{Name: roleBinding.Namespace}, &namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// namespace is already deleted, nothing to do
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	// If namespace is not terminating, we can safely remove the finalizer. it must mean the removal was triggered by another reason and it would get recreated if needed
	namespaceIsTerminating := !namespace.GetDeletionTimestamp().IsZero() && namespace.Status.Phase == corev1.NamespaceTerminating
	if !namespaceIsTerminating {
		old := roleBinding.DeepCopy()
		if controllerutil.RemoveFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
			if err := r.client.Patch(ctx, &roleBinding, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
				logger.Error(err, "failed to remove finalizer from RoleBinding")
				metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
				metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
				return ctrl.Result{}, err
			}
			logger.V(1).Info("removed finalizer from RoleBinding")
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultSuccess).Inc()
			return ctrl.Result{}, nil
		}
	}

	// if namespace is being terminated, we need to check if there are any remaining resources and make sure the last resources to get removed are the RoleBinings.
	// this is to allow users to make changes (like removing finalizers on other things) that otherwise would prevent proper cleanup

	// Check if namespace has any remaining resources before cleanup
	blockingResources, err := r.getNamespacedBlockingResources(ctx, namespace.Name)
	if err != nil {
		logger.Error(err, "failed to check if namespace has resources", "namespace", namespace.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	terminationAllowed := len(blockingResources) == 0

	if !terminationAllowed {
		logger.V(1).Info("terminating namespace still has resources - NOT removing RoleBinding finalizer", "namespace", namespace.Name)
		// Log detailed information about blocking resources
		for _, br := range blockingResources {
			resourceType := br.ResourceType
			if br.APIGroup != "" {
				resourceType = fmt.Sprintf("%s.%s", br.ResourceType, br.APIGroup)
			}
			logger.V(1).Info("blocking resource found", "namespace", namespace.Name, "resourceType", resourceType, "count", br.Count, "names", br.Names)
		}

		conditions.MarkTrue(
			conditions.NewNamespaceWrapper(&namespace),
			authnv1alpha1.NamespaceTerminationBlockedCondition,
			0,
			authnv1alpha1.NamespaceTerminationBlockedReason,
			conditions.ConditionMessage(fmt.Sprintf("%s: %s", authnv1alpha1.NamespaceTerminationBlockedMessage, formatBlockingResourcesMessage(blockingResources))),
		)
		// Best-effort status update on Namespace (core type) — SSA migration deferred.
		// Low conflict risk: runs only during namespace termination, errors are non-fatal.
		if err := r.client.Status().Update(ctx, &namespace); err != nil {
			logger.Error(err, "Failed to update Namespace status with blocking resources information", "namespace", namespace.Name)
		}

		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultRequeue).Inc()
		return ctrl.Result{RequeueAfter: terminatingNamespaceRequeueInterval}, nil
	}

	// No resources found - safe to remove finalizer from RoleBinding
	bindDefinition, err := r.getOwningBindDefinition(ctx, roleBinding.OwnerReferences)
	if err != nil {
		logger.Error(err, "failed to get owning BindDefinition for RoleBinding", "roleBindingName", roleBinding.Name, "namespace", namespace.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	logger = logger.WithValues("bindDefinitionName", bindDefinition.Name)

	logger.V(1).Info("terminating namespace has no more resources - proceeding to remove RoleBinding finalizers")
	old := roleBinding.DeepCopy()
	if controllerutil.RemoveFinalizer(&roleBinding, authnv1alpha1.RoleBindingFinalizer) {
		logger.V(2).Info("removing finalizer from RoleBinding in terminating namespace")
		if err := r.client.Patch(ctx, &roleBinding, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			logger.Error(err, "failed to remove finalizer from RoleBinding", "roleBindingName", roleBinding.Name, "roleBinding", roleBinding.Name, "namespace", namespace.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ErrorTypeAPI).Inc()
			return ctrl.Result{}, err
		}
		r.recorder.Eventf(bindDefinition, nil, corev1.EventTypeNormal, authnv1alpha1.EventReasonFinalizerRemoved, authnv1alpha1.EventActionFinalizerRemove, "Removed finalizer from RoleBinding %s in terminating namespace %s", roleBinding.Name, namespace.Name)
		logger.V(1).Info("successfully removed finalizer from RoleBinding in terminating namespace")
	} else {
		logger.V(3).Info("RoleBinding does not have finalizer", "roleBindingName", roleBinding.Name)
	}

	conditions.MarkFalse(
		conditions.NewNamespaceWrapper(&namespace),
		authnv1alpha1.NamespaceTerminationBlockedCondition,
		0,
		authnv1alpha1.NamespaceTerminationAllowedReason,
		authnv1alpha1.NamespaceTerminationAllowedMessage,
	)
	// Best-effort status update on Namespace (core type) — SSA migration deferred.
	// Low conflict risk: runs only during namespace termination, errors are non-fatal.
	if err := r.client.Status().Update(ctx, &namespace); err != nil {
		logger.Error(err, "failed to update Namespace status with blocking resources information", "namespace", namespace.Name)
	}

	logger.V(2).Info("reconcileTerminatingNamespaces completed")
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRoleBindingTerminator, metrics.ResultFinalized).Inc()
	return ctrl.Result{}, nil
}
