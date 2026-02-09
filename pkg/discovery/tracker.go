package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	pkgerrors "github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/telekom/auth-operator/pkg/metrics"
)

// ErrResourceTrackerNotStarted is returned when the ResourceTracker has not been started yet.
var ErrResourceTrackerNotStarted = fmt.Errorf("resource tracker not started")

const (
	// Duration between periodic API resource collections.
	periodicCollectionInterval = 30 * time.Second

	// Duration between full rescans to account for missed events.
	// This refreshes both the CRD UUID map and the API resources cache.
	fullRescanInterval = 15 * time.Minute
)

// APIResourcesByGroupVersion maps GroupVersion strings to their corresponding API resources.
type APIResourcesByGroupVersion map[string][]metav1.APIResource

// Equals compares two APIResourcesByGroupVersion for equality.
func (r APIResourcesByGroupVersion) Equals(other APIResourcesByGroupVersion) bool {
	if len(r) != len(other) {
		return false
	}
	for gv, resources := range r {
		otherResources, exists := other[gv]
		if !exists {
			return false
		}
		if len(resources) != len(otherResources) {
			return false
		}
		resourceMap := make(map[string]metav1.APIResource)
		for _, res := range resources {
			resourceMap[res.Name] = res
		}
		for _, otherRes := range otherResources {
			res, exists := resourceMap[otherRes.Name]
			if !exists {
				return false
			}
			// Compare relevant fields
			if res.Namespaced != otherRes.Namespaced ||
				res.Kind != otherRes.Kind ||
				!cmp.Equal(res.Verbs, otherRes.Verbs, cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
				return false
			}
		}
	}
	return true
}

type signalFunc func() error

// ResourceTracker tracks and caches the available API resources in the Kubernetes cluster.
type ResourceTracker struct {
	started     atomic.Bool
	rateLimit   rate.Sometimes
	scheme      *runtime.Scheme
	config      *rest.Config
	mutex       sync.RWMutex
	cache       APIResourcesByGroupVersion
	signalFuncs []signalFunc
	crdsMutex   sync.RWMutex
	crdsUUIDs   map[string]struct{}
}

// hasCRDUUID returns true if the given UID is in the CRD UUID map (thread-safe).
func (r *ResourceTracker) hasCRDUUID(uid string) bool {
	r.crdsMutex.RLock()
	defer r.crdsMutex.RUnlock()
	_, exists := r.crdsUUIDs[uid]
	return exists
}

// addCRDUUID adds a UID to the CRD UUID map (thread-safe).
func (r *ResourceTracker) addCRDUUID(uid string) {
	r.crdsMutex.Lock()
	defer r.crdsMutex.Unlock()
	r.crdsUUIDs[uid] = struct{}{}
}

// setCRDUUIDs replaces the CRD UUID map atomically (thread-safe).
func (r *ResourceTracker) setCRDUUIDs(uuids map[string]struct{}) {
	r.crdsMutex.Lock()
	defer r.crdsMutex.Unlock()
	r.crdsUUIDs = uuids
}

// crdUUIDCount returns the count of tracked CRD UUIDs (thread-safe).
func (r *ResourceTracker) crdUUIDCount() int {
	r.crdsMutex.RLock()
	defer r.crdsMutex.RUnlock()
	return len(r.crdsUUIDs)
}

// shouldSkipTerminatingCRD returns true if the CRD has a DeletionTimestamp and
// the event is not a DELETED event. This ensures resources from terminating CRDs
// remain in generated roles until the CRD is fully deleted.
func shouldSkipTerminatingCRD(crd *apiextensionsv1.CustomResourceDefinition, eventType watch.EventType) bool {
	return crd.DeletionTimestamp != nil && eventType != watch.Deleted
}

// NewResourceTracker creates a new ResourceTracker.
// The signalFunc is called whenever the API resources are updated
// (no information about what triggers the update is provided).
func NewResourceTracker(scheme *runtime.Scheme, config *rest.Config) *ResourceTracker {
	return &ResourceTracker{
		config:      config,
		scheme:      scheme,
		signalFuncs: []signalFunc{},

		// known CRD UUIDs to filter ADDED events in the watch
		crdsUUIDs: make(map[string]struct{}),

		// Rate limit to avoid excessive API resource collection on bursts of CRD events
		rateLimit: rate.Sometimes{Interval: 5 * time.Second},

		// API resources cache
		cache: make(APIResourcesByGroupVersion),

		// RWMutex to protect access to the cache
		mutex: sync.RWMutex{},
	}
}

// AddSignalFunc adds a signal function to be called when API resources are updated.
func (r *ResourceTracker) AddSignalFunc(f signalFunc) {
	r.signalFuncs = append(r.signalFuncs, f)
}

// NeedLeaderElection implements LeaderElectionRunnable and indicates that it does not need leader election.
// This would make it start before the role definition controller that depends on it.
func (r *ResourceTracker) NeedLeaderElection() bool {
	return false
}

// Start starts the ResourceTracker, beginning the periodic and event-driven collection of API resources.
func (r *ResourceTracker) Start(ctx context.Context) error {
	err := r.initUUIDMap(ctx)
	if err != nil {
		return fmt.Errorf("unable to initialize CRD UUID map: %w", err)
	}

	// Initial collection
	_, err = r.collectAPIResources(ctx)
	if err != nil {
		return err
	}

	// Mark as started. This is needed as Controller-Runtime starts all
	// runnables concurrently, and the RoleDefinitionReconciler may
	// call GetAPIResources() before the initial collection is done.
	// By marking as started only after the initial collection, we ensure
	// that the RoleDefinitionReconciler always gets a valid cache on first call (or ErrResourceTrackerNotStarted).
	// Subsequent calls will be blocked until the first collection is done
	// by the mutex in GetAPIResources().
	r.started.Store(true)

	// Start CRD watch with jitter and exponential backoff
	go func() {
		if err := r.launchWatch(ctx); err != nil {
			log.FromContext(ctx).Error(err, "failed to launch CRD watch")
		}
	}()

	// Start periodic collection
	go r.periodicCollection(ctx)

	// Start periodic full rescan to account for missed events
	go r.periodicFullRescan(ctx)

	return nil
}

func (r *ResourceTracker) initUUIDMap(ctx context.Context) error {
	cli, err := client.New(r.config, client.Options{Scheme: r.scheme})
	if err != nil {
		return fmt.Errorf("unable to create client for CRD watch: %w", err)
	}

	// List existing CRDs to initialize the known CRD UUIDs
	// This will be used to filter ADDED events in the watch and skip running
	// expensive operations (like API resource collection) for "non-events". Watch always
	// sends an ADDED event for existing objects when the watch is created.
	var crdList apiextensionsv1.CustomResourceDefinitionList
	err = cli.List(ctx, &crdList)
	if err != nil {
		return err
	}
	for _, crd := range crdList.Items {
		r.addCRDUUID(string(crd.UID))
	}
	return nil
}

// collectAndNotify attempts to collect API resources and notify via signalFunc if there are changes.
// it will only run if the rate limiter allows it.
func (r *ResourceTracker) collectAndNotify(ctx context.Context) func() {
	return func() {
		logger := log.FromContext(ctx).WithName("ResourceTracker.collectAndNotify")
		logger.V(2).Info("triggering rate-limited API resource collection")

		changed, err := r.collectAPIResources(ctx)
		if err != nil {
			logger.Error(err, "failed to collect API resources")
			return
		}
		if !changed {
			return
		}
		for _, f := range r.signalFuncs {
			err := f()
			if err != nil {
				logger.Error(err, "failed to send signal after API resource collection")
				continue
			}
		}
		logger.Info("successfully sent signal after API resource collection")
	}
}

// GetAPIResources returns a deep copy of the cached API resources by group version.
func (r *ResourceTracker) GetAPIResources() (APIResourcesByGroupVersion, error) {
	if !r.started.Load() {
		return nil, ErrResourceTrackerNotStarted
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Deep copy the cache to avoid race conditions
	copiedCache := make(APIResourcesByGroupVersion)
	for gv, resources := range r.cache {
		copiedCache[gv] = make([]metav1.APIResource, len(resources))
		copy(copiedCache[gv], resources)
	}
	return copiedCache, nil
}

// collectAPIResources collects the API resources from the Kubernetes API server
// and updates the internal cache if there are changes.
// It returns (true, nil) if the cache was updated, (false, nil) if unchanged or
// skipped due to another collection in progress.
// It uses a mutex to ensure only one collection is in progress at a time.
// It runs the collection with higher QPS and Burst to speed up the process.
// It collects resources concurrently for each API group version.
func (r *ResourceTracker) collectAPIResources(ctx context.Context) (bool, error) {
	startTime := time.Now()
	if !r.mutex.TryLock() {
		// another collection is in progress
		return false, nil
	}
	defer r.mutex.Unlock()

	logger := log.FromContext(ctx)
	logger.V(2).Info("collecting API resources - locking mutex")

	// Create a Discovery client with higher QPS and Burst to speed up the discovery process
	discoveryConfig := rest.CopyConfig(r.config)
	discoveryConfig.QPS = 100
	discoveryConfig.Burst = 200

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(discoveryConfig)
	if err != nil {
		logger.Error(err, "failed to create Discovery client")
		metrics.APIDiscoveryErrors.Inc()
		return false, err
	}

	// Fetch all existing API Groups and filter them against RestrictedAPIs
	logger.V(2).Info("starting API discovery")

	discoveredAPIGroups, err := discoveryClient.ServerGroups()
	if err != nil {
		logger.Error(err, "failed to discover API groups")
		metrics.APIDiscoveryErrors.Inc()
		return false, err
	}
	logger.V(2).Info("discovered API groups", "groupCount", len(discoveredAPIGroups.Groups))

	// Record API discovery duration after successful completion
	defer func() {
		metrics.APIDiscoveryDuration.Observe(time.Since(startTime).Seconds())
	}()

	// Fetch all existing API Resources and filter them against RestrictedResources
	errorGroup, groupCtx := errgroup.WithContext(ctx)

	// Collect results
	apiResourcesByGroupVersion := make(APIResourcesByGroupVersion)
	mutex := sync.Mutex{}

	for _, apiGroup := range discoveredAPIGroups.Groups {
		// Check context cancellation between API group iterations
		select {
		case <-ctx.Done():
			logger.V(1).Info("stopping API resource collection due to context cancellation")
			return false, ctx.Err()
		default:
		}

		for _, apiGroupVersion := range apiGroup.Versions {
			// Copy loop variables to avoid closure capture bug
			apiGroupName := apiGroup.Name
			apiVersionStr := apiGroupVersion.Version
			gv := metav1.GroupVersion{
				Group:   apiGroupName,
				Version: apiVersionStr,
			}
			errorGroup.Go(func() error {
				// Check context before starting work
				select {
				case <-groupCtx.Done():
					return groupCtx.Err()
				default:
				}

				resources, err := r.collectAPIResourcesForGroupVersion(discoveryClient, apiGroupName, apiVersionStr)
				if err != nil {
					logger.Error(err, "failed to discover API resources for group version",
						"group", apiGroupName, "version", apiVersionStr)
					return err
				}
				// Append results into the shared map under mutex to avoid sharing per-goroutine slices
				mutex.Lock()
				apiResourcesByGroupVersion[gv.String()] = append(apiResourcesByGroupVersion[gv.String()], resources...)
				mutex.Unlock()
				return nil
			})
		}
	}
	if err := errorGroup.Wait(); err != nil {
		// Don't log context cancellation as an error
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			logger.V(1).Info("API resource collection cancelled", "reason", err.Error())
			return false, err
		}
		logger.Error(err, "failed to discover resources concurrently")
		return false, err
	}

	logger.V(2).Info("discovered API resources", "resourceCount", len(apiResourcesByGroupVersion))

	if apiResourcesByGroupVersion.Equals(r.cache) {
		logger.V(2).Info("API resources cache unchanged")
		return false, nil
	}
	r.cache = apiResourcesByGroupVersion

	logger.V(2).Info("API resources cache updated")
	return true, nil
}

func (r *ResourceTracker) periodicCollection(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("ResourceTracker.periodicCollection")
	logger.Info("starting periodic API resource collection", "interval", periodicCollectionInterval)

	ticker := time.NewTicker(periodicCollectionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// Trigger rate-limited collection after ticker
			r.rateLimit.Do(r.collectAndNotify(ctx))
		case <-ctx.Done():
			logger.Info("stopping periodic API resource collection due to context done")
			return
		}
	}
}

// periodicFullRescan performs a full rescan of the cluster to account for missed events.
// This refreshes the CRD UUID map and forces an API resources collection regardless of the rate limiter.
func (r *ResourceTracker) periodicFullRescan(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("ResourceTracker.periodicFullRescan")
	logger.Info("starting periodic full rescan", "interval", fullRescanInterval)

	ticker := time.NewTicker(fullRescanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			logger.Info("performing full rescan to account for missed events")

			// Reinitialize the UUID map to pick up any CRDs we may have missed
			if err := r.refreshUUIDMap(ctx); err != nil {
				logger.Error(err, "failed to refresh CRD UUID map during full rescan")
				// Continue with collection anyway
			}

			// Force collection bypassing rate limiter
			changed, err := r.collectAPIResources(ctx)
			if err != nil {
				logger.Error(err, "failed to collect API resources during full rescan")
				continue
			}
			if !changed {
				logger.V(1).Info("full rescan completed, no changes detected (or concurrent collection in progress)")
				continue
			}
			for _, f := range r.signalFuncs {
				if err := f(); err != nil {
					logger.Error(err, "failed to send signal after full rescan")
					continue
				}
			}
			logger.Info("full rescan completed with changes, signals sent")
		case <-ctx.Done():
			logger.Info("stopping periodic full rescan due to context done")
			return
		}
	}
}

// refreshUUIDMap refreshes the CRD UUID map by listing all current CRDs.
// This ensures the tracker doesn't skip legitimately new CRDs that may have been
// added while the watch was disconnected.
func (r *ResourceTracker) refreshUUIDMap(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("ResourceTracker.refreshUUIDMap")

	cli, err := client.New(r.config, client.Options{Scheme: r.scheme})
	if err != nil {
		return fmt.Errorf("unable to create client for CRD list: %w", err)
	}

	var crdList apiextensionsv1.CustomResourceDefinitionList
	err = cli.List(ctx, &crdList)
	if err != nil {
		return fmt.Errorf("unable to list CRDs: %w", err)
	}

	// Build new UUID map
	newUUIDs := make(map[string]struct{}, len(crdList.Items))
	for _, crd := range crdList.Items {
		newUUIDs[string(crd.UID)] = struct{}{}
	}

	// Replace the old map atomically (thread-safe)
	r.setCRDUUIDs(newUUIDs)

	logger.V(1).Info("refreshed CRD UUID map", "crdCount", len(newUUIDs))
	return nil
}

func (r *ResourceTracker) launchWatch(ctx context.Context) error {
	watchBackoff := NewForeverWatchBackoff()
	if err := ExponentialBackoffWithContext(ctx, watchBackoff, r.watchAPIResources); err != nil {
		return pkgerrors.Wrap(err, "failed to launch CRD watch with backoff")
	}

	return nil
}

func (r *ResourceTracker) watchAPIResources(ctx context.Context) {
	logger := log.FromContext(ctx)
	cli, err := client.NewWithWatch(r.config, client.Options{Scheme: r.scheme})
	if err != nil {
		logger.Error(err, "unable to create client for CRD watch")
		return
	}

	var crdList apiextensionsv1.CustomResourceDefinitionList
	watcher, err := cli.Watch(ctx, &crdList)
	if err != nil {
		logger.Error(err, "unable to start CRD watch")
		return
	}

	logger.Info("starting CRD watch for RoleDefinitionReconciler")
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				logger.Info("CRD watch channel closed")
				return
			}
			if event.Type == watch.Error {
				status, isStatus := event.Object.(*metav1.Status)
				if isStatus {
					logger.Info("CRD watch error event received", "message", status.Message, "reason", status.Reason, "code", status.Code)
					return
				}
				logger.Info("CRD watch error event received", "eventObject", event.Object)
				return
			}
			crd := event.Object.(*apiextensionsv1.CustomResourceDefinition)

			logger.V(2).Info("CRD watch event received", "eventType", event.Type, "name", crd.Name, "uid", crd.UID)
			if event.Type == watch.Added {
				if r.hasCRDUUID(string(crd.UID)) {
					// already exists, skip
					continue
				}
				r.addCRDUUID(string(crd.UID))
			}

			// Skip re-collection for CRDs that are being deleted (have deletionTimestamp).
			// This ensures resources from terminating CRDs remain in generated roles until
			// the CRD is fully deleted (DELETED event), preventing premature removal of
			// permissions during CRD cleanup.
			if shouldSkipTerminatingCRD(crd, event.Type) {
				logger.V(1).Info("skipping API resource collection for terminating CRD",
					"name", crd.Name, "deletionTimestamp", crd.DeletionTimestamp)
				continue
			}

			// Trigger rate-limited collection
			// for ADDED, DELETED, and MODIFIED events
			// Note: we do not differentiate between these events here
			// as any of them may impact the available API resources
			// (e.g., a CRD modification may add/remove versions)
			// and we want to keep the cache up-to-date.
			// The rate limiter will ensure we do not overload the API server
			// with discovery requests in case of bursts of events.
			r.rateLimit.Do(r.collectAndNotify(ctx))

		case <-ctx.Done():
			logger.Info("stopping CRD watch after context done")
			return
		}
	}
}

func (r *ResourceTracker) collectAPIResourcesForGroupVersion(
	cli *discovery.DiscoveryClient,
	group string,
	version string,
) ([]metav1.APIResource, error) {
	result := make([]metav1.APIResource, 0)

	gv := metav1.GroupVersion{
		Group:   group,
		Version: version,
	}

	discoveredAPIResources, err := cli.ServerResourcesForGroupVersion(gv.String())
	if err != nil {
		return nil, err
	}
	for _, resource := range discoveredAPIResources.APIResources {
		isSubresource := strings.Contains(resource.Name, "/")

		subResourceRequiresExplicitVerbs := isSubresource &&
			(strings.HasSuffix(resource.Name, "/status") || strings.HasSuffix(resource.Name, "/finalizers"))
		if subResourceRequiresExplicitVerbs {
			resource.Verbs = append(resource.Verbs, "list", "watch")
		}

		// for roles and rolebindings in rbac.authorization.k8s.io/v1,
		// we need to add the bind verb explicitly, as they are not part of the API discovery
		requiresExplicitBind := group == "rbac.authorization.k8s.io" && version == "v1" &&
			(resource.Name == "roles" || resource.Name == "rolebindings")
		if requiresExplicitBind {
			resource.Verbs = append(resource.Verbs, "bind")
		}

		// for roles in rbac.authorization.k8s.io/v1,
		// we need to add the escalate verb explicitly, as it is not part of the API discovery
		requiresExplicitEscalate := group == "rbac.authorization.k8s.io" && version == "v1" &&
			resource.Name == "roles"
		if requiresExplicitEscalate {
			resource.Verbs = append(resource.Verbs, "escalate")
		}

		// send the resource to the channel
		result = append(result, resource)

		// Skip subresources for further processing
		if isSubresource {
			continue
		}

		// There are certain resources that are not known to the APIServer (and thus the DiscoveryClient)
		// but are important to end up in the RoleDefinition. These are added here manually.

		// if the item is not a subresource (i.e. it does not contain slashes)
		// we add the finalizer explicitly as it's not part of discovery
		finalizersSubresourceResource := resource.DeepCopy()
		finalizersSubresourceResource.Name = fmt.Sprintf("%s/%s", resource.Name, "finalizers")
		finalizersSubresourceResource.Verbs = metav1.Verbs{"update", "list", "watch"}
		result = append(result, *finalizersSubresourceResource)
		if group == "" && version == "v1" && resource.Name == "nodes" {
			// nodes/metrics in the core group are not filtered by the RestrictedResources,
			// as they are not part of the API discovery.
			nodeMetricsSubresource := resource.DeepCopy()
			nodeMetricsSubresource.Name = "nodes/metrics"
			nodeMetricsSubresource.Verbs = metav1.Verbs{"get", "list", "watch"}
			result = append(result, *nodeMetricsSubresource)
		}
	}
	return result, nil
}
