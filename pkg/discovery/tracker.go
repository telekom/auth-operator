// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	discoverytracker "github.com/telekom/t-caas-go-library/pkg/discovery/tracker"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/telekom/auth-operator/pkg/metrics"
)

var (
	// ErrResourceTrackerNotStarted means discovery has not published a usable snapshot.
	ErrResourceTrackerNotStarted = discoverytracker.ErrNotReady
	errEmptyDiscovery            = errors.New("API resource discovery returned no usable resources")
)

const (
	defaultCollectionInterval = 5 * time.Minute
	defaultFullRescanInterval = 15 * time.Minute
	verbBind                  = "bind"
	verbEscalate              = "escalate"
	verbGet                   = "get"
	verbList                  = "list"
	verbUpdate                = "update"
	verbWatch                 = "watch"
	rbacResourceClusterRoles  = "clusterroles"
	rbacResourceRoles         = "roles"
)

// APIResourcesByGroupVersion is the shared, deeply isolated discovery snapshot.
type APIResourcesByGroupVersion = discoverytracker.Snapshot
type signalFunc func() error

// ResourceTracker adds the operator's RBAC policy and metrics to shared discovery.
type ResourceTracker struct {
	scheme             *runtime.Scheme
	config             *rest.Config
	initOnce           sync.Once
	tracker            *discoverytracker.Tracker
	initErr            error
	signalMu           sync.RWMutex
	signalFuncs        []signalFunc
	FullRescanInterval time.Duration
	CollectionInterval time.Duration
}

// NewResourceTracker preserves operator defaults around the shared tracker.
func NewResourceTracker(scheme *runtime.Scheme, config *rest.Config) *ResourceTracker {
	return &ResourceTracker{scheme: scheme, config: config}
}

// AddSignalFunc registers a controller notification for snapshot changes.
func (r *ResourceTracker) AddSignalFunc(f signalFunc) {
	r.signalMu.Lock()
	defer r.signalMu.Unlock()
	r.signalFuncs = append(r.signalFuncs, f)
}

func (r *ResourceTracker) signalFuncsSnapshot() []signalFunc {
	r.signalMu.RLock()
	defer r.signalMu.RUnlock()
	return append([]signalFunc(nil), r.signalFuncs...)
}

// NeedLeaderElection preserves the operator's leader-only discovery lifecycle.
func (*ResourceTracker) NeedLeaderElection() bool { return true }

func (r *ResourceTracker) initialize() error {
	r.initOnce.Do(func() {
		if r.config == nil {
			r.initErr = errors.New("discovery configuration is required")
			return
		}
		config := rest.CopyConfig(r.config)
		config.QPS, config.Burst = 100, 200
		source, err := discovery.NewDiscoveryClientForConfig(config)
		if err != nil {
			r.initErr = fmt.Errorf("create discovery client: %w", err)
			return
		}
		watcher, err := client.NewWithWatch(r.config, client.Options{Scheme: r.scheme})
		if err != nil {
			r.initErr = fmt.Errorf("create CRD watch client: %w", err)
			return
		}
		r.signalMu.Lock()
		defer r.signalMu.Unlock()
		r.tracker, r.initErr = discoverytracker.New(nonemptyDiscovery{source}, watcher, discoverytracker.Options{
			Interval:  r.collectionInterval(),
			Debounce:  100 * time.Millisecond,
			Transform: augmentRBACResources,
			Hooks: discoverytracker.Hooks{
				Collected: func(ctx context.Context, duration time.Duration, err error) {
					metrics.APIDiscoveryDuration.Observe(duration.Seconds())
					if err != nil {
						metrics.APIDiscoveryErrors.Inc()
					}
				},
			},
			OnChange: func(ctx context.Context, _ discoverytracker.Snapshot) {
				for _, callback := range r.signalFuncsSnapshot() {
					if err := callback(); err != nil {
						log.FromContext(ctx).Error(err, "failed to signal discovery change")
					}
				}
			},
		})
	})
	return r.initErr
}

// Start checks initial discovery and runs until cancellation, joining all workers.
func (r *ResourceTracker) Start(ctx context.Context) error {
	if _, err := r.collectAPIResources(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	workers.Go(func() {
		ticker := time.NewTicker(r.fullRescanInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := r.collectAPIResources(ctx); err != nil && ctx.Err() == nil {
					log.FromContext(ctx).Error(err, "failed to rescan API resources")
				}
			}
		}
	})
	defer func() { cancel(); workers.Wait() }()
	return r.tracker.Start(ctx)
}

// GetAPIResources returns an isolated snapshot or the not-started sentinel.
func (r *ResourceTracker) GetAPIResources() (APIResourcesByGroupVersion, error) {
	// Synchronize initialization with concurrent controller reads.
	r.signalMu.RLock()
	tracker := r.tracker
	r.signalMu.RUnlock()
	if tracker == nil {
		return nil, ErrResourceTrackerNotStarted
	}
	snapshot, err := tracker.Snapshot()
	if err == nil && countAPIResources(snapshot) == 0 {
		return nil, ErrResourceTrackerNotStarted
	}
	return snapshot, err
}

func (r *ResourceTracker) collectAPIResources(ctx context.Context) (bool, error) {
	if err := r.initialize(); err != nil {
		return false, err
	}
	changed, err := r.tracker.Refresh(ctx)
	if errors.Is(err, errEmptyDiscovery) {
		if _, snapshotErr := r.tracker.Snapshot(); snapshotErr == nil {
			return false, nil
		}
	}
	if snapshot, snapshotErr := r.tracker.Snapshot(); snapshotErr == nil && countAPIResources(snapshot) == 0 {
		return false, errors.Join(errEmptyDiscovery, err)
	}
	return changed, err
}

func (r *ResourceTracker) collectionInterval() time.Duration {
	if r.CollectionInterval > 0 {
		return r.CollectionInterval
	}
	return defaultCollectionInterval
}

func (r *ResourceTracker) fullRescanInterval() time.Duration {
	if r.FullRescanInterval > 0 {
		return r.FullRescanInterval
	}
	return defaultFullRescanInterval
}

type nonemptyDiscovery struct{ discoverytracker.Source }

// ServerGroupsAndResourcesWithContext prevents empty discovery from clearing RBAC.
func (s nonemptyDiscovery) ServerGroupsAndResourcesWithContext(ctx context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	groups, lists, err := s.Source.ServerGroupsAndResourcesWithContext(ctx)
	if err != nil {
		return groups, lists, err
	}
	for _, list := range lists {
		if list != nil && len(list.APIResources) > 0 {
			return groups, lists, nil
		}
	}
	return nil, nil, errEmptyDiscovery
}

func countAPIResources(resources APIResourcesByGroupVersion) int {
	count := 0
	for _, groupResources := range resources {
		count += len(groupResources)
	}
	return count
}

func augmentRBACResources(_ context.Context, snapshot discoverytracker.Snapshot) discoverytracker.Snapshot {
	for groupVersion, resources := range snapshot {
		gv, err := schema.ParseGroupVersion(groupVersion)
		if err != nil {
			continue
		}
		names := make(map[string]struct{}, len(resources))
		for _, resource := range resources {
			names[resource.Name] = struct{}{}
		}
		result := make([]metav1.APIResource, 0, len(resources)*2)
		for _, resource := range resources {
			isSubresource := strings.Contains(resource.Name, "/")
			if isSubresource && (strings.HasSuffix(resource.Name, "/status") || strings.HasSuffix(resource.Name, "/finalizers")) {
				for _, verb := range []string{verbList, verbWatch} {
					if !slices.Contains(resource.Verbs, verb) {
						resource.Verbs = append(resource.Verbs, verb)
					}
				}
			}
			resource = withExplicitRBACVerbs(gv.Group, gv.Version, resource)
			result = append(result, resource)
			if isSubresource {
				continue
			}
			if _, exists := names[resource.Name+"/finalizers"]; !exists {
				finalizers := resource.DeepCopy()
				finalizers.Name += "/finalizers"
				finalizers.Verbs = metav1.Verbs{verbUpdate, verbList, verbWatch}
				result = append(result, *finalizers)
			}
			if gv.Group == "" && gv.Version == "v1" && resource.Name == "nodes" {
				if _, exists := names["nodes/metrics"]; !exists {
					nodeMetrics := resource.DeepCopy()
					nodeMetrics.Name = "nodes/metrics"
					nodeMetrics.Verbs = metav1.Verbs{verbGet, verbList, verbWatch}
					result = append(result, *nodeMetrics)
				}
			}
		}
		snapshot[groupVersion] = result
	}
	return snapshot
}

func withExplicitRBACVerbs(group, version string, resource metav1.APIResource) metav1.APIResource {
	if group == rbacv1.GroupName && version == "v1" && (resource.Name == rbacResourceClusterRoles || resource.Name == rbacResourceRoles) {
		for _, verb := range []string{verbBind, verbEscalate} {
			if !slices.Contains(resource.Verbs, verb) {
				resource.Verbs = append(resource.Verbs, verb)
			}
		}
	}
	return resource
}
