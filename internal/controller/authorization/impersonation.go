// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

type impersonatedClientFactory func(cfg *rest.Config, scheme *runtime.Scheme, username string) (client.Client, error)

// impersonatedClientCache caches impersonated clients by username to avoid
// creating a new HTTP connection pool on every reconcile cycle.
// The cache is safe for concurrent use and lives for the lifetime of the
// controller, so entries are never evicted (the set of impersonation targets
// is small and bounded by the number of distinct impersonation usernames
// observed over the controller's lifetime).
type impersonatedClientCache struct {
	mu    sync.RWMutex
	cache map[string]client.Client
	group singleflight.Group
}

func newImpersonatedClientCache() *impersonatedClientCache {
	return &impersonatedClientCache{
		cache: make(map[string]client.Client),
	}
}

// getOrCreate returns the cached client for username, calling factory to build
// one if it does not yet exist. Cache reads use a shared read-lock so that
// lookups for different usernames do not serialise each other. A singleflight
// group ensures that concurrent callers for the same username wait for a single
// factory invocation rather than each spawning their own, without holding any
// lock during the (potentially slow) factory call.
func (c *impersonatedClientCache) getOrCreate(
	username string,
	cfg *rest.Config,
	scheme *runtime.Scheme,
	factory impersonatedClientFactory,
) (client.Client, error) {
	// Fast path: check cache under read-lock.
	c.mu.RLock()
	cl, ok := c.cache[username]
	c.mu.RUnlock()
	if ok {
		return cl, nil
	}

	// Slow path: use singleflight so only the first goroutine per username
	// calls the factory. Other concurrent callers for the same username block
	// here and share the result — no lock is held during the factory call so
	// goroutines for different usernames proceed in parallel.
	v, err, _ := c.group.Do(username, func() (any, error) {
		// Re-check under read-lock: a previous singleflight call may have
		// already populated the cache.
		c.mu.RLock()
		if cl, ok := c.cache[username]; ok {
			c.mu.RUnlock()
			return cl, nil
		}
		c.mu.RUnlock()

		built, err := factory(cfg, scheme, username)
		if err != nil {
			return nil, err
		}
		if built == nil {
			return nil, fmt.Errorf("impersonated client factory returned nil for %q", username)
		}

		c.mu.Lock()
		// Store only if still absent (another goroutine may have won the race
		// on a previous singleflight call that has since completed).
		if existing, ok := c.cache[username]; ok {
			c.mu.Unlock()
			return existing, nil
		}
		c.cache[username] = built
		c.mu.Unlock()
		return built, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(client.Client), nil //nolint:forcetypeassert // type is guaranteed by the closure above
}

func newImpersonatedClient(cfg *rest.Config, scheme *runtime.Scheme, username string) (client.Client, error) {
	impersonatedConfig := rest.CopyConfig(cfg)
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{UserName: username}

	impersonatedClient, err := client.New(impersonatedConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create impersonated client for %q: %w", username, err)
	}

	return impersonatedClient, nil
}

func impersonatedUsernameForPolicy(policy *authorizationv1alpha1.RBACPolicy) (username string, enabled bool, err error) {
	if policy == nil || policy.Spec.Impersonation == nil {
		return "", false, nil
	}
	if !policy.Spec.Impersonation.Enabled {
		return "", false, nil
	}
	if policy.Spec.Impersonation.ServiceAccountRef == nil {
		return "", false, fmt.Errorf("policy %q has impersonation.enabled=true but no serviceAccountRef", policy.Name)
	}

	saRef := ptr.Deref(policy.Spec.Impersonation.ServiceAccountRef, authorizationv1alpha1.SARef{})
	if saRef.Name == "" || saRef.Namespace == "" {
		return "", false, fmt.Errorf("policy %q impersonation serviceAccountRef must include name and namespace", policy.Name)
	}

	return fmt.Sprintf("system:serviceaccount:%s:%s", saRef.Namespace, saRef.Name), true, nil
}

func resolvePolicyApplyClient(
	baseClient client.Client,
	scheme *runtime.Scheme,
	baseConfig *rest.Config,
	policy *authorizationv1alpha1.RBACPolicy,
	factory impersonatedClientFactory,
	cache *impersonatedClientCache,
) (client.Client, string, error) {
	username, enabled, err := impersonatedUsernameForPolicy(policy)
	if err != nil {
		return nil, "", err
	}
	if !enabled {
		return baseClient, "", nil
	}

	if baseConfig == nil {
		return nil, "", fmt.Errorf("impersonation configured by policy %q but controller rest config is unavailable", policy.Name)
	}
	if factory == nil {
		factory = newImpersonatedClient
	}

	var impersonatedClient client.Client
	if cache != nil {
		impersonatedClient, err = cache.getOrCreate(username, baseConfig, scheme, factory)
	} else {
		impersonatedClient, err = factory(baseConfig, scheme, username)
	}
	if err != nil {
		return nil, "", fmt.Errorf("build impersonated apply client: %w", err)
	}

	return impersonatedClient, username, nil
}
