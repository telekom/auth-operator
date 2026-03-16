// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

type impersonatedClientFactory func(cfg *rest.Config, scheme *runtime.Scheme, username string) (client.Client, error)

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

	impersonatedClient, err := factory(baseConfig, scheme, username)
	if err != nil {
		return nil, "", fmt.Errorf("build impersonated apply client: %w", err)
	}

	return impersonatedClient, username, nil
}
