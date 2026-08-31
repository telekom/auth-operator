// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import "fmt"

type Workload struct {
	Name, Tier, Kind, Verb string
	Requests, Concurrency  int
}

func (w Workload) Validate() error {
	if w.Name == "" || w.Tier == "" || w.Kind == "" || w.Verb == "" {
		return fmt.Errorf("workload fields must be non-empty")
	}
	if w.Requests < 1 || w.Concurrency < 1 {
		return fmt.Errorf("requests and concurrency must be positive")
	}
	return nil
}

// Tier resource scopes grow while the object workload stays service-account based.
var tierScopes = map[string][]string{
	"t1": {resourceServiceAccount},
	"t2": {resourceServiceAccount, resourceSecret},
	"t3": {resourceServiceAccount, resourceSecret, resourceRole, resourceRoleBinding},
	"t4": {resourceServiceAccount, resourceSecret, resourceRole, resourceRoleBinding, resourceClusterRole, resourceClusterRoleBinding, resourceRoleDefinition, resourceBindDefinition},
}

func TierResources(tier string) ([]string, error) {
	v, ok := tierScopes[tier]
	if !ok {
		return nil, fmt.Errorf("invalid tier %q", tier)
	}
	return append([]string(nil), v...), nil
}

func tierScope(tier string) []string {
	if scopes, ok := tierScopes[tier]; ok {
		return scopes
	}
	if resource, err := IsolationResource(tier); err == nil {
		return []string{resource}
	}
	return nil
}

func IsolationResource(tier string) (string, error) {
	if len(tier) < 4 || tier[:4] != "iso-" {
		return "", fmt.Errorf("not an isolation tier")
	}
	switch k := tier[4:]; k {
	case resourceNamespaces, resourceServiceAccount + "s", resourceSecret + "s", "rbac-group", "crd-group":
		return k, nil
	default:
		return "", fmt.Errorf("unsupported isolation tier %q", tier)
	}
}
