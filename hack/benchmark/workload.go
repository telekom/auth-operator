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
	case resourceNamespaces, resourceServiceAccount + "s", resourceSecret + "s", isolationRBACGroup, isolationCRDGroup:
		return k, nil
	default:
		return "", fmt.Errorf("unsupported isolation tier %q", tier)
	}
}

// IsolationKind returns the benchmark resource kind selected by an isolation
// tier. Planning and execution share this mapping so the planned result keys
// exactly match the emitted cells.
func IsolationKind(tier string) (string, error) {
	resource, err := IsolationResource(tier)
	if err != nil {
		return "", err
	}
	switch resource {
	case resourceNamespaces:
		return resourceNamespace, nil
	case resourceServiceAccounts:
		return resourceServiceAccount, nil
	case resourceSecrets:
		return resourceSecret, nil
	case isolationRBACGroup:
		return resourceRole, nil
	case isolationCRDGroup:
		return resourceRoleDefinition, nil
	default:
		return "", fmt.Errorf("unsupported isolation resource %q", resource)
	}
}

// operationalMode maps component-only measurements to the corresponding
// policy mode. The component name remains part of the Cell identity so these
// measurements are reported separately from the core mode matrix.
func operationalMode(mode string) string {
	switch mode {
	case modeComponentStamp:
		return modeCreateOnly
	case modeComponentRestore:
		return modeProtect
	case modeComponentContrib:
		return modeContributors
	default:
		return mode
	}
}

func validBenchmarkMode(mode string) bool {
	switch mode {
	case modeCreateOnly, modeProtect, modeContributors,
		modeComponentStamp, modeComponentRestore, modeComponentContrib:
		return true
	default:
		return false
	}
}

func isolationTiers() []string {
	return []string{
		"iso-" + resourceNamespaces,
		"iso-" + resourceServiceAccount + "s",
		"iso-" + resourceSecret + "s",
		"iso-" + isolationRBACGroup,
		"iso-" + isolationCRDGroup,
	}
}
