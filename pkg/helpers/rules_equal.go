package helpers

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

/*
func policyRulesEqual(a, b []rbacv1.PolicyRule) ([]string, bool) {
	var changes []string

	// Collect unique API groups, resources, and verbs from both sets
	existingAPIGroupsSet := make(map[string]struct{})
	newAPIGroupsSet := make(map[string]struct{})
	existingResourcesSet := make(map[string]struct{})
	newResourcesSet := make(map[string]struct{})
	existingVerbsSet := make(map[string]struct{})
	newVerbsSet := make(map[string]struct{})

	for _, rule := range a {
		for _, apiGroup := range rule.APIGroups {
			existingAPIGroupsSet[apiGroup] = struct{}{}
		}
		for _, resource := range rule.Resources {
			existingResourcesSet[resource] = struct{}{}
		}
		for _, verb := range rule.Verbs {
			existingVerbsSet[verb] = struct{}{}
		}
	}

	for _, rule := range b {
		for _, apiGroup := range rule.APIGroups {
			newAPIGroupsSet[apiGroup] = struct{}{}
		}
		for _, resource := range rule.Resources {
			newResourcesSet[resource] = struct{}{}
		}
		for _, verb := range rule.Verbs {
			newVerbsSet[verb] = struct{}{}
		}
	}

	// Find added and removed API groups
	for apiGroup := range existingAPIGroupsSet {
		if _, exists := newAPIGroupsSet[apiGroup]; !exists {
			changes = append(changes, fmt.Sprintf("Removed API group '%s'", apiGroup))
		}
	}
	for apiGroup := range newAPIGroupsSet {
		if _, exists := existingAPIGroupsSet[apiGroup]; !exists {
			changes = append(changes, fmt.Sprintf("Added API group '%s'", apiGroup))
		}
	}

	// Find added and removed resources
	for resource := range existingResourcesSet {
		if _, exists := newResourcesSet[resource]; !exists {
			changes = append(changes, fmt.Sprintf("Removed resource '%s'", resource))
		}
	}
	for resource := range newResourcesSet {
		if _, exists := existingResourcesSet[resource]; !exists {
			changes = append(changes, fmt.Sprintf("Added resource '%s'", resource))
		}
	}

	// Find added and removed verbs
	for verb := range existingVerbsSet {
		if _, exists := newVerbsSet[verb]; !exists {
			changes = append(changes, fmt.Sprintf("Removed verb '%s'", verb))
		}
	}
	for verb := range newVerbsSet {
		if _, exists := existingVerbsSet[verb]; !exists {
			changes = append(changes, fmt.Sprintf("Added verb '%s'", verb))
		}
	}

	equal := len(changes) == 0
	return changes, equal
}

func sortPolicyRules(rules []rbacv1.PolicyRule) {
	for i := range rules {
		sort.Strings(rules[i].APIGroups)
		sort.Strings(rules[i].Resources)
		sort.Strings(rules[i].Verbs)
		sort.Strings(rules[i].ResourceNames)
		sort.Strings(rules[i].NonResourceURLs)
	}

	sort.SliceStable(rules, func(i, j int) bool {
		return policyRuleKey(rules[i]) < policyRuleKey(rules[j])
	})
}

func policyRuleKey(r rbacv1.PolicyRule) string {
	return fmt.Sprintf("apigroups=%v,resources=%v,verbs=%v,resourcenames=%v,nonresourceurls=%v",
		r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, r.NonResourceURLs)
}

*/

func PolicyRulesEqual(a, b []rbacv1.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}

	// Sort both slices to ensure consistent ordering
	sortPolicyRules(a)
	sortPolicyRules(b)

	for i := range a {
		if !policyRuleEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func policyRuleEqual(a, b rbacv1.PolicyRule) bool {
	return stringSlicesEqual(a.APIGroups, b.APIGroups) &&
		stringSlicesEqual(a.Resources, b.Resources) &&
		stringSlicesEqual(a.Verbs, b.Verbs) &&
		stringSlicesEqual(a.ResourceNames, b.ResourceNames) &&
		stringSlicesEqual(a.NonResourceURLs, b.NonResourceURLs)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Sort the slices to ensure consistent ordering
	sort.Strings(a)
	sort.Strings(b)

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortPolicyRules(rules []rbacv1.PolicyRule) {
	for i := range rules {
		sort.Strings(rules[i].APIGroups)
		sort.Strings(rules[i].Resources)
		sort.Strings(rules[i].Verbs)
		sort.Strings(rules[i].ResourceNames)
		sort.Strings(rules[i].NonResourceURLs)
	}

	sort.SliceStable(rules, func(i, j int) bool {
		return policyRuleKey(rules[i]) < policyRuleKey(rules[j])
	})
}

func policyRuleKey(r rbacv1.PolicyRule) string {
	return fmt.Sprintf("apigroups=%v,resources=%v,verbs=%v,resourcenames=%v,nonresourceurls=%v",
		r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, r.NonResourceURLs)
}
