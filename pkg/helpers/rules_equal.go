package helpers

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

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
