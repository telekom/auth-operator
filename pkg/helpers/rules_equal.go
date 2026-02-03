package helpers

import (
	"fmt"
	"slices"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// PolicyRulesEqual compares two slices of PolicyRules for equality.
// It does not mutate the input slices.
func PolicyRulesEqual(a, b []rbacv1.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}

	// Make deep copies to avoid mutating the original slices
	aCopy := deepCopyPolicyRules(a)
	bCopy := deepCopyPolicyRules(b)

	// Sort both slices to ensure consistent ordering
	sortPolicyRules(aCopy)
	sortPolicyRules(bCopy)

	for i := range aCopy {
		if !policyRuleEqual(aCopy[i], bCopy[i]) {
			return false
		}
	}
	return true
}

// deepCopyPolicyRules creates a deep copy of a slice of PolicyRules.
func deepCopyPolicyRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	if rules == nil {
		return nil
	}
	result := make([]rbacv1.PolicyRule, len(rules))
	for i, rule := range rules {
		result[i] = rbacv1.PolicyRule{
			APIGroups:       slices.Clone(rule.APIGroups),
			Resources:       slices.Clone(rule.Resources),
			Verbs:           slices.Clone(rule.Verbs),
			ResourceNames:   slices.Clone(rule.ResourceNames),
			NonResourceURLs: slices.Clone(rule.NonResourceURLs),
		}
	}
	return result
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

	// Make copies to avoid mutating the original slices
	aCopy := slices.Clone(a)
	bCopy := slices.Clone(b)

	// Sort the copies to ensure consistent ordering
	sort.Strings(aCopy)
	sort.Strings(bCopy)

	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
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
