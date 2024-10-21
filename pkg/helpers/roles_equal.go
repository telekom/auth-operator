package helpers

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func ClusterRoleBindsEqual(existing, expected *rbacv1.ClusterRoleBinding) bool {
	// Compare Names
	if existing.Name != expected.Name {
		return false
	}

	// Compare Labels
	if !mapsEqual(existing.Labels, expected.Labels) {
		return false
	}

	// Compare RoleRef
	if !roleRefEqual(&existing.RoleRef, &expected.RoleRef) {
		return false
	}

	// Compare Subjects
	if !subjectsEqual(existing.Subjects, expected.Subjects) {
		return false
	}

	return true
}

func RoleBindsEqual(existing, expected *rbacv1.RoleBinding) bool {
	// Compare Names and Namespaces
	if existing.Name != expected.Name || existing.Namespace != expected.Namespace {
		return false
	}

	// Compare Labels
	if !mapsEqual(existing.Labels, expected.Labels) {
		return false
	}

	// Compare RoleRef
	if !roleRefEqual(&existing.RoleRef, &expected.RoleRef) {
		return false
	}

	// Compare Subjects
	if !subjectsEqual(existing.Subjects, expected.Subjects) {
		return false
	}

	return true
}

func ServiceAccountsEqual(existing, expected *corev1.ServiceAccount) bool {
	// Compare Names and Namespaces
	if existing.Name != expected.Name || existing.Namespace != expected.Namespace {
		return false
	}

	// Compare Labels
	if !mapsEqual(existing.Labels, expected.Labels) {
		return false
	}

	// Compare AutomountServiceAccountToken
	if existing.AutomountServiceAccountToken == nil && expected.AutomountServiceAccountToken != nil {
		return false
	}
	if existing.AutomountServiceAccountToken != nil && expected.AutomountServiceAccountToken == nil {
		return false
	}
	if existing.AutomountServiceAccountToken != nil && expected.AutomountServiceAccountToken != nil {
		if *existing.AutomountServiceAccountToken != *expected.AutomountServiceAccountToken {
			return false
		}
	}

	return true
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, valA := range a {
		valB, exists := b[key]
		if !exists || valA != valB {
			return false
		}
	}
	return true
}

func roleRefEqual(a, b *rbacv1.RoleRef) bool {
	if a.APIGroup != b.APIGroup || a.Kind != b.Kind || a.Name != b.Name {
		return false
	}
	return true
}

func subjectsEqual(a, b []rbacv1.Subject) bool {
	if len(a) != len(b) {
		return false
	}

	// Sort both slices before comparison
	sorterSubjects(a)
	sorterSubjects(b)

	for i := range a {
		if !subjectEqual(&a[i], &b[i]) {
			return false
		}
	}
	return true
}

func subjectEqual(a, b *rbacv1.Subject) bool {
	if a.APIGroup != b.APIGroup || a.Kind != b.Kind || a.Name != b.Name || a.Namespace != b.Namespace {
		return false
	}
	return true
}

func sorterSubjects(subjects []rbacv1.Subject) {
	sort.SliceStable(subjects, func(i, j int) bool {
		return subjects[i].Kind+subjects[i].Name < subjects[j].Kind+subjects[j].Name
	})
}
