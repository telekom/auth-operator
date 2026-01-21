package helpers

import (
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// SubjectExists checks if an rbacv1.Subject exists in a slice
func SubjectExists(subjectList []rbacv1.Subject, subject rbacv1.Subject) bool {
	for _, existingSubject := range subjectList {
		if existingSubject.Kind == subject.Kind &&
			existingSubject.Name == subject.Name &&
			existingSubject.Namespace == subject.Namespace &&
			existingSubject.APIGroup == subject.APIGroup {
			return true
		}
	}
	return false
}

// MergeSubjects merges two slices of rbacv1.Subject without duplicates
func MergeSubjects(existingSubjects []rbacv1.Subject, newSubjects []rbacv1.Subject) []rbacv1.Subject {
	// Create a map to hold Subjects with keys as "kind|apiGroup|namespace|name"
	subjectMap := make(map[string]rbacv1.Subject)

	// Add existing Subjects to the map
	for _, subject := range existingSubjects {
		key := subjectKey(subject)
		subjectMap[key] = subject
	}

	// Add new Subjects to the map (overwriting if they already exist)
	for _, subject := range newSubjects {
		key := subjectKey(subject)
		subjectMap[key] = subject
	}

	// Convert the map back to a slice
	mergedSubjects := make([]rbacv1.Subject, 0, len(subjectMap))
	for _, subject := range subjectMap {
		mergedSubjects = append(mergedSubjects, subject)
	}

	// Sort subjects for deterministic ordering
	sort.Slice(mergedSubjects, func(i, j int) bool {
		return subjectKey(mergedSubjects[i]) < subjectKey(mergedSubjects[j])
	})

	return mergedSubjects
}

// Helper function to generate a unique key for a subject
func subjectKey(subject rbacv1.Subject) string {
	return subject.Kind + "|" + subject.APIGroup + "|" + subject.Namespace + "|" + subject.Name
}
