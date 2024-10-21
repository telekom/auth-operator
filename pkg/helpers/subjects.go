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

	return mergedSubjects
}

// Helper function to generate a unique key for a subject
func subjectKey(subject rbacv1.Subject) string {
	return subject.Kind + "|" + subject.APIGroup + "|" + subject.Namespace + "|" + subject.Name
}

// BySubject implements sort.Interface for []rbacv1.Subject based on Kind, APIGroup, Namespace, Name.
type BySubject []rbacv1.Subject

func (a BySubject) Len() int      { return len(a) }
func (a BySubject) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BySubject) Less(i, j int) bool {
	if a[i].Kind != a[j].Kind {
		return a[i].Kind < a[j].Kind
	}
	if a[i].APIGroup != a[j].APIGroup {
		return a[i].APIGroup < a[j].APIGroup
	}
	if a[i].Namespace != a[j].Namespace {
		return a[i].Namespace < a[j].Namespace
	}
	return a[i].Name < a[j].Name
}

// sortSubjects returns a sorted copy of the subjects slice.
func sortSubjects(subjects []rbacv1.Subject) []rbacv1.Subject {
	sorted := make([]rbacv1.Subject, len(subjects))
	copy(sorted, subjects)
	sort.Sort(BySubject(sorted))
	return sorted
}
