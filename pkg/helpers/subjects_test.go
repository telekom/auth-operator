// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestSubjectExists_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		subjectList []rbacv1.Subject
		subject     rbacv1.Subject
		want        bool
	}{
		{
			name:        "empty list returns false",
			subjectList: []rbacv1.Subject{},
			subject: rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				Name:     "admin",
				APIGroup: rbacv1.GroupName,
			},
			want: false,
		},
		{
			name:        "nil list returns false",
			subjectList: nil,
			subject: rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				Name:     "admin",
				APIGroup: rbacv1.GroupName,
			},
			want: false,
		},
		{
			name: "subject found with exact match",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName},
			},
			subject: rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				Name:     "admin",
				APIGroup: rbacv1.GroupName,
			},
			want: true,
		},
		{
			name: "subject not found - different name",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
			},
			subject: rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				Name:     "user",
				APIGroup: rbacv1.GroupName,
			},
			want: false,
		},
		{
			name: "subject not found - different kind",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
			},
			subject: rbacv1.Subject{
				Kind:     rbacv1.GroupKind,
				Name:     "admin",
				APIGroup: rbacv1.GroupName,
			},
			want: false,
		},
		{
			name: "subject not found - different namespace",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "sa", Namespace: "default"},
			},
			subject: rbacv1.Subject{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "sa",
				Namespace: "kube-system",
			},
			want: false,
		},
		{
			name: "subject not found - different APIGroup",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
			},
			subject: rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				Name:     "admin",
				APIGroup: "",
			},
			want: false,
		},
		{
			name: "ServiceAccount subject found with namespace",
			subjectList: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "controller", Namespace: "kube-system"},
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
			},
			subject: rbacv1.Subject{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "controller",
				Namespace: "kube-system",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SubjectExists(tt.subjectList, tt.subject)
			if got != tt.want {
				t.Errorf("SubjectExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeSubjects_EdgeCases(t *testing.T) {
	tests := []struct {
		name             string
		existingSubjects []rbacv1.Subject
		newSubjects      []rbacv1.Subject
		wantLen          int
		wantContains     []rbacv1.Subject
	}{
		{
			name:             "both nil returns empty slice",
			existingSubjects: nil,
			newSubjects:      nil,
			wantLen:          0,
			wantContains:     []rbacv1.Subject{},
		},
		{
			name:             "both empty returns empty slice",
			existingSubjects: []rbacv1.Subject{},
			newSubjects:      []rbacv1.Subject{},
			wantLen:          0,
			wantContains:     []rbacv1.Subject{},
		},
		{
			name:             "existing only - nil new",
			existingSubjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}},
			newSubjects:      nil,
			wantLen:          1,
			wantContains:     []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}},
		},
		{
			name:             "new only - nil existing",
			existingSubjects: nil,
			newSubjects:      []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}},
			wantLen:          1,
			wantContains:     []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}},
		},
		{
			name:             "no overlap - merge all",
			existingSubjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}},
			newSubjects:      []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName}},
			wantLen:          2,
			wantContains: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName},
			},
		},
		{
			name: "full overlap - deduplicates",
			existingSubjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName},
			},
			newSubjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName},
			},
			wantLen: 2,
			wantContains: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.GroupKind, Name: "developers", APIGroup: rbacv1.GroupName},
			},
		},
		{
			name: "partial overlap",
			existingSubjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
			},
			newSubjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName}, // duplicate
				{Kind: rbacv1.UserKind, Name: "user2", APIGroup: rbacv1.GroupName}, // new
			},
			wantLen: 3, // admin, user1, user2
			wantContains: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.UserKind, Name: "user1", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.UserKind, Name: "user2", APIGroup: rbacv1.GroupName},
			},
		},
		{
			name: "ServiceAccounts with namespaces",
			existingSubjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "sa1", Namespace: "ns1"},
			},
			newSubjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "sa1", Namespace: "ns2"}, // different namespace
				{Kind: rbacv1.ServiceAccountKind, Name: "sa2", Namespace: "ns1"},
			},
			wantLen: 3, // same name but different namespace treated as different subjects
			wantContains: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: "sa1", Namespace: "ns1"},
				{Kind: rbacv1.ServiceAccountKind, Name: "sa1", Namespace: "ns2"},
				{Kind: rbacv1.ServiceAccountKind, Name: "sa2", Namespace: "ns1"},
			},
		},
		{
			name: "result is sorted deterministically",
			existingSubjects: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "z-group", APIGroup: rbacv1.GroupName},
			},
			newSubjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "a-user", APIGroup: rbacv1.GroupName},
			},
			wantLen: 2,
			wantContains: []rbacv1.Subject{
				{Kind: rbacv1.GroupKind, Name: "z-group", APIGroup: rbacv1.GroupName},
				{Kind: rbacv1.UserKind, Name: "a-user", APIGroup: rbacv1.GroupName},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeSubjects(tt.existingSubjects, tt.newSubjects)
			if len(got) != tt.wantLen {
				t.Errorf("MergeSubjects() length = %d, want %d", len(got), tt.wantLen)
			}
			for _, want := range tt.wantContains {
				if !SubjectExists(got, want) {
					t.Errorf("MergeSubjects() missing subject: %+v", want)
				}
			}
		})
	}
}

func TestMergeSubjects_SortOrder(t *testing.T) {
	// Run merge twice with different input orders, result should be same
	subjects1 := []rbacv1.Subject{
		{Kind: rbacv1.UserKind, Name: "charlie", APIGroup: rbacv1.GroupName},
		{Kind: rbacv1.UserKind, Name: "alice", APIGroup: rbacv1.GroupName},
	}
	subjects2 := []rbacv1.Subject{
		{Kind: rbacv1.UserKind, Name: "bob", APIGroup: rbacv1.GroupName},
	}

	result1 := MergeSubjects(subjects1, subjects2)
	result2 := MergeSubjects(subjects2, subjects1)

	if len(result1) != len(result2) {
		t.Fatalf("Results have different lengths: %d vs %d", len(result1), len(result2))
	}

	// Results should be in same order regardless of input order
	for i := range result1 {
		if result1[i].Name != result2[i].Name {
			t.Errorf("Sort order differs at index %d: %s vs %s", i, result1[i].Name, result2[i].Name)
		}
	}
}

func TestSubjectKey(t *testing.T) {
	// Test that the key function creates unique keys for different subjects
	tests := []struct {
		name     string
		subject1 rbacv1.Subject
		subject2 rbacv1.Subject
		sameKey  bool
	}{
		{
			name: "identical subjects have same key",
			subject1: rbacv1.Subject{
				Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName,
			},
			subject2: rbacv1.Subject{
				Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName,
			},
			sameKey: true,
		},
		{
			name: "different name - different key",
			subject1: rbacv1.Subject{
				Kind: rbacv1.UserKind, Name: "admin", APIGroup: rbacv1.GroupName,
			},
			subject2: rbacv1.Subject{
				Kind: rbacv1.UserKind, Name: "user", APIGroup: rbacv1.GroupName,
			},
			sameKey: false,
		},
		{
			name: "different namespace - different key",
			subject1: rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind, Name: "sa", Namespace: "ns1",
			},
			subject2: rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind, Name: "sa", Namespace: "ns2",
			},
			sameKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := subjectKey(tt.subject1)
			key2 := subjectKey(tt.subject2)
			if (key1 == key2) != tt.sameKey {
				t.Errorf("subjectKey() sameKey = %v, want %v (key1=%s, key2=%s)",
					key1 == key2, tt.sameKey, key1, key2)
			}
		})
	}
}
