package helpers

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestSubjectsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []rbacv1.Subject
		b    []rbacv1.Subject
		want bool
	}{
		{
			name: "both empty",
			a:    []rbacv1.Subject{},
			b:    []rbacv1.Subject{},
			want: true,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "same single subject",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins", APIGroup: "rbac.authorization.k8s.io"}},
			b:    []rbacv1.Subject{{Kind: "Group", Name: "admins", APIGroup: "rbac.authorization.k8s.io"}},
			want: true,
		},
		{
			name: "different length",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:    []rbacv1.Subject{},
			want: false,
		},
		{
			name: "different subjects",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:    []rbacv1.Subject{{Kind: "Group", Name: "users"}},
			want: false,
		},
		{
			name: "same subjects different order",
			a: []rbacv1.Subject{
				{Kind: "Group", Name: "admins"},
				{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
			},
			b: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
				{Kind: "Group", Name: "admins"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SubjectsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("SubjectsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectsEqualDoesNotMutateInput(t *testing.T) {
	a := []rbacv1.Subject{
		{Kind: "Group", Name: "b"},
		{Kind: "Group", Name: "a"},
	}
	b := []rbacv1.Subject{
		{Kind: "Group", Name: "a"},
		{Kind: "Group", Name: "b"},
	}

	aOriginal := make([]rbacv1.Subject, len(a))
	copy(aOriginal, a)
	bOriginal := make([]rbacv1.Subject, len(b))
	copy(bOriginal, b)

	SubjectsEqual(a, b)

	for i := range a {
		if a[i] != aOriginal[i] {
			t.Errorf("SubjectsEqual mutated input 'a' at index %d", i)
		}
	}
	for i := range b {
		if b[i] != bOriginal[i] {
			t.Errorf("SubjectsEqual mutated input 'b' at index %d", i)
		}
	}
}

func TestPolicyRulesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []rbacv1.PolicyRule
		b    []rbacv1.PolicyRule
		want bool
	}{
		{
			name: "both empty",
			a:    []rbacv1.PolicyRule{},
			b:    []rbacv1.PolicyRule{},
			want: true,
		},
		{
			name: "same single rule",
			a: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
			b: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
			want: true,
		},
		{
			name: "different verbs",
			a: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
			b: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
			},
			want: false,
		},
		{
			name: "different length",
			a: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
			b:    []rbacv1.PolicyRule{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyRulesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("PolicyRulesEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyRulesEqualDoesNotMutateInput(t *testing.T) {
	// Create input slices with unsorted elements
	a := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps", ""},
			Resources: []string{"pods", "deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"create"},
		},
	}
	b := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"", "apps"},
			Resources: []string{"deployments", "pods"},
			Verbs:     []string{"watch", "list", "get"},
		},
	}

	// Store original values to compare after function call
	aOriginal := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps", ""},
			Resources: []string{"pods", "deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"create"},
		},
	}
	bOriginal := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"", "apps"},
			Resources: []string{"deployments", "pods"},
			Verbs:     []string{"watch", "list", "get"},
		},
	}

	// Call the function (should return true since they are equivalent)
	result := PolicyRulesEqual(a, b)
	if !result {
		t.Errorf("PolicyRulesEqual() = %v, want true", result)
	}

	// Verify input slices were not mutated
	for i := range a {
		if len(a[i].APIGroups) != len(aOriginal[i].APIGroups) {
			t.Errorf("PolicyRulesEqual mutated input 'a' APIGroups at index %d", i)
		}
		for j := range a[i].APIGroups {
			if a[i].APIGroups[j] != aOriginal[i].APIGroups[j] {
				t.Errorf("PolicyRulesEqual mutated input 'a' APIGroups[%d] at index %d: got %q, want %q",
					j, i, a[i].APIGroups[j], aOriginal[i].APIGroups[j])
			}
		}
		for j := range a[i].Resources {
			if a[i].Resources[j] != aOriginal[i].Resources[j] {
				t.Errorf("PolicyRulesEqual mutated input 'a' Resources[%d] at index %d: got %q, want %q",
					j, i, a[i].Resources[j], aOriginal[i].Resources[j])
			}
		}
		for j := range a[i].Verbs {
			if a[i].Verbs[j] != aOriginal[i].Verbs[j] {
				t.Errorf("PolicyRulesEqual mutated input 'a' Verbs[%d] at index %d: got %q, want %q",
					j, i, a[i].Verbs[j], aOriginal[i].Verbs[j])
			}
		}
	}

	for i := range b {
		for j := range b[i].APIGroups {
			if b[i].APIGroups[j] != bOriginal[i].APIGroups[j] {
				t.Errorf("PolicyRulesEqual mutated input 'b' APIGroups[%d] at index %d: got %q, want %q",
					j, i, b[i].APIGroups[j], bOriginal[i].APIGroups[j])
			}
		}
		for j := range b[i].Resources {
			if b[i].Resources[j] != bOriginal[i].Resources[j] {
				t.Errorf("PolicyRulesEqual mutated input 'b' Resources[%d] at index %d: got %q, want %q",
					j, i, b[i].Resources[j], bOriginal[i].Resources[j])
			}
		}
		for j := range b[i].Verbs {
			if b[i].Verbs[j] != bOriginal[i].Verbs[j] {
				t.Errorf("PolicyRulesEqual mutated input 'b' Verbs[%d] at index %d: got %q, want %q",
					j, i, b[i].Verbs[j], bOriginal[i].Verbs[j])
			}
		}
	}
}

func TestClusterRoleBindsEqual(t *testing.T) {
	tests := []struct {
		name     string
		existing *rbacv1.ClusterRoleBinding
		expected *rbacv1.ClusterRoleBinding
		want     bool
	}{
		{
			name: "equal bindings",
			existing: &rbacv1.ClusterRoleBinding{
				RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "admin"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			},
			expected: &rbacv1.ClusterRoleBinding{
				RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "admin"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			},
			want: true,
		},
		{
			name: "different role ref",
			existing: &rbacv1.ClusterRoleBinding{
				RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "admin"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			},
			expected: &rbacv1.ClusterRoleBinding{
				RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClusterRoleBindsEqual(tt.existing, tt.expected)
			if got != tt.want {
				t.Errorf("ClusterRoleBindsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectExists(t *testing.T) {
	subjects := []rbacv1.Subject{
		{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
		{Kind: "Group", Name: "admins"},
	}

	tests := []struct {
		name    string
		subject rbacv1.Subject
		want    bool
	}{
		{
			name:    "existing ServiceAccount",
			subject: rbacv1.Subject{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
			want:    true,
		},
		{
			name:    "non-existing subject",
			subject: rbacv1.Subject{Kind: "User", Name: "john"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SubjectExists(subjects, tt.subject)
			if got != tt.want {
				t.Errorf("SubjectExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeSubjects(t *testing.T) {
	tests := []struct {
		name    string
		a       []rbacv1.Subject
		b       []rbacv1.Subject
		wantLen int
	}{
		{
			name:    "merge non-overlapping",
			a:       []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:       []rbacv1.Subject{{Kind: "Group", Name: "users"}},
			wantLen: 2,
		},
		{
			name:    "merge overlapping",
			a:       []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:       []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeSubjects(tt.a, tt.b)
			if len(got) != tt.wantLen {
				t.Errorf("MergeSubjects() returned %d subjects, want %d", len(got), tt.wantLen)
			}
		})
	}
}
