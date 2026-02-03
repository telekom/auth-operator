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
