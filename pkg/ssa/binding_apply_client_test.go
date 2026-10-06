// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestBindingApplyClientCanonicalization(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		clusterScoped bool
	}{
		{name: "cluster scoped", clusterScoped: true},
		{name: "namespaced"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			subjects := []*rbacv1ac.SubjectApplyConfiguration{
				rbacv1ac.Subject().WithKind(rbacv1.UserKind).WithName("bob"),
				rbacv1ac.Subject().WithKind(rbacv1.UserKind).WithName("alice"),
			}
			owners := []*metav1ac.OwnerReferenceApplyConfiguration{
				metav1ac.OwnerReference().WithAPIVersion("v1").WithKind("Namespace").WithName("z").WithUID("z"),
				metav1ac.OwnerReference().WithAPIVersion("v1").WithKind("Namespace").WithName("a").WithUID("a"),
			}
			var desired runtime.ApplyConfiguration = rbacv1ac.RoleBinding("binding", "namespace").
				WithSubjects(subjects...).WithOwnerReferences(owners...)
			if testCase.clusterScoped {
				desired = rbacv1ac.ClusterRoleBinding("binding").WithSubjects(subjects...).WithOwnerReferences(owners...)
			}
			before, err := json.Marshal(desired)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &bindingRecordingClient{}
			adapter := &bindingApplyClient{Client: recorder}
			if err := adapter.Apply(context.Background(), desired,
				client.FieldOwner(FieldOwner), client.ForceOwnership, client.DryRunAll); err != nil {
				t.Fatal(err)
			}
			if recorder.applied == desired {
				t.Fatal("apply forwarded the caller's configuration instead of an isolated clone")
			}
			after, err := json.Marshal(desired)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("apply canonicalization mutated the caller's configuration")
			}
			switch applied := recorder.applied.(type) {
			case *rbacv1ac.ClusterRoleBindingApplyConfiguration:
				assertCanonicalBindingLists(t, applied.Subjects, applied.OwnerReferences)
			case *rbacv1ac.RoleBindingApplyConfiguration:
				assertCanonicalBindingLists(t, applied.Subjects, applied.OwnerReferences)
			default:
				t.Fatalf("unexpected apply configuration %T", recorder.applied)
			}
			options := recorder.options
			if options.FieldManager != FieldOwner || options.Force == nil || !*options.Force ||
				!slices.Equal(options.DryRun, []string{metav1.DryRunAll}) {
				t.Fatalf("apply options were not preserved: %+v", options)
			}
		})
	}
}

func assertCanonicalBindingLists(t *testing.T, subjects []rbacv1ac.SubjectApplyConfiguration, owners []metav1ac.OwnerReferenceApplyConfiguration) {
	t.Helper()
	if len(subjects) != 2 || subjects[0].Name == nil || subjects[1].Name == nil ||
		*subjects[0].Name != "alice" || *subjects[1].Name != "bob" {
		t.Fatalf("subjects were not sorted: %+v", subjects)
	}
	for _, subject := range subjects {
		if subject.APIGroup == nil || *subject.APIGroup != rbacv1.GroupName {
			t.Fatalf("User APIGroup was not defaulted: %+v", subject)
		}
	}
	if len(owners) != 2 || owners[0].UID == nil || owners[1].UID == nil || *owners[0].UID != "a" || *owners[1].UID != "z" {
		t.Fatalf("owner references were not sorted: %+v", owners)
	}
}

type bindingRecordingClient struct {
	client.Client
	applied runtime.ApplyConfiguration
	options *client.ApplyOptions
}

func (c *bindingRecordingClient) Apply(_ context.Context, ac runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	c.applied = ac
	c.options = (&client.ApplyOptions{}).ApplyOptions(opts)
	return nil
}
