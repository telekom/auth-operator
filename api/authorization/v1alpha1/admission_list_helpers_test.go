// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type admissionListPage struct {
	continueToken string
	items         []client.Object
}

type recordingAdmissionReader struct {
	pages  map[string]admissionListPage
	calls  []client.ListOptions
	getErr error
}

func (r *recordingAdmissionReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return r.getErr
}

func (r *recordingAdmissionReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	listOptions := client.ListOptions{}
	listOptions.ApplyOptions(opts)
	r.calls = append(r.calls, listOptions)

	page, ok := r.pages[listOptions.Continue]
	if !ok {
		return fmt.Errorf("unexpected continue token %q", listOptions.Continue)
	}

	items, err := meta.ExtractList(list)
	if err != nil {
		return err
	}
	items = items[:0]
	for _, item := range page.items {
		items = append(items, item)
	}
	if err := meta.SetList(list, items); err != nil {
		return err
	}
	list.SetContinue(page.continueToken)
	return nil
}

func TestListAdmissionPageUsesLimitAndContinue(t *testing.T) {
	reader := &recordingAdmissionReader{
		pages: map[string]admissionListPage{
			"next": {continueToken: "done"},
		},
	}

	list := &RBACPolicyList{}
	continueToken, err := listAdmissionPage(context.Background(), reader, list, "next")
	if err != nil {
		t.Fatalf("list admission page: %v", err)
	}
	if continueToken != "done" {
		t.Fatalf("expected continue token done, got %q", continueToken)
	}
	if len(reader.calls) != 1 {
		t.Fatalf("expected one list call, got %d", len(reader.calls))
	}
	if reader.calls[0].Limit != admissionListPageLimit {
		t.Fatalf("expected list limit %d, got %d", admissionListPageLimit, reader.calls[0].Limit)
	}
	if reader.calls[0].Continue != "next" {
		t.Fatalf("expected continue token next, got %q", reader.calls[0].Continue)
	}
}

func TestPolicyReferenceScansPageAndStopEarly(t *testing.T) {
	reader := &recordingAdmissionReader{
		pages: map[string]admissionListPage{
			"": {
				continueToken: "second",
				items: []client.Object{
					&RestrictedBindDefinition{
						ObjectMeta: metav1.ObjectMeta{Name: "unrelated"},
						Spec: RestrictedBindDefinitionSpec{
							PolicyRef: RBACPolicyReference{Name: "other-policy"},
						},
					},
				},
			},
			"second": {
				continueToken: "should-not-be-read",
				items: []client.Object{
					&RestrictedBindDefinition{
						ObjectMeta: metav1.ObjectMeta{Name: "referencing"},
						Spec: RestrictedBindDefinitionSpec{
							PolicyRef: RBACPolicyReference{Name: "target-policy"},
						},
					},
				},
			},
		},
	}

	found, err := policyHasRestrictedBindDefinitionReference(context.Background(), reader, "target-policy")
	if err != nil {
		t.Fatalf("scan policy references: %v", err)
	}
	if !found {
		t.Fatal("expected reference to be found")
	}
	if len(reader.calls) != 2 {
		t.Fatalf("expected scan to stop after second page, got %d calls", len(reader.calls))
	}
	for i, call := range reader.calls {
		if call.Limit != admissionListPageLimit {
			t.Fatalf("call %d used limit %d, want %d", i, call.Limit, admissionListPageLimit)
		}
	}
}

func TestPolicyReferenceScansAllPagesWhenNoReferenceExists(t *testing.T) {
	reader := &recordingAdmissionReader{
		pages: map[string]admissionListPage{
			"": {
				continueToken: "second",
				items: []client.Object{
					&RestrictedRoleDefinition{
						ObjectMeta: metav1.ObjectMeta{Name: "unrelated-a"},
						Spec: RestrictedRoleDefinitionSpec{
							PolicyRef: RBACPolicyReference{Name: "other-policy"},
						},
					},
				},
			},
			"second": {
				items: []client.Object{
					&RestrictedRoleDefinition{
						ObjectMeta: metav1.ObjectMeta{Name: "unrelated-b"},
						Spec: RestrictedRoleDefinitionSpec{
							PolicyRef: RBACPolicyReference{Name: "another-policy"},
						},
					},
				},
			},
		},
	}

	found, err := policyHasRestrictedRoleDefinitionReference(context.Background(), reader, "target-policy")
	if err != nil {
		t.Fatalf("scan policy references: %v", err)
	}
	if found {
		t.Fatal("expected no reference to be found")
	}
	if len(reader.calls) != 2 {
		t.Fatalf("expected scan to read both pages, got %d calls", len(reader.calls))
	}
}

var _ client.Reader = (*recordingAdmissionReader)(nil)
var _ runtime.Object = (*RBACPolicyList)(nil)
