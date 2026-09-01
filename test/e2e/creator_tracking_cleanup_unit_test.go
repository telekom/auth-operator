//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func TestCreatorPrivateRunDirRequiresProvenance(t *testing.T) {
	runDir := t.TempDir()
	if err := os.Chmod(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("E2E_CREATOR_TRACKING_RUN_DIR", runDir)
	if _, err := creatorPrivateRunDir(); err == nil {
		t.Fatal("expected missing provenance marker to fail")
	}
	marker := filepath.Join(runDir, "provenance")
	if err := os.WriteFile(marker, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := creatorPrivateRunDir(); err == nil {
		t.Fatal("expected empty provenance marker to fail")
	}
	if err := os.WriteFile(marker, []byte("wrong-cluster\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := creatorPrivateRunDir(); err == nil {
		t.Fatal("expected wrong provenance value to fail")
	}
	if err := os.WriteFile(marker, []byte("auth-operator-e2e-creator-tracking\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := creatorPrivateRunDir(); err != nil {
		t.Fatalf("valid provenance marker: %v", err)
	}
	if err := os.Chmod(marker, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := creatorPrivateRunDir(); err == nil {
		t.Fatal("expected non-private provenance marker to fail")
	}
}

func TestCreatorPrivatePathsRejectSymlinks(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "provenance"), []byte("auth-operator-e2e-creator-tracking\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("E2E_CREATOR_TRACKING_RUN_DIR", link)
	if _, err := creatorPrivateRunDir(); err == nil {
		t.Fatal("expected symlink run directory to fail")
	}
	t.Setenv("E2E_CREATOR_TRACKING_RUN_DIR", target)
	kubeconfig := filepath.Join(target, "cluster.kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	kubeLink := filepath.Join(target, "kubeconfig-link")
	if err := os.Symlink(kubeconfig, kubeLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeLink)
	if _, err := creatorPrivateKubeconfig(); err == nil {
		t.Fatal("expected symlink kubeconfig to fail")
	}
}

func TestCreatorDockerImageKnownAbsent(t *testing.T) {
	for _, output := range [][]byte{[]byte("Error: No such image: example:test"), []byte("No such object")} {
		if !creatorDockerImageKnownAbsent(output) {
			t.Fatalf("expected known-absent output: %q", output)
		}
	}
	if creatorDockerImageKnownAbsent([]byte("Cannot connect to the Docker daemon")) {
		t.Fatal("daemon failure must not be treated as image absence")
	}
}

func TestCreatorRunnerUsesOwnedRegularLock(t *testing.T) {
	runner, err := os.ReadFile("../../hack/run-creator-tracking-e2e.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(runner)
	for _, required := range []string{
		"cd -- \"$repo_root\"",
		"set -C; : >\"$lock_file\"",
		"lock_type=$(stat -c %F",
		"lock_owner=$(stat -c %u",
		"lock_mode=$(stat -c %a",
		"$lock_type != \"regular file\"",
		"$lock_owner != \"$lock_uid\"",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("runner lock check is missing %q", required)
		}
	}
	if strings.Contains(script, "touch \"$lock_file\"") {
		t.Fatal("runner must not touch the fixed lock path")
	}
}

func TestCreatorManagedFieldAnnotationOwnership(t *testing.T) {
	fields := map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{
		creatorManagedFieldKey(createdByAnnotation):       map[string]any{},
		creatorManagedFieldKey(createdByGroupsAnnotation): map[string]any{},
		creatorManagedFieldKey(updatedByAnnotation):       map[string]any{},
	}}}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	object := creatorObject{}
	object.Metadata.ManagedFields = []creatorManagedField{{Manager: "user-manager", Operation: "Apply", FieldsV1: raw}}
	if err := creatorValidateManagedFields(object, nil); err == nil {
		t.Fatal("expected user manager annotation ownership to be rejected")
	} else if !strings.Contains(err.Error(), createdByAnnotation) {
		t.Fatalf("error = %v, want creator annotation path", err)
	}
}

func TestCreatorManagedFieldsDuplicateManagerEntries(t *testing.T) {
	unrelated, err := json.Marshal(map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := json.Marshal(map[string]any{"f:spec": map[string]any{"f:subjects": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	object := creatorObject{}
	object.Metadata.ManagedFields = []creatorManagedField{
		{Manager: "repeated-manager", Operation: "Update", FieldsV1: unrelated},
		{Manager: "repeated-manager", Operation: "Apply", FieldsV1: unrelated},
		{Manager: "repeated-manager", Operation: "Apply", FieldsV1: wanted},
	}
	expected := []creatorExpectedManagedField{{
		Manager:   "repeated-manager",
		Operation: "Apply",
		Paths:     [][]string{{"f:spec", "f:subjects"}},
	}}
	if err := creatorValidateManagedFields(object, expected); err != nil {
		t.Fatalf("duplicate manager entries: %v", err)
	}
}

func TestCreatorManagedFieldsDuplicateManagerAnnotationOwnership(t *testing.T) {
	wanted, err := json.Marshal(map[string]any{"f:spec": map[string]any{"f:subjects": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	forbidden, err := json.Marshal(map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{
		creatorManagedFieldKey(updatedByAnnotation): map[string]any{},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	object := creatorObject{}
	object.Metadata.ManagedFields = []creatorManagedField{
		{Manager: "repeated-manager", Operation: "Apply", FieldsV1: wanted},
		{Manager: "repeated-manager", Operation: "Update", FieldsV1: forbidden},
	}
	expected := []creatorExpectedManagedField{{
		Manager:   "repeated-manager",
		Operation: "Apply",
		Paths:     [][]string{{"f:spec", "f:subjects"}},
	}}
	if err := creatorValidateManagedFields(object, expected); err == nil {
		t.Fatal("expected creator annotation ownership in a duplicate entry to be rejected")
	} else if !strings.Contains(err.Error(), updatedByAnnotation) {
		t.Fatalf("error = %v, want updated-by annotation path", err)
	}
}

func TestCreatorCleanupUnrelatedFinalizerPreserved(t *testing.T) {
	got := creatorRemoveExactFinalizer([]string{authorizationv1alpha1.BindDefinitionFinalizer, "example.com/keep"}, authorizationv1alpha1.BindDefinitionFinalizer)
	want := []string{"example.com/keep"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finalizers = %v, want %v", got, want)
	}
}

func TestCreatorCleanupFrontendBarrier(t *testing.T) {
	plan := creatorCleanupPlan(false, true, true)
	for _, forbidden := range []string{"admission-policies", "reinvocation-backend", "helm-uninstall", "release-sweep", "namespaces"} {
		if containsString(plan, forbidden) {
			t.Fatalf("unsafe phase %q in failed frontend plan: %v", forbidden, plan)
		}
	}
}

func TestCreatorCleanupPartialUninstallStillSweeps(t *testing.T) {
	plan := creatorCleanupPlan(true, true, true)
	if !containsString(plan, "helm-uninstall") || !containsString(plan, "release-sweep") {
		t.Fatalf("plan = %v, want uninstall and exact sweep", plan)
	}
}

func TestCreatorCleanupReportsIndependentErrors(t *testing.T) {
	var got []error
	first, second := errors.New("frontend failed"), errors.New("role cleanup failed")
	creatorAppendErrors(&got, []error{first})
	creatorAppendErrors(&got, []error{second})
	if len(got) != 2 || !errors.Is(got[0], first) || !errors.Is(got[1], second) {
		t.Fatalf("errors = %v, want both independent errors", got)
	}
	if !containsString(creatorCleanupPlan(true, true, true), "release-sweep") {
		t.Fatal("safe cleanup phases must remain available after independent errors")
	}
}

func TestCreatorReleaseAdmissionFrontendsAreScoped(t *testing.T) {
	resources := creatorAdmissionFrontendsForRelease("release-x")
	if len(resources) != 3 {
		t.Fatalf("frontends = %v, want three release-scoped frontends", resources)
	}
	for _, resource := range resources {
		if !strings.HasPrefix(resource.Name, "release-x-auth-operator-") {
			t.Fatalf("frontend %q is not release scoped", resource.Name)
		}
	}
	if got := creatorReleaseFullname("auth-operator-contained"); got != "auth-operator-contained" {
		t.Fatalf("fullname = %q, want release containing chart name unchanged", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
