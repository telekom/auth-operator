//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

const (
	kyvernoNamespace        = "creator-tracking-kyverno-e2e"
	kyvernoPrePolicy        = "creator-tracking-kyverno-pre-policy"
	kyvernoLegacy           = "creator-tracking-kyverno-legacy"
	kyvernoLegacyRole       = "creator-tracking-kyverno-legacy-role"
	kyvernoSA               = "creator-tracking-kyverno-sa"
	reservedUser            = "e2e-user%,comma"
	reservedEditor          = "e2e-editor%,comma"
	reservedExcludedEditor  = "e2e-excluded%,comma"
	creatorGroup            = "e2e-creator-group"
	editorGroup             = "e2e-editor-group"
	creatorAnnotation       = "t-caas.telekom.com/created-by"
	creatorGroupsAnnotation = "t-caas.telekom.com/created-by-groups"
	updatedAnnotation       = "t-caas.telekom.com/updated-by"
	exclusionLabel          = "t-caas.telekom.com/creator-tracking=disabled"
)

type kyvernoUserInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type kyvernoWhoAmI struct {
	Status struct {
		UserInfo kyvernoUserInfo `json:"userInfo"`
	} `json:"status"`
}

func decodeKyvernoWhoAmI(data []byte) (kyvernoUserInfo, error) {
	var response kyvernoWhoAmI
	if err := json.Unmarshal(data, &response); err != nil {
		return kyvernoUserInfo{}, fmt.Errorf("decode SelfSubjectReview: %w", err)
	}
	return response.Status.UserInfo, nil
}

func kyvernoNestedValue(object map[string]interface{}, path ...string) string {
	var current interface{} = object
	for _, key := range path {
		if index, err := strconv.Atoi(key); err == nil {
			items, ok := current.([]interface{})
			if !ok || index < 0 || index >= len(items) || items[index] == nil {
				return ""
			}
			current = items[index]
			continue
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		next, found := m[key]
		if !found || next == nil {
			return ""
		}
		current = next
	}
	return fmt.Sprint(current)
}

func TestDecodeKyvernoWhoAmI(t *testing.T) {
	t.Parallel()
	identity, err := decodeKyvernoWhoAmI([]byte(`{"status":{"userInfo":{"username":"e2e-user%,comma","groups":["system:authenticated","e2e-creator-group"]}}}`))
	if err != nil {
		t.Fatalf("decode whoami response: %v", err)
	}
	if identity.Username != reservedUser {
		t.Fatalf("username = %q, want %q", identity.Username, reservedUser)
	}
	if strings.Join(identity.Groups, ",") != "system:authenticated,e2e-creator-group" {
		t.Fatalf("groups = %q", identity.Groups)
	}
}

func TestKyvernoNestedValue(t *testing.T) {
	t.Parallel()
	object := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{"present": "value", "nil": nil},
		},
		"items": []interface{}{map[string]interface{}{"name": "first"}},
	}
	for name, tc := range map[string]struct {
		path []string
		want string
	}{
		"present":            {path: []string{"metadata", "annotations", "present"}, want: "value"},
		"missing terminal":   {path: []string{"metadata", "annotations", "missing"}, want: ""},
		"missing parent":     {path: []string{"status", "ready"}, want: ""},
		"nil terminal":       {path: []string{"metadata", "annotations", "nil"}, want: ""},
		"indexed":            {path: []string{"items", "0", "name"}, want: "first"},
		"index out of range": {path: []string{"items", "1", "name"}, want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := kyvernoNestedValue(object, tc.path...); got != tc.want {
				t.Fatalf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

var _ = Describe("Creator Tracking Kyverno", Label("creator-tracking-kyverno"), Ordered, Serial, func() {
	run := func(ctx context.Context, args ...string) []byte {
		output, err := utils.Run(utils.CommandContext(ctx, args[0], args[1:]...)) // #nosec G204
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "command %q failed: %s", args, output)
		return output
	}
	runResult := func(ctx context.Context, args ...string) ([]byte, error) {
		return utils.Run(utils.CommandContext(ctx, args[0], args[1:]...)) // #nosec G204
	}
	apply := func(ctx context.Context, manifest string) {
		cmd := utils.CommandContext(ctx, "kubectl", "apply", "-f", "-") // #nosec G204
		cmd.Stdin = strings.NewReader(manifest)
		output, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "apply failed: %s", output)
	}
	applyAs := func(ctx context.Context, user, manifest string, groups ...string) {
		args := make([]string, 0, 6+2*len(groups))
		args = append(args, "kubectl", "--as", user)
		for _, group := range groups {
			args = append(args, "--as-group", group)
		}
		args = append(args, "apply", "-f", "-")
		cmd := utils.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
		cmd.Stdin = strings.NewReader(manifest)
		output, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "impersonated apply failed: %s", output)
	}
	get := func(ctx context.Context, args ...string) (map[string]interface{}, error) {
		commandArgs := append([]string{"get"}, args...)
		output, err := utils.Run(utils.CommandContext(ctx, "kubectl", commandArgs...)) // #nosec G204
		if err != nil {
			return nil, err
		}
		var object map[string]interface{}
		if err := json.Unmarshal(output, &object); err != nil {
			return nil, fmt.Errorf("decode kubectl JSON: %w", err)
		}
		return object, nil
	}
	value := kyvernoNestedValue
	mustGet := func(ctx context.Context, resource, name string) map[string]interface{} {
		object, err := get(ctx, resource, name, "-o", "json")
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return object
	}
	waitMutatingPolicyReady := func(ctx context.Context, name string) {
		EventuallyWithOffset(1, func() error {
			object, err := get(ctx, "mutatingpolicy", name, "-o", "json")
			if err != nil {
				return fmt.Errorf("get MutatingPolicy %s: %w", name, err)
			}
			status, _ := object["status"].(map[string]interface{})
			// Kyverno 1.19 reports the aggregate readiness under
			// status.conditionStatus.ready instead of exposing a conventional
			// Ready entry in status.conditions. Accept that authoritative
			// representation while retaining the condition-based check for
			// older releases.
			conditionStatus, _ := status["conditionStatus"].(map[string]interface{})
			if ready, ok := conditionStatus["ready"].(bool); ok && ready {
				return nil
			}
			conditions, _ := status["conditions"].([]interface{})
			for _, raw := range conditions {
				condition, _ := raw.(map[string]interface{})
				if fmt.Sprint(condition["type"]) == "Ready" && fmt.Sprint(condition["status"]) == "True" {
					return nil
				}
			}
			statusJSON, err := json.Marshal(object["status"])
			if err != nil {
				return fmt.Errorf("encode MutatingPolicy %s status: %w", name, err)
			}
			return fmt.Errorf("MutatingPolicy %s is not ready: %s", name, statusJSON)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	}
	annotations := func(ctx context.Context, resource, name string, namespace ...string) map[string]string {
		args := []string{resource, name, "-o", "json"}
		if len(namespace) > 0 {
			args = append(args, "-n", namespace[0])
		}
		object, err := get(ctx, args...)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		result := map[string]string{}
		metadata, _ := object["metadata"].(map[string]interface{})
		raw, _ := metadata["annotations"].(map[string]interface{})
		for key, item := range raw {
			result[key] = fmt.Sprint(item)
		}
		return result
	}
	whoami := func(ctx context.Context, user string, groups ...string) kyvernoUserInfo {
		args := make([]string, 0, 7+2*len(groups))
		args = append(args, "kubectl", "auth", "whoami", "--as", user)
		for _, group := range groups {
			args = append(args, "--as-group", group)
		}
		args = append(args, "-o", "json")
		identity, err := decodeKyvernoWhoAmI(run(ctx, args...))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		ExpectWithOffset(1, identity.Username).To(Equal(user))
		expected := append([]string{"system:authenticated"}, groups...)
		sort.Strings(expected)
		actual := append([]string(nil), identity.Groups...)
		sort.Strings(actual)
		ExpectWithOffset(1, actual).To(Equal(expected))
		return identity
	}
	impersonated := func(user string, groups ...string) []string {
		args := make([]string, 0, 3+2*len(groups))
		args = append(args, "kubectl", "--as", user)
		for _, group := range groups {
			args = append(args, "--as-group", group)
		}
		return args
	}
	waitCreatorTrackingInactive := func(ctx context.Context, probeName string) {
		// API-server admission can briefly outlive deletion of policy and
		// binding objects. Require an unstamped server-side dry run before
		// creating an object that is meant to predate the next policy.
		EventuallyWithOffset(1, func() (bool, error) {
			args := append(impersonated(reservedUser, creatorGroup), "create", "namespace", probeName, "--dry-run=server", "-o", "json")
			output, err := runResult(ctx, args...)
			if err != nil {
				return false, fmt.Errorf("probe creator tracking deactivation: %w", err)
			}
			var object map[string]interface{}
			if err := json.Unmarshal(output, &object); err != nil {
				return false, fmt.Errorf("decode creator tracking deactivation probe: %w", err)
			}
			return value(object, "metadata", "annotations", creatorAnnotation) == "", nil
		}, time.Minute, time.Second).Should(BeTrue())
	}
	createNamespace := func(ctx context.Context, user, name string, groups ...string) {
		run(ctx, append(impersonated(user, groups...), "create", "namespace", name)...)
	}
	createWithAnnotation := func(ctx context.Context, user, name, key, annotationValue string, groups ...string) ([]byte, error) {
		manifest := fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  annotations:\n    %s: %q\n", name, key, annotationValue)
		args := append(impersonated(user, groups...), "create", "-f", "-")
		cmd := utils.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
		cmd.Stdin = strings.NewReader(manifest)
		return utils.Run(cmd)
	}
	bytesString := func(size int) string {
		value := strings.Repeat("界", size/len([]byte("界")))
		return value + strings.Repeat("x", size-len([]byte(value)))
	}
	encodeGroups := func(groups []string) string {
		encoded := make([]string, len(groups))
		for i, group := range groups {
			encoded[i] = strings.NewReplacer("%", "%25", ",", "%2C").Replace(group)
		}
		return strings.Join(encoded, ",")
	}
	waitAbsent := func(ctx context.Context, resource string, names ...string) {
		for _, name := range names {
			Eventually(func() error {
				output, err := runResult(ctx, "kubectl", "get", resource, name)
				if err == nil {
					return fmt.Errorf("%s/%s still exists", resource, name)
				}
				if !creatorIsAbsentError(output, err) {
					return fmt.Errorf("checking %s/%s: %w (%s)", resource, name, err, output)
				}
				return nil
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		}
	}
	deleteAndWait := func(ctx context.Context, resource string, names ...string) {
		args := append([]string{"kubectl", "delete", resource}, names...)
		args = append(args, "--ignore-not-found=true")
		output, err := utils.Run(utils.CommandContext(ctx, args[0], args[1:]...)) // #nosec G204
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "delete %s failed: %s", resource, output)
		waitAbsent(ctx, resource, names...)
	}
	waitAnnotation := func(ctx context.Context, resource, name, key, expected string, namespace ...string) {
		Eventually(func() string { return annotations(ctx, resource, name, namespace...)[key] }, 2*time.Minute, 2*time.Second).Should(Equal(expected))
	}

	BeforeAll(func(ctx SpecContext) {
		run(ctx, "kubectl", "api-resources", "--api-group=policies.kyverno.io")
		run(ctx, "kubectl", "api-resources", "--api-group=admissionregistration.k8s.io")
		whoami(ctx, reservedUser, creatorGroup)
		whoami(ctx, reservedEditor, editorGroup)
		whoami(ctx, reservedExcludedEditor, editorGroup)
		apply(ctx, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: creator-tracking-kyverno-e2e}
rules:
- apiGroups: [""]
  resources: [namespaces, serviceaccounts, secrets]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: [rbac.authorization.k8s.io]
  resources: [roles, rolebindings, clusterroles, clusterrolebindings]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: [authorization.t-caas.telekom.com]
  resources: [roledefinitions, binddefinitions, rbacpolicies, restrictedbinddefinitions, restrictedroledefinitions, webhookauthorizers]
  verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: creator-tracking-kyverno-e2e}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: creator-tracking-kyverno-e2e}
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: "e2e-user%,comma"
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: "e2e-editor%,comma"
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: "e2e-excluded%,comma"
`)
		run(ctx, "kubectl", "apply", "-f", "docs/examples/creator-tracking-kyverno-benign-policy.yaml")
	})

	AfterAll(func(ctx SpecContext) {
		// Delete source policies before generated resources. Kyverno owns the
		// generated resources and garbage collection can otherwise race with
		// the explicit waits below.
		deleteAndWait(ctx, "mutatingpolicy", "creator-tracking", "contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicy", "mpol-creator-tracking", "mpol-contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicybinding", "mpol-creator-tracking-binding", "mpol-contributor-tracking-binding")
		deleteAndWait(ctx, "clusterpolicy", "creator-tracking", "creator-tracking-benign-label")
		deleteAndWait(ctx, "binddefinition", "creator-tracking-kyverno-binding")
		deleteAndWait(ctx, "roledefinition", "creator-tracking-kyverno-role", kyvernoLegacyRole)
		deleteAndWait(ctx, "clusterrolebinding", "creator-tracking-kyverno-binding-creator-tracking-kyverno-reader-binding")
		deleteAndWait(ctx, "namespace", kyvernoNamespace, kyvernoPrePolicy, kyvernoLegacy,
			"creator-tracking-kyverno-legacy-new", "creator-tracking-kyverno-mutating",
			"creator-tracking-kyverno-benign", "creator-tracking-kyverno-byte-exact",
			"creator-tracking-kyverno-byte-overflow")
		deleteAndWait(ctx, "clusterrolebinding", "creator-tracking-kyverno-e2e")
		deleteAndWait(ctx, "clusterrole", "creator-tracking-kyverno-e2e", "creator-tracking-kyverno-reader", kyvernoLegacyRole)
		Expect(os.Getenv("CREATOR_TRACKING_KYVERNO_CLEANUP")).NotTo(Equal("skip"), "cleanup bypass is forbidden")
	})

	It("coexists with native MAP and records exact identity", func(ctx SpecContext) {
		for _, name := range []string{"auth-operator-creator-tracking", "auth-operator-contributor-tracking"} {
			Eventually(func() error { _, err := get(ctx, "mutatingadmissionpolicy", name, "-o", "json"); return err }, 2*time.Minute, 2*time.Second).Should(Succeed())
			Eventually(func() error {
				_, err := get(ctx, "mutatingadmissionpolicybinding", name, "-o", "json")
				return err
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		}
		waitAbsent(ctx, "mutatingadmissionpolicy", "mpol-creator-tracking", "mpol-contributor-tracking")
		waitAbsent(ctx, "mutatingadmissionpolicybinding", "mpol-creator-tracking-binding", "mpol-contributor-tracking-binding")
		run(ctx, "kubectl", "apply", "-f", "docs/examples/creator-tracking-kyverno-mutatingpolicy.yaml")
		for _, name := range []string{"creator-tracking", "contributor-tracking"} {
			waitMutatingPolicyReady(ctx, name)
			Eventually(func() error { _, err := get(ctx, "mutatingadmissionpolicy", "mpol-"+name, "-o", "json"); return err }, 2*time.Minute, 2*time.Second).Should(Succeed())
			Eventually(func() error {
				_, err := get(ctx, "mutatingadmissionpolicybinding", "mpol-"+name+"-binding", "-o", "json")
				return err
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		}
		identity := whoami(ctx, reservedUser, creatorGroup)
		createNamespace(ctx, reservedUser, kyvernoNamespace, creatorGroup)
		waitAnnotation(ctx, "namespace", kyvernoNamespace, creatorAnnotation, reservedUser)
		a := annotations(ctx, "namespace", kyvernoNamespace)
		Expect(a[creatorGroupsAnnotation]).To(Equal(encodeGroups(identity.Groups)))
		Expect(a[updatedAnnotation]).To(BeEmpty())
		dryRun := run(ctx, append(impersonated(reservedUser, creatorGroup), "create", "namespace", "creator-tracking-kyverno-dry-run", "--dry-run=server", "-o", "json")...)
		var dryObject map[string]interface{}
		Expect(json.Unmarshal(dryRun, &dryObject)).To(Succeed())
		Expect(value(dryObject, "metadata", "annotations", creatorAnnotation)).To(Equal(reservedUser))
		dryUpdate := run(ctx, append(impersonated(reservedEditor, editorGroup),
			"annotate", "namespace", kyvernoNamespace, creatorAnnotation+"=forged",
			"--overwrite", "--dry-run=server", "-o", "json")...)
		var dryUpdatedObject map[string]interface{}
		Expect(json.Unmarshal(dryUpdate, &dryUpdatedObject)).To(Succeed())
		Expect(value(dryUpdatedObject, "metadata", "annotations", creatorAnnotation)).To(Equal(reservedUser))
		object, err := get(ctx, "namespace", kyvernoNamespace, "-o", "json")
		Expect(err).NotTo(HaveOccurred())
		rv := value(object, "metadata", "resourceVersion")
		Consistently(func() string {
			object, err := get(ctx, "namespace", kyvernoNamespace, "-o", "json")
			if err != nil {
				return "error"
			}
			return value(object, "metadata", "resourceVersion")
		}, 5*time.Second, time.Second).Should(Equal(rv))
		benign := "creator-tracking-kyverno-benign"
		createNamespace(ctx, reservedUser, benign, creatorGroup)
		Eventually(func() string {
			return value(mustGet(ctx, "namespace", benign), "metadata", "labels", "kyverno-touched")
		}, time.Minute, time.Second).Should(Equal("true"))
		deleteAndWait(ctx, "mutatingpolicy", "creator-tracking", "contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicy", "mpol-creator-tracking", "mpol-contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicybinding", "mpol-creator-tracking-binding", "mpol-contributor-tracking-binding")
	})

	It("uses isolated Kyverno MAPs after native disablement", func(ctx SpecContext) {
		release, namespace := os.Getenv("AUTH_OPERATOR_HELM_RELEASE"), os.Getenv("AUTH_OPERATOR_HELM_NAMESPACE")
		if release == "" {
			release = "auth-operator"
		}
		if namespace == "" {
			namespace = "auth-operator-system"
		}
		run(ctx, "helm", "upgrade", release, "chart/auth-operator", "-n", namespace, "--reuse-values", "--set", "creatorTracking.enabled=false", "--wait", "--timeout", "5m")
		waitAbsent(ctx, "mutatingadmissionpolicy", "auth-operator-creator-tracking", "auth-operator-contributor-tracking")
		waitAbsent(ctx, "mutatingadmissionpolicybinding", "auth-operator-creator-tracking", "auth-operator-contributor-tracking")
		deleteAndWait(ctx, "clusterpolicy", "creator-tracking-benign-label")
		deleteAndWait(ctx, "namespace", kyvernoPrePolicy)
		waitCreatorTrackingInactive(ctx, "creator-tracking-kyverno-native-disabled")
		createNamespace(ctx, reservedUser, kyvernoPrePolicy, creatorGroup)
		run(ctx, "kubectl", "apply", "-f", "docs/examples/creator-tracking-kyverno-mutatingpolicy.yaml")
		for _, name := range []string{"creator-tracking", "contributor-tracking"} {
			waitMutatingPolicyReady(ctx, name)
			Eventually(func() string {
				return value(mustGet(ctx, "mutatingadmissionpolicy", "mpol-"+name), "apiVersion")
			}, 2*time.Minute, 2*time.Second).Should(Equal("admissionregistration.k8s.io/v1"))
			Eventually(func() string {
				return value(mustGet(ctx, "mutatingadmissionpolicybinding", "mpol-"+name+"-binding"), "spec", "policyName")
			}, 2*time.Minute, 2*time.Second).Should(Equal("mpol-" + name))
		}
		// Source readiness can precede API-server policy activation. A server-side
		// dry run proves the generated binding is active before the one-shot
		// pre-existing-object update below.
		Eventually(func() (string, error) {
			args := append(impersonated(reservedUser, creatorGroup), "create", "namespace", "creator-tracking-kyverno-activation", "--dry-run=server", "-o", "json")
			output, err := runResult(ctx, args...)
			if err != nil {
				return "", fmt.Errorf("probe generated Kyverno MAP: %w", err)
			}
			var object map[string]interface{}
			if err := json.Unmarshal(output, &object); err != nil {
				return "", fmt.Errorf("decode generated Kyverno MAP probe: %w", err)
			}
			return value(object, "metadata", "annotations", creatorAnnotation), nil
		}, time.Minute, time.Second).Should(Equal(reservedUser))
		run(ctx, "kubectl", "annotate", "namespace", kyvernoPrePolicy, creatorAnnotation+"=forged", creatorGroupsAnnotation+"=forged", "--overwrite")
		Eventually(func() map[string]string { return annotations(ctx, "namespace", kyvernoPrePolicy) }, time.Minute, time.Second).ShouldNot(HaveKey(creatorAnnotation))
		Eventually(func() map[string]string { return annotations(ctx, "namespace", kyvernoPrePolicy) }, time.Minute, time.Second).ShouldNot(HaveKey(creatorGroupsAnnotation))
		createNamespace(ctx, reservedUser, "creator-tracking-kyverno-mutating", creatorGroup)
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", creatorAnnotation, reservedUser)
		run(ctx, append(impersonated(reservedEditor, editorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-editor=seen", "--overwrite")...)
		Eventually(func() string {
			return annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[updatedAnnotation]
		}, time.Minute, time.Second).Should(Equal("e2e-editor%25%2Ccomma"))
		run(ctx, append(impersonated(reservedEditor, editorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-editor=again", "--overwrite")...)
		Consistently(func() string {
			return annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[updatedAnnotation]
		}, 5*time.Second, time.Second).Should(Equal("e2e-editor%25%2Ccomma"))
		// A contributor history is protected even when an UPDATE forges,
		// replaces, or removes the complete annotation value. This also
		// exercises the alreadyTracked path: the current editor is repeated,
		// but the exact old list must still be restored.
		oldContributors := annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[updatedAnnotation]
		run(ctx, append(impersonated(reservedEditor, editorGroup), "annotate", "namespace",
			"creator-tracking-kyverno-mutating", updatedAnnotation+"=forged%25%2Cother",
			"--overwrite")...)
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation, oldContributors)
		run(ctx, append(impersonated(reservedEditor, editorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation+"-", "--overwrite")...)
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation, oldContributors)
		run(ctx, append(impersonated(reservedUser, creatorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-excluded-touch=1", "--overwrite")...)
		contributors := "e2e-editor%25%2Ccomma,e2e-user%25%2Ccomma"
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation, contributors)
		run(ctx, append(impersonated(reservedUser, creatorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-repeated-touch=1", "--overwrite")...)
		Consistently(func() string {
			return annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[updatedAnnotation]
		}, 5*time.Second, time.Second).Should(Equal(contributors))
		run(ctx, "kubectl", "label", "namespace", "creator-tracking-kyverno-mutating", exclusionLabel, "--overwrite")
		excludedHistory := annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[updatedAnnotation]
		run(ctx, append(impersonated(reservedExcludedEditor, editorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-excluded-touch=1", "--overwrite")...)
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation, excludedHistory)
		run(ctx, append(impersonated(reservedUser, creatorGroup), "annotate", "namespace", "creator-tracking-kyverno-mutating", "kyverno-excluded-creator=1", "--overwrite")...)
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", updatedAnnotation, excludedHistory)
		original := annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")
		run(ctx, "kubectl", "annotate", "namespace", "creator-tracking-kyverno-mutating", creatorAnnotation+"=forged", "--overwrite")
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", creatorAnnotation, reservedUser)
		run(ctx, "kubectl", "annotate", "namespace", "creator-tracking-kyverno-mutating", creatorAnnotation+"=forged", "--overwrite")
		waitAnnotation(ctx, "namespace", "creator-tracking-kyverno-mutating", creatorAnnotation, reservedUser)
		Expect(annotations(ctx, "namespace", "creator-tracking-kyverno-mutating")[creatorGroupsAnnotation]).To(Equal(original[creatorGroupsAnnotation]))
		Expect(run(ctx, "kubectl", "auth", "can-i", "create", "mutatingadmissionpolicies",
			"--as", "system:serviceaccount:kyverno:kyverno-admission-controller")).To(ContainSubstring("yes"))
		identity := whoami(ctx, reservedUser, creatorGroup)
		creatorKey, groupsKey := creatorAnnotation, creatorGroupsAnnotation
		fixedBytes := len([]byte(creatorKey)) + len([]byte(reservedUser)) + len([]byte(groupsKey)) + len([]byte(encodeGroups(identity.Groups)))
		fillerKey := "e2e.filler"
		exactName := "creator-tracking-kyverno-byte-exact"
		output, err := createWithAnnotation(ctx, reservedUser, exactName, fillerKey, bytesString(262144-fixedBytes-len([]byte(fillerKey))), creatorGroup)
		Expect(err).NotTo(HaveOccurred(), "exact annotation budget create failed: %s", output)
		waitAnnotation(ctx, "namespace", exactName, creatorAnnotation, reservedUser)
		exactAnnotations := annotations(ctx, "namespace", exactName)
		Expect([]byte(exactAnnotations[fillerKey])).To(HaveLen(262144 - fixedBytes - len([]byte(fillerKey))))
		overflowName := "creator-tracking-kyverno-byte-overflow"
		// The object itself remains within the API annotation limit, but adding
		// the creator fields would exceed the policy budget. Ignore therefore
		// admits it without mutation; this is distinct from API rejection.
		output, err = createWithAnnotation(ctx, reservedUser, overflowName, fillerKey, bytesString(262143-len([]byte(fillerKey))), creatorGroup)
		Expect(err).NotTo(HaveOccurred(), "over-budget stamp should be admitted unchanged under Ignore: %s", output)
		Eventually(func() map[string]string { return annotations(ctx, "namespace", overflowName) }, time.Minute, time.Second).ShouldNot(HaveKey(creatorAnnotation))
		Expect([]byte(annotations(ctx, "namespace", overflowName)[fillerKey])).To(HaveLen(262143 - len([]byte(fillerKey))))
	})

	It("keeps legacy ClusterPolicy isolated and does not backfill", func(ctx SpecContext) {
		deleteAndWait(ctx, "mutatingpolicy", "creator-tracking", "contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicy", "mpol-creator-tracking", "mpol-contributor-tracking")
		deleteAndWait(ctx, "mutatingadmissionpolicybinding", "mpol-creator-tracking-binding", "mpol-contributor-tracking-binding")
		deleteAndWait(ctx, "namespace", kyvernoLegacy)
		waitCreatorTrackingInactive(ctx, "creator-tracking-kyverno-map-disabled")
		createNamespace(ctx, reservedUser, kyvernoLegacy, creatorGroup)
		Expect(annotations(ctx, "namespace", kyvernoLegacy)[creatorAnnotation]).To(BeEmpty())
		run(ctx, "kubectl", "apply", "-f", "docs/examples/creator-tracking-kyverno-clusterpolicy.yaml")
		// ClusterPolicy creation can complete before Kyverno's admission webhook
		// activates the generated rule. Prove activation with a server-side dry
		// run before creating the one-shot RoleDefinition below.
		Eventually(func() (string, error) {
			args := append(impersonated(reservedUser, creatorGroup), "create", "namespace", "creator-tracking-kyverno-legacy-activation", "--dry-run=server", "-o", "json")
			output, err := runResult(ctx, args...)
			if err != nil {
				return "", fmt.Errorf("probe legacy Kyverno ClusterPolicy: %w", err)
			}
			var object map[string]interface{}
			if err := json.Unmarshal(output, &object); err != nil {
				return "", fmt.Errorf("decode legacy Kyverno ClusterPolicy probe: %w", err)
			}
			return value(object, "metadata", "annotations", creatorAnnotation), nil
		}, time.Minute, time.Second).Should(Equal(reservedUser))
		applyAs(ctx, reservedUser, `apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: creator-tracking-kyverno-legacy-role
spec:
  targetRole: ClusterRole
  targetName: creator-tracking-kyverno-legacy-role
  scopeNamespaced: false
`, creatorGroup)
		waitAnnotation(ctx, "roledefinition", kyvernoLegacyRole, creatorAnnotation, reservedUser)
		// This is deliberately an UPDATE of an unstamped object after the
		// classic policy becomes active. The oldObject creator is absent while
		// the newObject is forged, exercising the legacy rule's limitation.
		run(ctx, "kubectl", "annotate", "namespace", kyvernoLegacy, creatorAnnotation+"=forged", "--overwrite")
		legacyValue := annotations(ctx, "namespace", kyvernoLegacy)[creatorAnnotation]
		Expect(legacyValue).To(Equal("forged"))
		run(ctx, "kubectl", "annotate", "namespace", kyvernoLegacy, "legacy-touch=1", "--overwrite")
		Consistently(func() string { return annotations(ctx, "namespace", kyvernoLegacy)[creatorAnnotation] }, 5*time.Second, time.Second).Should(Equal("forged"))
		newLegacy := "creator-tracking-kyverno-legacy-new"
		createNamespace(ctx, reservedUser, newLegacy, creatorGroup)
		waitAnnotation(ctx, "namespace", newLegacy, creatorAnnotation, reservedUser)
		Expect(annotations(ctx, "namespace", newLegacy)[updatedAnnotation]).To(BeEmpty())
		run(ctx, "kubectl", "annotate", "namespace", newLegacy, creatorAnnotation+"=forged", "--overwrite")
		waitAnnotation(ctx, "namespace", newLegacy, creatorAnnotation, reservedUser)
		deleteAndWait(ctx, "roledefinition", kyvernoLegacyRole)
		deleteAndWait(ctx, "clusterrole", kyvernoLegacyRole)
		deleteAndWait(ctx, "clusterpolicy", "creator-tracking")
		waitCreatorTrackingInactive(ctx, "creator-tracking-kyverno-legacy-disabled")
	})

	It("tracks operator-created service accounts after native restoration", func(ctx SpecContext) {
		release, namespace := os.Getenv("AUTH_OPERATOR_HELM_RELEASE"), os.Getenv("AUTH_OPERATOR_HELM_NAMESPACE")
		if release == "" {
			release = "auth-operator"
		}
		if namespace == "" {
			namespace = "auth-operator-system"
		}
		run(ctx, "helm", "upgrade", release, "chart/auth-operator", "-n", namespace, "--reuse-values", "--set", "creatorTracking.enabled=true", "--wait", "--timeout", "5m")
		for _, name := range []string{"auth-operator-creator-tracking", "auth-operator-contributor-tracking"} {
			Eventually(func() error {
				_, err := get(ctx, "mutatingadmissionpolicy", name, "-o", "json")
				return err
			}, 2*time.Minute, 2*time.Second).Should(Succeed(), "native MAP %s was not restored", name)
			Eventually(func() error {
				_, err := get(ctx, "mutatingadmissionpolicybinding", name, "-o", "json")
				return err
			}, 2*time.Minute, 2*time.Second).Should(Succeed(), "native MAP binding %s was not restored", name)
		}
		Eventually(func() (string, error) {
			args := append(impersonated(reservedUser, creatorGroup), "create", "namespace", "creator-tracking-kyverno-native-restored", "--dry-run=server", "-o", "json")
			output, err := runResult(ctx, args...)
			if err != nil {
				return "", fmt.Errorf("probe restored native MAP: %w", err)
			}
			var object map[string]interface{}
			if err := json.Unmarshal(output, &object); err != nil {
				return "", fmt.Errorf("decode restored native MAP probe: %w", err)
			}
			return value(object, "metadata", "annotations", creatorAnnotation), nil
		}, time.Minute, time.Second).Should(Equal(reservedUser))
		run(ctx, "kubectl", "apply", "-f", "docs/examples/creator-tracking-kyverno-benign-policy.yaml")
		apply(ctx, `apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata: {name: creator-tracking-kyverno-role}
spec:
  targetRole: ClusterRole
  targetName: creator-tracking-kyverno-reader
  scopeNamespaced: false
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata: {name: creator-tracking-kyverno-binding}
spec:
  targetName: creator-tracking-kyverno-binding
  subjects:
  - kind: ServiceAccount
    name: creator-tracking-kyverno-sa
    namespace: creator-tracking-kyverno-e2e
  clusterRoleBindings:
    clusterRoleRefs: [creator-tracking-kyverno-reader]
`)
		Eventually(func() (string, error) {
			output, err := runResult(ctx, "kubectl", "get", "binddefinition", "creator-tracking-kyverno-binding", "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			return strings.TrimSpace(string(output)), err
		}, 3*time.Minute, 2*time.Second).Should(Equal("True"))
		Eventually(func() error {
			_, err := get(ctx, "serviceaccount", kyvernoSA, "-n", kyvernoNamespace, "-o", "json")
			return err
		}, 3*time.Minute, 2*time.Second).Should(Succeed())
		generatedBinding := "creator-tracking-kyverno-binding-creator-tracking-kyverno-reader-binding"
		Eventually(func() error { _, err := get(ctx, "clusterrolebinding", generatedBinding, "-o", "json"); return err }, 3*time.Minute, 2*time.Second).Should(Succeed())
		binding := mustGet(ctx, "clusterrolebinding", generatedBinding)
		Expect(value(binding, "roleRef", "name")).To(Equal("creator-tracking-kyverno-reader"))
		Expect(value(binding, "subjects", "0", "kind")).To(Equal("ServiceAccount"))
		Expect(value(binding, "subjects", "0", "name")).To(Equal(kyvernoSA))
		Expect(value(binding, "subjects", "0", "namespace")).To(Equal(kyvernoNamespace))
		Expect(binding["subjects"]).To(HaveLen(1))
		role := mustGet(ctx, "clusterrole", "creator-tracking-kyverno-reader")
		foundNamespaceRule := false
		if rules, ok := role["rules"].([]interface{}); ok {
			for _, rawRule := range rules {
				rule, ok := rawRule.(map[string]interface{})
				if !ok || value(rule, "apiGroups", "0") != "" {
					continue
				}
				if resources, ok := rule["resources"].([]interface{}); ok {
					for _, resource := range resources {
						if resource == "namespaces" {
							foundNamespaceRule = true
						}
					}
				}
			}
		}
		Expect(foundNamespaceRule).To(BeTrue(), "generated ClusterRole lacks the relevant namespace rule")
		controllerServiceAccount := strings.TrimSpace(string(run(ctx, "kubectl", "get", "deployment",
			"-n", namespace, "-l", "control-plane=controller-manager",
			"-o", "jsonpath={.items[0].spec.template.spec.serviceAccountName}")))
		Expect(controllerServiceAccount).NotTo(BeEmpty())
		waitAnnotation(ctx, "serviceaccount", kyvernoSA, creatorAnnotation, "system:serviceaccount:"+namespace+":"+controllerServiceAccount, kyvernoNamespace)
		first := annotations(ctx, "serviceaccount", kyvernoSA, kyvernoNamespace)
		Consistently(func() map[string]string { return annotations(ctx, "serviceaccount", kyvernoSA, kyvernoNamespace) }, 5*time.Second, time.Second).Should(Equal(first))
		deleteAndWait(ctx, "binddefinition", "creator-tracking-kyverno-binding")
		waitAbsent(ctx, "clusterrolebinding", generatedBinding)
		Eventually(func() error {
			output, err := runResult(ctx, "kubectl", "get", "serviceaccount", kyvernoSA, "-n", kyvernoNamespace)
			if err == nil {
				return fmt.Errorf("serviceaccount/%s still exists: %s", kyvernoSA, output)
			}
			if !creatorIsAbsentError(output, err) {
				return fmt.Errorf("checking serviceaccount/%s: %w (%s)", kyvernoSA, err, output)
			}
			return nil
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})
})
