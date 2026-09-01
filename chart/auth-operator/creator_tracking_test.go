// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	mapTemplatePath   = "templates/creator-tracking-map.yaml"
	mapV1APIFlag      = "admissionregistration.k8s.io/v1/MutatingAdmissionPolicy"
	mapV1beta1APIFlag = "admissionregistration.k8s.io/v1beta1/MutatingAdmissionPolicy"
)

func TestCreatorTrackingSchemaDefaults(t *testing.T) {
	raw, err := os.ReadFile("values.schema.json")
	if err != nil {
		t.Fatalf("read values schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse values schema: %v", err)
	}

	creator := nestedMap(t, schema, "properties", "creatorTracking")
	if got, ok := creator["additionalProperties"].(bool); !ok || got {
		t.Fatalf("creatorTracking additionalProperties = %v, want false", creator["additionalProperties"])
	}
	if _, required := creator["required"]; required {
		t.Fatal("creatorTracking must accept a partial enabled=false map")
	}
	properties := schemaObject(t, creator["properties"], "creatorTracking.properties")
	enabled := schemaObject(t, properties["enabled"], "creatorTracking.enabled")
	if got, ok := enabled["default"].(bool); !ok || got {
		t.Fatalf("creatorTracking.enabled default = %v, want false", enabled["default"])
	}
	assertSchemaString(t, properties, "mode", "protect", []any{"create-only", "protect", "contributors"})
	assertSchemaString(t, properties, "map", "auto", []any{"auto", "enabled", "disabled"})

	resources := schemaObject(t, properties["resources"], "creatorTracking.resources")
	if got, ok := resources["uniqueItems"].(bool); !ok || !got {
		t.Fatalf("creatorTracking.resources uniqueItems = %v, want true", resources["uniqueItems"])
	}
	item := schemaObject(t, resources["items"], "creatorTracking.resources.items")
	if got, ok := item["additionalProperties"].(bool); !ok || got {
		t.Fatalf("resource rule additionalProperties = %v, want false", item["additionalProperties"])
	}
	if got, want := item["required"], []any{"apiGroups", "apiVersions", "resources"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resource rule required = %v, want %v", got, want)
	}
	itemProperties := schemaObject(t, item["properties"], "creatorTracking.resources.items.properties")
	apiGroupItems := schemaObject(t,
		schemaObject(t, itemProperties["apiGroups"], "apiGroups")["items"], "apiGroups.items")
	if _, constrained := apiGroupItems["minLength"]; constrained {
		t.Fatal("apiGroups items must allow the empty core API group")
	}
	apiVersionItems := schemaObject(t,
		schemaObject(t, itemProperties["apiVersions"], "apiVersions")["items"], "apiVersions.items")
	if got := apiVersionItems["minLength"]; got != float64(1) {
		t.Fatalf("apiVersions item minLength = %v, want 1", got)
	}
	resourceItems := schemaObject(t,
		schemaObject(t, itemProperties["resources"], "resources")["items"], "resources.items")
	if got := resourceItems["pattern"]; got != "^[^/]+$" {
		t.Fatalf("resources item pattern = %v, want parent resources only", got)
	}
}

func TestCreatorTrackingMAPRendering(t *testing.T) {
	requireHelm(t)

	t.Run("disabled by default", func(t *testing.T) {
		assertCreatorTrackingNotRendered(t, "--api-versions", mapV1APIFlag)
	})
	t.Run("auto without a served API", func(t *testing.T) {
		assertCreatorTrackingNotRendered(t, "--set", "creatorTracking.enabled=true")
	})
	t.Run("auto selects v1", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true")
		assertProtectDocuments(t, docs, "admissionregistration.k8s.io/v1")
	})
	t.Run("auto selects v1beta1", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1beta1APIFlag,
			"--set", "creatorTracking.enabled=true")
		assertProtectDocuments(t, docs, "admissionregistration.k8s.io/v1beta1")
	})
	t.Run("auto prefers v1", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1beta1APIFlag,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true")
		assertProtectDocuments(t, docs, "admissionregistration.k8s.io/v1")
	})
	t.Run("enabled forces v1", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.map=enabled")
		assertProtectDocuments(t, docs, "admissionregistration.k8s.io/v1")
	})
	t.Run("map disabled", func(t *testing.T) {
		assertCreatorTrackingNotRendered(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.map=disabled")
	})
	t.Run("feature disabled", func(t *testing.T) {
		assertCreatorTrackingNotRendered(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=false")
	})
	t.Run("create-only", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.mode=create-only")
		assertCreatorTrackingDocumentCount(t, docs)
		creator := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-creator-tracking")
		assertRuleOperations(t, creator, []any{"CREATE"})
		assertParentResourceCondition(t, creator)
		if expression := mutationExpression(t, creator); strings.Contains(expression, "oldObject") {
			t.Fatalf("create-only creator mutation contains UPDATE restore logic: %s", expression)
		}
		contributor := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
		assertRuleOperations(t, contributor, []any{"UPDATE"})
		assertContributorScrub(t, contributor)
	})
	t.Run("protect", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true")
		assertProtectDocuments(t, docs, "admissionregistration.k8s.io/v1")
	})
	t.Run("contributors", func(t *testing.T) {
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.mode=contributors")
		assertCreatorTrackingDocumentCount(t, docs)
		creator := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-creator-tracking")
		assertRuleOperations(t, creator, []any{"CREATE", "UPDATE"})
		assertParentResourceCondition(t, creator)
		contributor := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
		assertRuleOperations(t, contributor, []any{"UPDATE"})
		assertContributorTracking(t, contributor)
		assertBinding(t,
			selectCreatorDocument(t, docs, "MutatingAdmissionPolicyBinding", "auth-operator-creator-tracking"),
			"auth-operator-creator-tracking")
		assertBinding(t,
			selectCreatorDocument(t, docs, "MutatingAdmissionPolicyBinding", "auth-operator-contributor-tracking"),
			"auth-operator-contributor-tracking")
	})
	t.Run("custom resource rules", func(t *testing.T) {
		const custom = `creatorTracking.resources=[{"apiGroups":["apps"],"apiVersions":["v1","v1beta1"],"resources":["deployments","statefulsets"]}]`
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.mode=contributors",
			"--set-json", custom)
		creatorWant := []any{map[string]any{
			"apiGroups": []any{"apps"}, "apiVersions": []any{"v1", "v1beta1"},
			"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"deployments", "statefulsets"},
		}}
		contributorWant := []any{map[string]any{
			"apiGroups": []any{"apps"}, "apiVersions": []any{"v1", "v1beta1"},
			"operations": []any{"UPDATE"}, "resources": []any{"deployments", "statefulsets"},
		}}
		creator := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-creator-tracking")
		contributor := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
		if got := policyResourceRules(t, creator); !reflect.DeepEqual(got, creatorWant) {
			t.Fatalf("custom creator rules = %#v, want %#v", got, creatorWant)
		}
		if got := policyResourceRules(t, contributor); !reflect.DeepEqual(got, contributorWant) {
			t.Fatalf("custom contributor rules = %#v, want %#v", got, contributorWant)
		}
	})
	t.Run("excluded usernames are CEL-safe", func(t *testing.T) {
		excluded := []string{"plain-user", `quote"and\backslash`}
		rawExcluded, err := json.Marshal(excluded)
		if err != nil {
			t.Fatalf("marshal excluded usernames: %v", err)
		}
		docs := renderCreatorTracking(t,
			"--api-versions", mapV1APIFlag,
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.mode=contributors",
			"--set-json", "creatorTracking.excludedUsernames="+string(rawExcluded))
		for _, name := range []string{"auth-operator-creator-tracking", "auth-operator-contributor-tracking"} {
			policy := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", name)
			assertParentResourceCondition(t, policy)
			if expression := policyVariable(t, policy, "isExcluded"); !strings.Contains(expression, string(rawExcluded)) {
				t.Fatalf("%s exclusion expression does not contain %s", name, rawExcluded)
			}
		}
	})
}

func TestCreatorTrackingAnnotationConstantsWired(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("templates", "creator-tracking-map.yaml"))
	if err != nil {
		t.Fatalf("read creator tracking template: %v", err)
	}
	template := string(raw)
	for _, key := range []string{
		authorizationv1alpha1.AnnotationKeyCreatedBy,
		authorizationv1alpha1.AnnotationKeyCreatedByGroups,
		authorizationv1alpha1.AnnotationKeyUpdatedBy,
	} {
		if !strings.Contains(template, key) {
			t.Fatalf("creator tracking template does not wire exported annotation constant %q", key)
		}
	}
}

func TestCreatorTrackingModeAPIMatrix(t *testing.T) {
	requireHelm(t)
	apiVersions := []struct {
		name       string
		flag       string
		apiVersion string
	}{
		{name: "v1", flag: mapV1APIFlag, apiVersion: "admissionregistration.k8s.io/v1"},
		{name: "v1beta1", flag: mapV1beta1APIFlag, apiVersion: "admissionregistration.k8s.io/v1beta1"},
	}
	modes := []struct {
		name              string
		creatorOperations []any
		contributors      bool
	}{
		{name: "create-only", creatorOperations: []any{"CREATE"}},
		{name: "protect", creatorOperations: []any{"CREATE", "UPDATE"}},
		{name: "contributors", creatorOperations: []any{"CREATE", "UPDATE"}, contributors: true},
	}

	for _, api := range apiVersions {
		for _, mode := range modes {
			t.Run(api.name+"/"+mode.name, func(t *testing.T) {
				docs := renderCreatorTracking(t,
					"--api-versions", api.flag,
					"--set", "creatorTracking.enabled=true",
					"--set", "creatorTracking.mode="+mode.name)
				assertCreatorTrackingDocumentCount(t, docs)
				creator := selectCreatorDocument(t, docs,
					"MutatingAdmissionPolicy", "auth-operator-creator-tracking")
				contributor := selectCreatorDocument(t, docs,
					"MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
				for _, document := range docs {
					if document["apiVersion"] != api.apiVersion {
						t.Fatalf("document API version = %v, want %s",
							document["apiVersion"], api.apiVersion)
					}
				}
				assertRuleOperations(t, creator, mode.creatorOperations)
				assertRuleOperations(t, contributor, []any{"UPDATE"})
				if mode.contributors {
					assertContributorTracking(t, contributor)
				} else {
					assertContributorScrub(t, contributor)
				}
			})
		}
	}
}

func TestCreatorTrackingSoleWildcardRule(t *testing.T) {
	requireHelm(t)
	const wildcard = `creatorTracking.resources=[{"apiGroups":["*"],"apiVersions":["*"],"resources":["*"]}]`
	docs := renderCreatorTracking(t,
		"--set", "creatorTracking.enabled=true",
		"--set", "creatorTracking.map=enabled",
		"--set-json", wildcard)
	wantCreator := []any{map[string]any{
		"apiGroups": []any{"*"}, "apiVersions": []any{"*"},
		"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"*"},
	}}
	wantContributor := []any{map[string]any{
		"apiGroups": []any{"*"}, "apiVersions": []any{"*"},
		"operations": []any{"UPDATE"}, "resources": []any{"*"},
	}}
	creator := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-creator-tracking")
	contributor := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
	if got := policyResourceRules(t, creator); !reflect.DeepEqual(got, wantCreator) {
		t.Fatalf("wildcard creator rules = %#v, want %#v", got, wantCreator)
	}
	if got := policyResourceRules(t, contributor); !reflect.DeepEqual(got, wantContributor) {
		t.Fatalf("wildcard contributor rules = %#v, want %#v", got, wantContributor)
	}
}

func TestCreatorTrackingInvalidValues(t *testing.T) {
	requireHelm(t)
	assertCreatorTrackingRenderFails(t, "value must be one of 'create-only', 'protect', 'contributors'",
		"--set", "creatorTracking.mode=invalid")
	assertCreatorTrackingRenderFails(t, "value must be one of 'auto', 'enabled', 'disabled'",
		"--set", "creatorTracking.map=invalid")
	assertCreatorTrackingRenderFails(t, "missing property 'apiVersions'",
		"--set-json", `creatorTracking.resources=[{"apiGroups":[""],"resources":["namespaces"]}]`)
	assertCreatorTrackingRenderFails(t, "additional properties 'extra' not allowed",
		"--set", "creatorTracking.extra=true")
	assertCreatorTrackingRenderFails(t, "minLength: got 0, want 1",
		"--set", "creatorTracking.enabled=true",
		"--set-json", `creatorTracking.resources=[{"apiGroups":[""],"apiVersions":[""],"resources":["namespaces"]}]`)
	assertCreatorTrackingRenderFails(t, "does not match pattern '^[^/]+$'",
		"--set", "creatorTracking.enabled=true",
		"--set-json", `creatorTracking.resources=[{"apiGroups":[""],"apiVersions":["v1"],"resources":["pods/status"]}]`)
	assertCreatorTrackingRenderFails(t, "maxItems: got 2, want 1",
		"--set", "creatorTracking.enabled=true",
		"--set-json", `creatorTracking.resources=[{"apiGroups":["*","apps"],"apiVersions":["v1"],"resources":["deployments"]}]`)
	assertCreatorTrackingRenderFails(t, "maxItems: got 2, want 1",
		"--set", "creatorTracking.enabled=true",
		"--set-json", `creatorTracking.resources=[{"apiGroups":["apps"],"apiVersions":["*","v1"],"resources":["deployments"]}]`)
	assertCreatorTrackingRenderFails(t, "maxItems: got 2, want 1",
		"--set", "creatorTracking.enabled=true",
		"--set-json", `creatorTracking.resources=[{"apiGroups":["apps"],"apiVersions":["v1"],"resources":["*","deployments"]}]`)
}

func TestCreatorTrackingLegacyValuesRenderDisabled(t *testing.T) {
	requireHelm(t)
	legacyValues := "testdata/values-before-creator-tracking.yaml"
	assertCreatorTrackingNotRendered(t,
		"--is-upgrade", "--api-versions", mapV1APIFlag,
		"--values", legacyValues, "--set-json", "creatorTracking=null")
	assertCreatorTrackingNotRendered(t,
		"--is-upgrade", "--api-versions", mapV1APIFlag,
		"--values", legacyValues, "--set-json", `creatorTracking={"enabled":false}`)
}

func TestCreatorTrackingLegacyValuesRenderActivation(t *testing.T) {
	requireHelm(t)
	chartCopy := filepath.Join(t.TempDir(), "auth-operator")
	if err := os.CopyFS(chartCopy, os.DirFS(".")); err != nil {
		t.Fatalf("copy chart: %v", err)
	}
	previousValues, err := os.ReadFile("testdata/values-before-creator-tracking.yaml")
	if err != nil {
		t.Fatalf("read previous values: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chartCopy, "values.yaml"), previousValues, 0o600); err != nil {
		t.Fatalf("replace copied values.yaml: %v", err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "forced v1",
			args: []string{
				"--set", "creatorTracking.enabled=true",
				"--set", "creatorTracking.map=enabled",
			},
		},
		{
			name: "auto v1",
			args: []string{
				"--api-versions", mapV1APIFlag,
				"--set", "creatorTracking.enabled=true",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			defaultDocs := renderCreatorTracking(t, testCase.args...)
			previousDocs := renderCreatorTrackingFromChart(t, chartCopy, testCase.args...)
			if !reflect.DeepEqual(previousDocs, defaultDocs) {
				t.Fatalf("fallback render differs from chart defaults\nFallback: %#v\nDefaults: %#v",
					previousDocs, defaultDocs)
			}
		})
	}
}

func TestCreatorTrackingExamplesMatchHelm(t *testing.T) {
	requireHelm(t)
	protect := renderCreatorTracking(t,
		"--api-versions", mapV1APIFlag,
		"--set", "creatorTracking.enabled=true")
	protectExample := readYAMLDocuments(t, "../../docs/examples/creator-tracking-map.yaml")
	assertPolicySpecsEqual(t,
		selectCreatorDocument(t, protect, "MutatingAdmissionPolicy", "auth-operator-creator-tracking"),
		selectCreatorDocument(t, protectExample, "MutatingAdmissionPolicy", "creator-tracking"))
	assertPolicySpecsEqual(t,
		selectCreatorDocument(t, protect, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking"),
		selectCreatorDocument(t, protectExample, "MutatingAdmissionPolicy", "contributor-tracking"))

	contributors := renderCreatorTracking(t,
		"--api-versions", mapV1APIFlag,
		"--set", "creatorTracking.enabled=true",
		"--set", "creatorTracking.mode=contributors")
	contributorsExample := readYAMLDocuments(t, "../../docs/examples/creator-tracking-map-contributors.yaml")
	assertPolicySpecsEqual(t,
		selectCreatorDocument(t, contributors, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking"),
		selectCreatorDocument(t, contributorsExample, "MutatingAdmissionPolicy", "contributor-tracking"))
}

func TestCreatorTrackingKustomizeNameReference(t *testing.T) {
	kustomize := findKustomize(t)
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	policyData, err := os.ReadFile(filepath.Join(repoRoot, "config/webhook/creator_tracking_map.yaml"))
	if err != nil {
		t.Fatalf("read creator tracking config: %v", err)
	}
	for _, apiVersion := range []string{"v1", "v1beta1"} {
		t.Run(apiVersion, func(t *testing.T) {
			overlay := t.TempDir()
			policies := string(policyData)
			if apiVersion == "v1beta1" {
				policies = strings.ReplaceAll(policies,
					"admissionregistration.k8s.io/v1\n", "admissionregistration.k8s.io/v1beta1\n")
			}
			writeTestFile(t, filepath.Join(overlay, "policies.yaml"), policies)
			kustomization := "apiVersion: kustomize.config.k8s.io/v1beta1\n" +
				"kind: Kustomization\nnamePrefix: test-\nresources:\n  - policies.yaml\n" +
				"configurations:\n  - " + filepath.ToSlash(filepath.Join(repoRoot, "config/webhook/kustomizeconfig.yaml")) + "\n"
			writeTestFile(t, filepath.Join(overlay, "kustomization.yaml"), kustomization)
			cmd := exec.CommandContext(t.Context(), kustomize, "build", // #nosec G204
				"--load-restrictor", "LoadRestrictionsNone", overlay)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("kustomize build failed: %v\n%s", err, output)
			}
			docs := decodeYAMLDocuments(t, output)
			for _, name := range []string{"creator-tracking", "contributor-tracking"} {
				prefixed := "test-" + name
				selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", prefixed)
				binding := selectCreatorDocument(t, docs, "MutatingAdmissionPolicyBinding", prefixed)
				if got := nestedObject(t, binding, "spec")["policyName"]; got != prefixed {
					t.Fatalf("binding %s policyName = %v, want %s", prefixed, got, prefixed)
				}
			}
		})
	}
}

func TestCreatorTrackingStandaloneConfigMatchesDocs(t *testing.T) {
	doc := readYAMLDocuments(t, "../../docs/examples/creator-tracking-map.yaml")
	config := readYAMLDocuments(t, "../../config/webhook/creator_tracking_map.yaml")
	if !reflect.DeepEqual(doc, config) {
		t.Fatal("config/webhook/creator_tracking_map.yaml differs semantically from the protect example")
	}
	kustomizationData, err := os.ReadFile("../../config/webhook/kustomization.yaml")
	if err != nil {
		t.Fatalf("read webhook kustomization: %v", err)
	}
	if !bytes.Contains(kustomizationData, []byte("creator_tracking_map.yaml")) {
		t.Fatal("webhook kustomization does not document the creator tracking opt-in")
	}
	var kustomization map[string]any
	if err := k8syaml.Unmarshal(kustomizationData, &kustomization); err != nil {
		t.Fatalf("parse webhook kustomization: %v", err)
	}
	resources, ok := kustomization["resources"].([]any)
	if !ok {
		t.Fatalf("webhook resources = %T, want array", kustomization["resources"])
	}
	for _, resource := range resources {
		if resource == "creator_tracking_map.yaml" {
			t.Fatal("creator_tracking_map.yaml must remain opt-in")
		}
	}
}

func assertProtectDocuments(t *testing.T, docs []map[string]any, apiVersion string) {
	t.Helper()
	assertCreatorTrackingDocumentCount(t, docs)
	creator := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-creator-tracking")
	if got := creator["apiVersion"]; got != apiVersion {
		t.Fatalf("creator policy apiVersion = %v, want %s", got, apiVersion)
	}
	assertPolicySettings(t, creator)
	assertStandardLabels(t, creator)
	assertRuleOperations(t, creator, []any{"CREATE", "UPDATE"})
	assertDefaultResourceRules(t, creator)
	assertParentResourceCondition(t, creator)
	expression := mutationExpression(t, creator)
	for _, required := range []string{
		"jsonpatch.escapeKey('t-caas.telekom.com/created-by')",
		"jsonpatch.escapeKey('t-caas.telekom.com/created-by-groups')",
		"jsonpatch.escapeKey('t-caas.telekom.com/updated-by')",
		"oldObject.metadata.annotations",
	} {
		if !strings.Contains(expression, required) {
			t.Fatalf("creator mutation does not contain %q", required)
		}
	}
	if groups := policyVariable(t, creator, "groups"); !strings.Contains(groups, "replace('%', '%25').replace(',', '%2C')") {
		t.Fatalf("groups variable does not encode percent before comma: %s", groups)
	}
	if guard := policyVariable(t, creator, "creatorStampFits"); !strings.Contains(guard, "<= 262144") {
		t.Fatalf("creator create guard = %s", guard)
	}
	if guard := policyVariable(t, creator, "creatorRestoreFits"); !strings.Contains(guard, "variables.oldCreatorBytes") || !strings.Contains(guard, "<= 262144") {
		t.Fatalf("creator restore guard = %s", guard)
	}
	if other := policyVariable(t, creator, "updateOtherAnnotationBytes"); !strings.Contains(other, "'t-caas.telekom.com/updated-by'") {
		t.Fatalf("creator restore does not defer updated-by ownership: %s", other)
	}

	creatorBinding := selectCreatorDocument(t, docs, "MutatingAdmissionPolicyBinding", "auth-operator-creator-tracking")
	if got := creatorBinding["apiVersion"]; got != apiVersion {
		t.Fatalf("creator binding apiVersion = %v, want %s", got, apiVersion)
	}
	assertBinding(t, creatorBinding, "auth-operator-creator-tracking")
	contributor := selectCreatorDocument(t, docs, "MutatingAdmissionPolicy", "auth-operator-contributor-tracking")
	assertContributorScrub(t, contributor)
	assertBinding(t,
		selectCreatorDocument(t, docs, "MutatingAdmissionPolicyBinding", "auth-operator-contributor-tracking"),
		"auth-operator-contributor-tracking")
}

func assertContributorTracking(t *testing.T, policy map[string]any) {
	t.Helper()
	assertPolicySettings(t, policy)
	assertStandardLabels(t, policy)
	assertParentResourceCondition(t, policy)
	if editor := policyVariable(t, policy, "editor"); !strings.Contains(editor, "replace('%', '%25').replace(',', '%2C')") {
		t.Fatalf("editor variable does not encode percent before comma: %s", editor)
	}
	if guard := policyVariable(t, policy, "candidateFits"); !strings.Contains(guard, "variables.previousCreatorBytes") || !strings.Contains(guard, "<= 262144") {
		t.Fatalf("contributor append guard = %s", guard)
	}
	if fit := policyVariable(t, policy, "oldListFits"); !strings.Contains(fit, "<= 262144") {
		t.Fatalf("contributor restore guard = %s", fit)
	}
	desired := policyVariable(t, policy, "desiredList")
	if !strings.Contains(desired, "!variables.oldListExists") || !strings.Contains(desired, "variables.candidateList") {
		t.Fatalf("first contributor is not initialized: %s", desired)
	}
	expression := mutationExpression(t, policy)
	if !strings.Contains(expression, "variables.desiredList") ||
		!strings.Contains(expression, "jsonpatch.escapeKey('t-caas.telekom.com/updated-by')") {
		t.Fatalf("contributor mutation = %s", expression)
	}
}

func assertContributorScrub(t *testing.T, policy map[string]any) {
	t.Helper()
	assertPolicySettings(t, policy)
	assertStandardLabels(t, policy)
	assertParentResourceCondition(t, policy)
	if _, exists := nestedObject(t, policy, "spec")["variables"]; exists {
		t.Fatal("contributor scrub policy unexpectedly has tracking variables")
	}
	expression := mutationExpression(t, policy)
	if !strings.Contains(expression, "op: 'remove'") ||
		!strings.Contains(expression, "jsonpatch.escapeKey('t-caas.telekom.com/updated-by')") {
		t.Fatalf("contributor scrub mutation = %s", expression)
	}
}

func assertDefaultResourceRules(t *testing.T, policy map[string]any) {
	t.Helper()
	want := []any{
		map[string]any{"apiGroups": []any{""}, "apiVersions": []any{"v1"},
			"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"namespaces", "serviceaccounts", "secrets"}},
		map[string]any{"apiGroups": []any{"rbac.authorization.k8s.io"}, "apiVersions": []any{"v1"},
			"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}},
		map[string]any{
			"apiGroups":   []any{"authorization.t-caas.telekom.com"},
			"apiVersions": []any{"v1alpha1"},
			"operations":  []any{"CREATE", "UPDATE"},
			"resources": []any{
				"roledefinitions", "binddefinitions", "rbacpolicies",
				"restrictedbinddefinitions", "restrictedroledefinitions", "webhookauthorizers",
			},
		},
	}
	if got := policyResourceRules(t, policy); !reflect.DeepEqual(got, want) {
		t.Fatalf("default resource rules = %#v, want %#v", got, want)
	}
}

func assertParentResourceCondition(t *testing.T, policy map[string]any) {
	t.Helper()
	conditions := nestedSlice(t, policy, "spec", "matchConditions")
	if len(conditions) != 1 {
		t.Fatalf("matchConditions length = %d, want 1", len(conditions))
	}
	condition := schemaObject(t, conditions[0], "matchConditions[0]")
	if condition["name"] != "parent-resource" || condition["expression"] != "request.?subResource.orValue('') == ''" {
		t.Fatalf("parent-resource condition = %#v", condition)
	}
}

func assertPolicySettings(t *testing.T, policy map[string]any) {
	t.Helper()
	spec := nestedObject(t, policy, "spec")
	if spec["failurePolicy"] != "Ignore" || spec["reinvocationPolicy"] != "IfNeeded" {
		t.Fatalf("policy settings = %#v", spec)
	}
}

func assertBinding(t *testing.T, binding map[string]any, policyName string) {
	t.Helper()
	assertStandardLabels(t, binding)
	if got := nestedObject(t, binding, "spec")["policyName"]; got != policyName {
		t.Fatalf("binding policyName = %v, want %s", got, policyName)
	}
}

func assertStandardLabels(t *testing.T, document map[string]any) {
	t.Helper()
	labels := nestedObject(t, document, "metadata", "labels")
	chart := readChartMetadata(t)
	chartName := chartString(t, chart, "name")
	want := map[string]string{
		"helm.sh/chart":                chartName + "-" + chartString(t, chart, "version"),
		"app.kubernetes.io/name":       chartName,
		"app.kubernetes.io/instance":   "auth-operator",
		"app.kubernetes.io/version":    chartString(t, chart, "appVersion"),
		"app.kubernetes.io/managed-by": "Helm",
	}
	for key, value := range want {
		if got := labels[key]; got != value {
			t.Fatalf("label %s = %v, want %s", key, got, value)
		}
	}
}

func readChartMetadata(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("Chart.yaml")
	if err != nil {
		t.Fatalf("read Chart.yaml: %v", err)
	}
	var chart map[string]any
	if err := k8syaml.Unmarshal(data, &chart); err != nil {
		t.Fatalf("parse Chart.yaml: %v", err)
	}
	return chart
}

func chartString(t *testing.T, chart map[string]any, key string) string {
	t.Helper()
	value, ok := chart[key].(string)
	if !ok || value == "" {
		t.Fatalf("Chart.yaml %s = %v, want nonempty string", key, chart[key])
	}
	return value
}

func assertRuleOperations(t *testing.T, policy map[string]any, want []any) {
	t.Helper()
	for index, raw := range policyResourceRules(t, policy) {
		rule := schemaObject(t, raw, "resourceRules")
		if got := rule["operations"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("resource rule %d operations = %v, want %v", index, got, want)
		}
	}
}

func policyResourceRules(t *testing.T, policy map[string]any) []any {
	t.Helper()
	return nestedSlice(t, policy, "spec", "matchConstraints", "resourceRules")
}

func policyVariable(t *testing.T, policy map[string]any, name string) string {
	t.Helper()
	for _, raw := range nestedSlice(t, policy, "spec", "variables") {
		variable := schemaObject(t, raw, "variables")
		if variable["name"] == name {
			expression, ok := variable["expression"].(string)
			if !ok {
				t.Fatalf("variable %s expression = %T, want string", name, variable["expression"])
			}
			return expression
		}
	}
	t.Fatalf("policy variable %s not found", name)
	return ""
}

func mutationExpression(t *testing.T, policy map[string]any) string {
	t.Helper()
	mutations := nestedSlice(t, policy, "spec", "mutations")
	if len(mutations) != 1 {
		t.Fatalf("mutations length = %d, want 1", len(mutations))
	}
	mutation := schemaObject(t, mutations[0], "mutations[0]")
	if mutation["patchType"] != "JSONPatch" {
		t.Fatalf("patchType = %v, want JSONPatch", mutation["patchType"])
	}
	jsonPatch := schemaObject(t, mutation["jsonPatch"], "jsonPatch")
	expression, ok := jsonPatch["expression"].(string)
	if !ok {
		t.Fatalf("JSONPatch expression = %T, want string", jsonPatch["expression"])
	}
	return expression
}

func renderCreatorTracking(t *testing.T, args ...string) []map[string]any {
	t.Helper()
	return renderCreatorTrackingFromChart(t, ".", args...)
}

func renderCreatorTrackingFromChart(t *testing.T, chart string, args ...string) []map[string]any {
	t.Helper()
	allArgs := append([]string{
		"template", "auth-operator", chart,
		"--namespace", "auth-operator-system",
		"--show-only", mapTemplatePath,
	}, args...)
	cmd := exec.CommandContext(t.Context(), "helm", allArgs...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, output)
	}
	return decodeYAMLDocuments(t, output)
}

func assertCreatorTrackingNotRendered(t *testing.T, args ...string) {
	t.Helper()
	allArgs := append([]string{"template", "auth-operator", ".", "--namespace", "auth-operator-system", "--show-only", mapTemplatePath}, args...)
	cmd := exec.CommandContext(t.Context(), "helm", allArgs...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err == nil {
		if strings.TrimSpace(string(output)) != "" {
			t.Fatalf("creator tracking rendered unexpectedly:\n%s", output)
		}
		return
	}
	// Helm 4 reports a gated show-only template as missing when it emits no documents.
	if !strings.Contains(string(output), "could not find template "+mapTemplatePath+" in chart") {
		t.Fatalf("helm template failed: %v\n%s", err, output)
	}
}

func assertCreatorTrackingRenderFails(t *testing.T, want string, args ...string) {
	t.Helper()
	templateArgs := append([]string{"--show-only", mapTemplatePath}, args...)
	assertHelmTemplateFails(t, want, templateArgs...)
}

func decodeYAMLDocuments(t *testing.T, output []byte) []map[string]any {
	t.Helper()
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var documents []map[string]any
	for {
		var document map[string]any
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				return documents
			}
			t.Fatalf("decode rendered YAML: %v", err)
		}
		if len(document) != 0 {
			documents = append(documents, document)
		}
	}
}

func readYAMLDocuments(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read YAML documents %s: %v", path, err)
	}
	return decodeYAMLDocuments(t, data)
}

func selectCreatorDocument(t *testing.T, documents []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, document := range documents {
		metadata := nestedObject(t, document, "metadata")
		if document["kind"] == kind && metadata["name"] == name {
			return document
		}
	}
	t.Fatalf("rendered document %s/%s not found", kind, name)
	return nil
}

func nestedObject(t *testing.T, object map[string]any, path ...string) map[string]any {
	t.Helper()
	current := object
	for _, key := range path {
		next, ok := current[key].(map[string]any)
		if !ok {
			t.Fatalf("path %q is %T, want object", strings.Join(path, "."), current[key])
		}
		current = next
	}
	return current
}

func nestedSlice(t *testing.T, object map[string]any, path ...string) []any {
	t.Helper()
	parent := nestedObject(t, object, path[:len(path)-1]...)
	value, ok := parent[path[len(path)-1]].([]any)
	if !ok {
		t.Fatalf("path %q is %T, want array", strings.Join(path, "."), parent[path[len(path)-1]])
	}
	return value
}

func schemaObject(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema path %s is %T, want object", path, value)
	}
	return object
}

func assertSchemaString(t *testing.T, properties map[string]any, name, defaultValue string, enum []any) {
	t.Helper()
	property := schemaObject(t, properties[name], "creatorTracking."+name)
	if property["default"] != defaultValue || !reflect.DeepEqual(property["enum"], enum) {
		t.Fatalf("creatorTracking.%s = %#v", name, property)
	}
}

func assertCreatorTrackingDocumentCount(t *testing.T, documents []map[string]any) {
	t.Helper()
	if len(documents) != 4 {
		t.Fatalf("rendered %d documents, want 4", len(documents))
	}
}

func assertPolicySpecsEqual(t *testing.T, helmPolicy, examplePolicy map[string]any) {
	t.Helper()
	if helmSpec, exampleSpec := nestedObject(t, helmPolicy, "spec"), nestedObject(t, examplePolicy, "spec"); !reflect.DeepEqual(helmSpec, exampleSpec) {
		t.Fatalf("standalone policy spec differs from Helm\nHelm: %#v\nExample: %#v", helmSpec, exampleSpec)
	}
}

func findKustomize(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "bin", "kustomize")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("kustomize not installed: %v", err)
	}
	return path
}

func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
