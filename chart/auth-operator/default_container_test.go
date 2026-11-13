// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os/exec"
	"strings"
	"testing"
)

// Every Deployment's default-container annotation must name a container in the
// same pod, otherwise kubectl logs/exec warns and falls back.
func TestDeploymentDefaultContainerAnnotationMatchesContainer(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		skipOrFailMissingToolf(t, "helm not installed: %v", err)
	}
	assertDefaultContainers(t, decodeYAMLDocuments(t, []byte(helmTemplate(t))), "")
}

// A user-supplied podAnnotations entry for the same key must win without
// rendering a duplicate key (helm template output is parsed strictly here).
func TestDefaultContainerPodAnnotationsOverride(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		skipOrFailMissingToolf(t, "helm not installed: %v", err)
	}
	out := helmTemplate(t, "--set", `podAnnotations.kubectl\.kubernetes\.io/default-container=custom`, "--set", "podAnnotations.foo=bar")
	if n := strings.Count(out, "kubectl.kubernetes.io/default-container:"); n != 2 {
		t.Fatalf("want exactly one annotation per Deployment (2), got %d", n)
	}
	assertContains(t, out, "default-container: custom")
	assertNotContains(t, out, "default-container: manager")
	assertNotContains(t, out, "default-container: webhook")
	assertDefaultContainers(t, decodeYAMLDocuments(t, []byte(out)), "custom")
}

// The kustomize manifests carry the same annotation and must stay consistent.
func TestKustomizeDefaultContainerAnnotationMatchesContainer(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), findKustomize(t), "build", "../../config/default") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("kustomize build failed: %v", err)
	}
	assertDefaultContainers(t, decodeYAMLDocuments(t, out), "")
}

// assertDefaultContainers checks every Deployment; override, if set, is the
// annotation value expected instead of a real container name.
func assertDefaultContainers(t *testing.T, docs []map[string]any, override string) {
	t.Helper()
	checked := 0
	for _, doc := range docs {
		if doc["kind"] != "Deployment" {
			continue
		}
		name, _ := nestedValue(doc, "metadata", "name").(string)
		podTemplate, _ := nestedValue(doc, "spec", "template").(map[string]any)
		want, _ := nestedValue(podTemplate, "metadata", "annotations", "kubectl.kubernetes.io/default-container").(string)
		if want == "" {
			t.Errorf("deployment %s: missing default-container annotation", name)
			continue
		}
		checked++
		if override != "" {
			if want != override {
				t.Errorf("deployment %s: default-container = %q, want %q", name, want, override)
			}
			continue
		}
		containers, _ := nestedValue(podTemplate, "spec", "containers").([]any)
		found := false
		for _, c := range containers {
			if m, ok := c.(map[string]any); ok && m["name"] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("deployment %s: default-container %q matches no container", name, want)
		}
	}
	if checked == 0 {
		t.Fatal("no Deployments checked")
	}
}

func nestedValue(m map[string]any, path ...string) any {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}
