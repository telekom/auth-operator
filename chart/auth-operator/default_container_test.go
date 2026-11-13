// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"os/exec"
	"testing"
)

// Every Deployment's default-container annotation must name a container in the
// same pod, otherwise kubectl logs/exec warns and falls back.
func TestDeploymentDefaultContainerAnnotationMatchesContainer(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	checked := 0
	for _, doc := range decodeYAMLDocuments(t, []byte(helmTemplate(t))) {
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
		checked++
	}
	if checked == 0 {
		t.Fatal("no Deployments rendered")
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
