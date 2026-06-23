// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	impersonationModeGeneric     = "generic"
	impersonationModeNone        = "none"
	impersonationModeScoped      = "scoped"
	impersonationModeClusterWide = "clusterwide"
)

type roleObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

func main() {
	impersonationMode := flag.String("impersonation", "generic", "impersonation mode to verify: generic, none, scoped, clusterwide")
	expectedServiceAccount := flag.String("serviceaccount", "", "expected ServiceAccount resourceName for scoped impersonation mode")
	flag.Parse()

	if flag.NArg() < 1 {
		exitf("usage: go run hack/verify-rendered-rbac.go [--impersonation generic|none|scoped|clusterwide] [--serviceaccount name] <rendered-yaml>...")
	}

	for _, path := range flag.Args() {
		if err := verifyFile(path, *impersonationMode, *expectedServiceAccount); err != nil {
			exitf("%s: %v", path, err)
		}
	}
}

func verifyFile(path, impersonationMode, expectedServiceAccount string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	roles := make([]roleObject, 0)
	decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var role roleObject
		if err := decoder.Decode(&role); err != nil {
			if errors.Is(err, io.EOF) {
				return verifyImpersonationMode(roles, impersonationMode, expectedServiceAccount)
			}
			return fmt.Errorf("decode YAML document: %w", err)
		}
		if role.Kind != "ClusterRole" && role.Kind != "Role" {
			continue
		}
		roles = append(roles, role)
		if err := verifyRole(role); err != nil {
			return err
		}
	}
}

func verifyRole(role roleObject) error {
	for _, rule := range role.Rules {
		if isAdmissionregistrationWrite(rule) && len(rule.ResourceNames) == 0 {
			return fmt.Errorf("%s %q grants admissionregistration write verbs without resourceNames", role.Kind, role.Metadata.Name)
		}
		if strings.HasSuffix(role.Metadata.Name, "manager-role") && hasAny(rule.Verbs, "patch", "update") {
			if hasAny(rule.Resources, "secrets") {
				return fmt.Errorf("%s %q grants manager secret mutation", role.Kind, role.Metadata.Name)
			}
			if hasAny(rule.APIGroups, "admissionregistration.k8s.io") {
				return fmt.Errorf("%s %q grants manager admissionregistration mutation", role.Kind, role.Metadata.Name)
			}
		}
		if strings.HasSuffix(role.Metadata.Name, "manager-role") && hasAny(rule.Verbs, "update") &&
			hasAny(rule.Resources, "serviceaccounts", "clusterrolebindings", "rolebindings", "clusterroles", "roles") {
			return fmt.Errorf("%s %q grants update on SSA-managed resources %v", role.Kind, role.Metadata.Name, rule.Resources)
		}
	}

	if strings.HasSuffix(role.Metadata.Name, "leader-election-role") {
		for _, rule := range role.Rules {
			if hasAny(rule.Resources, "configmaps") {
				return fmt.Errorf("%s %q grants ConfigMap leader-election permissions", role.Kind, role.Metadata.Name)
			}
		}
	}

	if strings.HasSuffix(role.Metadata.Name, "webhook-server") {
		return verifyWebhookServerRole(role)
	}
	return nil
}

func verifyWebhookServerRole(role roleObject) error {
	var mutatingWrite, validatingWrite bool

	for _, rule := range role.Rules {
		if !hasAny(rule.APIGroups, "admissionregistration.k8s.io") || !hasAny(rule.Verbs, "patch", "update") {
			continue
		}
		if hasAny(rule.Resources, "mutatingwebhookconfigurations") {
			mutatingWrite = true
			if !hasNameContaining(rule.ResourceNames, "namespace-mutating-webhook-configuration") {
				return fmt.Errorf("clusterRole %q mutating webhook write rule is not scoped to the operator webhook", role.Metadata.Name)
			}
		}
		if hasAny(rule.Resources, "validatingwebhookconfigurations") {
			validatingWrite = true
			if !hasNameContaining(rule.ResourceNames, "namespace-validating-webhook-configuration") {
				return fmt.Errorf("clusterRole %q validating webhook write rule is missing namespace webhook resourceName", role.Metadata.Name)
			}
			if !hasNameContaining(rule.ResourceNames, "binder-validating-webhook-configuration") &&
				!hasNameContaining(rule.ResourceNames, "validating-webhook-configuration") {
				return fmt.Errorf("clusterRole %q validating webhook write rule is missing binder webhook resourceName", role.Metadata.Name)
			}
		}
	}

	if !mutatingWrite {
		return fmt.Errorf("clusterRole %q has no name-scoped mutating webhook write rule", role.Metadata.Name)
	}
	if !validatingWrite {
		return fmt.Errorf("clusterRole %q has no name-scoped validating webhook write rule", role.Metadata.Name)
	}
	return nil
}

func verifyImpersonationMode(roles []roleObject, mode, expectedServiceAccount string) error {
	switch mode {
	case impersonationModeGeneric:
		return nil
	case impersonationModeNone, impersonationModeScoped, impersonationModeClusterWide:
	default:
		return fmt.Errorf("unsupported impersonation mode %q", mode)
	}

	var scopedRules, clusterWideRules int
	for _, role := range roles {
		for _, rule := range role.Rules {
			if !isServiceAccountImpersonate(rule) {
				continue
			}
			if err := verifyImpersonationRule(role, rule, mode, expectedServiceAccount); err != nil {
				return err
			}
			if role.Kind == "ClusterRole" {
				clusterWideRules++
			}
			if role.Kind == "Role" {
				scopedRules++
			}
		}
	}

	if mode == impersonationModeNone && (scopedRules > 0 || clusterWideRules > 0) {
		return fmt.Errorf("render contains serviceaccounts/impersonate grants")
	}
	if mode == impersonationModeScoped && scopedRules == 0 {
		return fmt.Errorf("scoped impersonation mode rendered no namespaced serviceaccounts/impersonate Role")
	}
	if mode == impersonationModeClusterWide && clusterWideRules == 0 {
		return fmt.Errorf("clusterwide impersonation mode rendered no ClusterRole serviceaccounts/impersonate rule")
	}
	return nil
}

func verifyImpersonationRule(role roleObject, rule policyRule, mode, expectedServiceAccount string) error {
	switch role.Kind {
	case "ClusterRole":
		if mode != impersonationModeClusterWide {
			return fmt.Errorf("clusterRole %q grants serviceaccounts/impersonate outside clusterwide mode", role.Metadata.Name)
		}
		if len(rule.ResourceNames) != 0 {
			return fmt.Errorf("clusterRole %q clusterwide impersonation rule must not use resourceNames", role.Metadata.Name)
		}
	case "Role":
		if mode != impersonationModeScoped {
			return fmt.Errorf("role %q/%q grants serviceaccounts/impersonate outside scoped mode", role.Metadata.Namespace, role.Metadata.Name)
		}
		if len(rule.ResourceNames) == 0 {
			return fmt.Errorf("role %q/%q grants serviceaccounts/impersonate without resourceNames", role.Metadata.Namespace, role.Metadata.Name)
		}
		for _, resourceName := range rule.ResourceNames {
			if expectedServiceAccount != "" && resourceName != expectedServiceAccount {
				return fmt.Errorf("role %q/%q grants serviceaccounts/impersonate for unexpected resourceName %q", role.Metadata.Namespace, role.Metadata.Name, resourceName)
			}
		}
	}
	return nil
}

func isAdmissionregistrationWrite(rule policyRule) bool {
	return hasAny(rule.APIGroups, "admissionregistration.k8s.io") &&
		hasAny(rule.Resources, "mutatingwebhookconfigurations", "validatingwebhookconfigurations") &&
		hasAny(rule.Verbs, "patch", "update")
}

func isServiceAccountImpersonate(rule policyRule) bool {
	return hasAny(rule.APIGroups, "") &&
		hasAny(rule.Resources, "serviceaccounts") &&
		hasAny(rule.Verbs, "impersonate")
}

func hasAny(values []string, needles ...string) bool {
	for _, value := range values {
		for _, needle := range needles {
			if value == needle {
				return true
			}
		}
	}
	return false
}

func hasNameContaining(names []string, part string) bool {
	for _, name := range names {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
