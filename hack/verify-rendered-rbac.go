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
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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

type renderedObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Rules []policyRule                   `json:"rules"`
	Spec  networkingv1.NetworkPolicySpec `json:"spec"`
}

type policyRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

type renderedRBAC struct {
	roles                  []roleObject
	mutatingWebhookNames   map[string]struct{}
	validatingWebhookNames map[string]struct{}
	networkPolicies        []renderedObject
}

func newRenderedRBAC() renderedRBAC {
	return renderedRBAC{
		roles:                  make([]roleObject, 0),
		mutatingWebhookNames:   make(map[string]struct{}),
		validatingWebhookNames: make(map[string]struct{}),
		networkPolicies:        make([]renderedObject, 0),
	}
}

func main() {
	impersonationMode := flag.String("impersonation", "generic", "impersonation mode to verify: generic, none, scoped, clusterwide")
	expectedServiceAccount := flag.String("serviceaccount", "", "expected ServiceAccount resourceName for scoped impersonation mode")
	requireBroadAPIServerEgress := flag.Bool("require-broad-apiserver-egress", false, "require every rendered NetworkPolicy to contain broad TCP 443/6443 egress")
	flag.Parse()

	if flag.NArg() < 1 {
		exitf("usage: go run hack/verify-rendered-rbac.go [--impersonation generic|none|scoped|clusterwide] [--serviceaccount name] <rendered-yaml>...")
	}

	for _, path := range flag.Args() {
		if err := verifyFile(path, *impersonationMode, *expectedServiceAccount, *requireBroadAPIServerEgress); err != nil {
			exitf("%s: %v", path, err)
		}
	}
}

func verifyFile(path, impersonationMode, expectedServiceAccount string, requireBroadAPIServerEgress bool) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	rendered := newRenderedRBAC()
	decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
	for {
		var object renderedObject
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				return verifyRenderedRBAC(rendered, impersonationMode, expectedServiceAccount, requireBroadAPIServerEgress)
			}
			return fmt.Errorf("decode YAML document: %w", err)
		}
		switch object.Kind {
		case "ClusterRole", "Role":
			rendered.roles = append(rendered.roles, roleObject{
				Kind:     object.Kind,
				Metadata: object.Metadata,
				Rules:    object.Rules,
			})
		case "MutatingWebhookConfiguration":
			rendered.mutatingWebhookNames[object.Metadata.Name] = struct{}{}
		case "ValidatingWebhookConfiguration":
			rendered.validatingWebhookNames[object.Metadata.Name] = struct{}{}
		case "NetworkPolicy":
			rendered.networkPolicies = append(rendered.networkPolicies, object)
		}
	}
}

func verifyRenderedRBAC(rendered renderedRBAC, impersonationMode, expectedServiceAccount string, requireBroadAPIServerEgress bool) error {
	for _, role := range rendered.roles {
		if err := verifyRole(role, rendered); err != nil {
			return err
		}
	}
	if requireBroadAPIServerEgress {
		if err := verifyBroadAPIServerEgress(rendered.networkPolicies); err != nil {
			return err
		}
	}
	return verifyImpersonationMode(rendered.roles, impersonationMode, expectedServiceAccount)
}

func verifyRole(role roleObject, rendered renderedRBAC) error {
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
		return verifyWebhookServerRole(role, rendered)
	}
	return nil
}

func verifyWebhookServerRole(role roleObject, rendered renderedRBAC) error {
	missingMutating := copyStringSet(rendered.mutatingWebhookNames)
	missingValidating := copyStringSet(rendered.validatingWebhookNames)

	for _, rule := range role.Rules {
		if !hasAny(rule.APIGroups, "admissionregistration.k8s.io") || !hasAny(rule.Verbs, "patch", "update") {
			continue
		}
		if hasAny(rule.Resources, "mutatingwebhookconfigurations") {
			if err := verifyWebhookWriteResourceNames(role, "mutating", rule.ResourceNames, rendered.mutatingWebhookNames, missingMutating); err != nil {
				return err
			}
		}
		if hasAny(rule.Resources, "validatingwebhookconfigurations") {
			if err := verifyWebhookWriteResourceNames(role, "validating", rule.ResourceNames, rendered.validatingWebhookNames, missingValidating); err != nil {
				return err
			}
		}
	}

	if len(missingMutating) > 0 {
		return fmt.Errorf("clusterRole %q has no name-scoped write rule for mutating webhook configurations: %s",
			role.Metadata.Name, strings.Join(sortedKeys(missingMutating), ", "))
	}
	if len(missingValidating) > 0 {
		return fmt.Errorf("clusterRole %q has no name-scoped write rule for validating webhook configurations: %s",
			role.Metadata.Name, strings.Join(sortedKeys(missingValidating), ", "))
	}
	return nil
}

func verifyWebhookWriteResourceNames(role roleObject, webhookKind string, resourceNames []string, rendered, missing map[string]struct{}) error {
	for _, resourceName := range resourceNames {
		if _, exists := rendered[resourceName]; !exists {
			return fmt.Errorf("clusterRole %q grants %s webhook write for unrendered webhook configuration %q",
				role.Metadata.Name, webhookKind, resourceName)
		}
		delete(missing, resourceName)
	}
	return nil
}

func copyStringSet(values map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func verifyBroadAPIServerEgress(networkPolicies []renderedObject) error {
	if len(networkPolicies) == 0 {
		return fmt.Errorf("render contains no NetworkPolicy objects")
	}
	for _, policy := range networkPolicies {
		if !hasBroadAPIServerEgressRule(policy.Spec.Egress) {
			return fmt.Errorf("NetworkPolicy %q has no broad TCP 443/6443 API-server egress rule", policy.Metadata.Name)
		}
	}
	return nil
}

func hasBroadAPIServerEgressRule(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, rule := range rules {
		if len(rule.To) != 0 {
			continue
		}
		if hasTCPPorts(rule.Ports, 443, 6443) {
			return true
		}
	}
	return false
}

func hasTCPPorts(ports []networkingv1.NetworkPolicyPort, expectedPorts ...int32) bool {
	missing := make(map[int32]struct{}, len(expectedPorts))
	for _, port := range expectedPorts {
		missing[port] = struct{}{}
	}
	for _, port := range ports {
		if port.Protocol != nil && *port.Protocol != corev1.ProtocolTCP {
			continue
		}
		if port.Port == nil || port.Port.Type != 0 {
			continue
		}
		delete(missing, port.Port.IntVal)
	}
	return len(missing) == 0
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

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
