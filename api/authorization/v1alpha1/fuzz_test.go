// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"testing"
)

const maxFuzzInputBytes = 64 * 1024

func skipLargeFuzzInput(t *testing.T, data []byte) {
	t.Helper()
	if len(data) > maxFuzzInputBytes {
		t.Skip("fuzz input is too large for smoke runs")
	}
}

func FuzzBindDefinitionSpecUnmarshal(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{}`,
		`{"targetName":"team-access","subjects":[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"team-a"}],"roleBindings":{"clusterRoleRefs":["view"],"namespace":"default"}}`,
		`{"targetName":"team-access","subjects":[{"kind":"ServiceAccount","name":"robot","namespace":"default"}],"roleBindings":[{"roleRefs":["editor"],"namespace":"default"}]}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		skipLargeFuzzInput(t, data)

		var spec BindDefinitionSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return
		}
		if _, err := json.Marshal(&spec); err != nil {
			t.Fatalf("marshal unmarshaled BindDefinitionSpec: %v", err)
		}
	})
}

func FuzzRoleDefinitionSpecValidation(f *testing.F) {
	for _, seed := range []string{
		`{"metadata":{"name":"team-reader"},"spec":{"targetRole":"ClusterRole","targetName":"team-reader","scopeNamespaced":false}}`,
		`{"metadata":{"name":"tenant-reader"},"spec":{"targetRole":"Role","targetName":"tenant-reader","targetNamespace":"default","scopeNamespaced":true}}`,
		`{"metadata":{"name":"bad-version"},"spec":{"targetRole":"ClusterRole","targetName":"bad-version","restrictedApis":[{"name":"apps","versions":[{"groupVersion":"apps/notv1","version":"notv1"}]}]}}`,
		`{"metadata":{"name":"aggregate"},"spec":{"targetRole":"ClusterRole","targetName":"aggregate","aggregateFrom":{"clusterRoleSelectors":[{"matchLabels":{"t-caas.telekom.com/rbac-fragment":"true","t-caas.telekom.com/aggregate-scope":"team"}}]}}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		skipLargeFuzzInput(t, data)

		var roleDefinition RoleDefinition
		if err := json.Unmarshal(data, &roleDefinition); err != nil {
			return
		}
		_ = validateRoleDefinitionSpec(&roleDefinition)
	})
}

func FuzzWebhookAuthorizerValidation(f *testing.F) {
	for _, seed := range []string{
		`{"metadata":{"name":"allow-pods"},"spec":{"resourceRules":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}],"allowedPrincipals":[{"user":"alice"}]}}`,
		`{"metadata":{"name":"deny-healthz"},"spec":{"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz"]}],"deniedPrincipals":[{"groups":["blocked"]}]}}`,
		`{"metadata":{"name":"selector"},"spec":{"namespaceSelector":{"matchLabels":{"environment":"prod"}},"resourceRules":[{"verbs":["list"],"apiGroups":["apps"],"resources":["deployments"]}],"allowedPrincipals":[{"namespace":"default"}]}}`,
		`{"metadata":{"name":"invalid-rule"},"spec":{"resourceRules":[{"apiGroups":[""],"resources":["pods"]}],"allowedPrincipals":[{"user":"alice"}],"deniedPrincipals":[{"user":"alice"}]}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		skipLargeFuzzInput(t, data)

		var webhookAuthorizer WebhookAuthorizer
		if err := json.Unmarshal(data, &webhookAuthorizer); err != nil {
			return
		}
		_, _ = validateWebhookAuthorizer(&webhookAuthorizer)
	})
}
