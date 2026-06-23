//go:build e2e

/*
Copyright © 2026 Deutsche Telekom AG.
*/

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("WebhookAuthorizer E2E", Ordered, Label("integration"), func() {
	const (
		waNamespace   = "auth-operator-wa-e2e"
		waRelease     = "auth-operator-wa"
		helmChartPath = "chart/auth-operator"
		deployTimeout = 3 * time.Minute
		pollingInt    = 3 * time.Second
		reconcileWait = 30 * time.Second
		testNSLabeled = "wa-e2e-labeled"
		testNSPlain   = "wa-e2e-plain"
	)

	BeforeAll(func() {
		setSuiteOutputDir("webhookauthorizer")

		By("Creating e2e namespaces")
		createNamespaceIfNotExists(waNamespace, nil)
		createNamespaceIfNotExists(testNSLabeled, map[string]string{
			"wa-e2e": "true",
			"env":    "production",
		})
		createNamespaceIfNotExists(testNSPlain, map[string]string{
			"wa-e2e": "true",
		})

		By("Installing auth-operator via Helm for WebhookAuthorizer E2E")
		cmd := utils.CommandContext(context.Background(), "kind", "load", "docker-image",
			projectImage, "--name", kindClusterName)
		_, _ = utils.Run(cmd)

		cmd = utils.CommandContext(context.Background(), "helm", "upgrade", "--install",
			waRelease, helmChartPath,
			"-n", waNamespace,
			"--set", "image.repository=auth-operator",
			"--set", "image.tag=e2e-test",
			"--set", "image.pullPolicy=Never",
			"--wait",
			"--timeout", deployTimeout.String(),
		)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Helm install failed: %s", string(output))
	})

	AfterAll(func() {
		By("Uninstalling auth-operator Helm release")
		cmd := utils.CommandContext(context.Background(), "helm", "uninstall", waRelease, "-n", waNamespace)
		_, _ = utils.Run(cmd)

		By("Cleaning up e2e namespaces")
		for _, ns := range []string{waNamespace, testNSLabeled, testNSPlain} {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "ns", ns, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		}
	})

	Context("Basic Allow/Deny", func() {
		const waBasicYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-basic
spec:
  allowedPrincipals:
    - user: e2e-allowed-user
  resourceRules:
    - verbs: ["get", "list"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating basic WebhookAuthorizer")
			applyYAML(waBasicYAML)
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-basic", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should show WebhookAuthorizer as created", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-basic", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to get WebhookAuthorizer")
			Expect(string(output)).To(ContainSubstring("wa-e2e-basic"))
		})
	})

	Context("Authorization Decisions", func() {
		const waDecisionYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-allow
spec:
  allowedPrincipals:
    - user: e2e-allowed-user
  resourceRules:
    - verbs: ["get", "list"]
      apiGroups: [""]
      resources: ["pods"]
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-deny
spec:
  allowedPrincipals:
    - user: e2e-denied-user
  deniedPrincipals:
    - user: e2e-denied-user
  resourceRules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["pods"]
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-group
spec:
  allowedPrincipals:
    - groups: ["oidc:wa-e2e-group"]
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["configmaps"]
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-serviceaccount
spec:
  allowedPrincipals:
    - user: e2e-sa-authorized
      namespace: wa-e2e-plain
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["services"]
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-ns-selector
spec:
  allowedPrincipals:
    - user: e2e-ns-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["secrets"]
  namespaceSelector:
    matchLabels:
      env: production
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-decisions-nonresource
spec:
  allowedPrincipals:
    - user: e2e-health-user
  nonResourceRules:
    - verbs: ["get"]
      nonResourceURLs: ["/healthz"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizers for live decision checks")
			applyYAML(waDecisionYAML)
			for _, name := range []string{
				"wa-e2e-decisions-allow",
				"wa-e2e-decisions-deny",
				"wa-e2e-decisions-group",
				"wa-e2e-decisions-serviceaccount",
				"wa-e2e-decisions-ns-selector",
				"wa-e2e-decisions-nonresource",
			} {
				waitForWebhookAuthorizerReady(name)
			}
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer",
				"wa-e2e-decisions-allow",
				"wa-e2e-decisions-deny",
				"wa-e2e-decisions-group",
				"wa-e2e-decisions-serviceaccount",
				"wa-e2e-decisions-ns-selector",
				"wa-e2e-decisions-nonresource",
				"--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should return expected decisions through the deployed /authorize endpoint", func() {
			serviceName := fmt.Sprintf("%s-webhook-service", waRelease)
			localPort, cleanup := startWebhookAuthorizerPortForward(waNamespace, serviceName)
			defer cleanup()

			cases := []struct {
				name           string
				sar            authzv1.SubjectAccessReview
				allowed        bool
				denied         bool
				reasonContains string
			}{
				{
					name:           "user allow",
					sar:            resourceSAR("e2e-allowed-user", nil, "get", "pods", testNSPlain),
					allowed:        true,
					denied:         false,
					reasonContains: "Access granted by WebhookAuthorizer wa-e2e-decisions-allow",
				},
				{
					name:           "explicit deny takes precedence within matching authorizer",
					sar:            resourceSAR("e2e-denied-user", nil, "delete", "pods", testNSPlain),
					allowed:        false,
					denied:         true,
					reasonContains: "Access denied by WebhookAuthorizer wa-e2e-decisions-deny",
				},
				{
					name:           "group principal allow",
					sar:            resourceSAR("e2e-group-user", []string{"oidc:wa-e2e-group"}, "get", "configmaps", testNSPlain),
					allowed:        true,
					denied:         false,
					reasonContains: "Access granted by WebhookAuthorizer wa-e2e-decisions-group",
				},
				{
					name: "service account principal allow",
					sar: resourceSAR(
						"system:serviceaccount:wa-e2e-plain:e2e-sa-authorized",
						nil,
						"get",
						"services",
						testNSPlain,
					),
					allowed:        true,
					denied:         false,
					reasonContains: "Access granted by WebhookAuthorizer wa-e2e-decisions-serviceaccount",
				},
				{
					name:           "namespace selector match",
					sar:            resourceSAR("e2e-ns-user", nil, "get", "secrets", testNSLabeled),
					allowed:        true,
					denied:         false,
					reasonContains: "Access granted by WebhookAuthorizer wa-e2e-decisions-ns-selector",
				},
				{
					name:           "namespace selector mismatch is no opinion",
					sar:            resourceSAR("e2e-ns-user", nil, "get", "secrets", testNSPlain),
					allowed:        false,
					denied:         false,
					reasonContains: "Access denied: no matching rules",
				},
				{
					name:           "non-resource allow",
					sar:            nonResourceSAR("e2e-health-user", nil, "get", "/healthz"),
					allowed:        true,
					denied:         false,
					reasonContains: "Access granted by WebhookAuthorizer wa-e2e-decisions-nonresource",
				},
				{
					name:           "unknown user is no opinion",
					sar:            resourceSAR("e2e-unknown-user", nil, "get", "pods", testNSPlain),
					allowed:        false,
					denied:         false,
					reasonContains: "Access denied: no matching rules",
				},
			}

			for _, tc := range cases {
				By("Checking decision: " + tc.name)
				Eventually(func() (authzv1.SubjectAccessReviewStatus, error) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					response, err := requestAuthorizer(ctx, localPort, tc.sar)
					return response.Status, err
				}, reconcileWait, pollingInt).Should(And(
					HaveField("Allowed", tc.allowed),
					HaveField("Denied", tc.denied),
					HaveField("Reason", ContainSubstring(tc.reasonContains)),
				))
			}
		})
	})

	Context("NamespaceSelector Filtering", func() {
		const waNSSelectorYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-ns-selector
spec:
  allowedPrincipals:
    - user: e2e-ns-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
  namespaceSelector:
    matchLabels:
      env: production
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer with namespace selector")
			applyYAML(waNSSelectorYAML)
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-ns-selector", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should show namespace-scoped WebhookAuthorizer", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-ns-selector", "-o", "jsonpath={.spec.namespaceSelector}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("production"))
		})
	})

	Context("Live Update", func() {
		const waLiveYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-live-update
spec:
  allowedPrincipals:
    - user: e2e-live-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer for live update test")
			applyYAML(waLiveYAML)
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-live-update", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should reflect resource changes", func() {
			By("Verifying initial state")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-live-update", "-o", "jsonpath={.spec.allowedPrincipals[0].user}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("e2e-live-user"))

			By("Updating the WebhookAuthorizer to change allowed user")
			patchJSON := `{"spec":{"allowedPrincipals":[{"user":"e2e-updated-user"}]}}`
			cmd = utils.CommandContext(context.Background(), "kubectl", "patch",
				"webhookauthorizer", "wa-e2e-live-update",
				"--type=merge", "-p", patchJSON)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Patch failed: %s", string(output))

			By("Verifying updated state")
			Eventually(func() string {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-live-update",
					"-o", "jsonpath={.spec.allowedPrincipals[0].user}")
				output, _ := utils.Run(cmd)
				return string(output)
			}, reconcileWait, pollingInt).Should(Equal("e2e-updated-user"))
		})
	})

	Context("Multiple WebhookAuthorizers", func() {
		const waMulti1YAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-multi-1
spec:
  allowedPrincipals:
    - user: e2e-multi-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`

		const waMulti2YAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-multi-2
spec:
  deniedPrincipals:
    - user: e2e-multi-user
  resourceRules:
    - verbs: ["delete"]
      apiGroups: [""]
      resources: ["pods"]
`

		BeforeAll(func() {
			By("Creating multiple WebhookAuthorizers")
			applyYAML(waMulti1YAML)
			applyYAML(waMulti2YAML)
		})

		AfterAll(func() {
			for _, name := range []string{"wa-e2e-multi-1", "wa-e2e-multi-2"} {
				cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
					"webhookauthorizer", name, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
		})

		It("should list both WebhookAuthorizers", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("wa-e2e-multi-1"))
			Expect(string(output)).To(ContainSubstring("wa-e2e-multi-2"))
		})
	})

	Context("Status Reporting", func() {
		const waStatusYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-status
spec:
  allowedPrincipals:
    - user: e2e-status-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["configmaps"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer for status check")
			applyYAML(waStatusYAML)
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-status", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should report status conditions", func() {
			// The controller (if running) should update conditions.
			// This test verifies the CRD supports the status subresource.
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-status", "-o", "json")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				var result map[string]interface{}
				if jsonErr := json.Unmarshal(output, &result); jsonErr != nil {
					return false
				}
				_, hasStatus := result["status"]
				return hasStatus
			}, reconcileWait, pollingInt).Should(BeTrue(), "Expected status field to be present")
		})
	})

	Context("Deletion Cleanup", func() {
		It("should cleanly delete a WebhookAuthorizer", func() {
			waDeleteYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-delete
spec:
  allowedPrincipals:
    - user: e2e-delete-user
  resourceRules:
    - verbs: ["get"]
      apiGroups: [""]
      resources: ["pods"]
`
			By("Creating WebhookAuthorizer to delete")
			applyYAML(waDeleteYAML)

			By("Verifying it exists")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-delete")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting the WebhookAuthorizer")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-delete", "--timeout=30s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Delete failed: %s", string(output))

			By("Verifying it's gone")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get",
					"webhookauthorizer", "wa-e2e-delete")
				_, err := utils.Run(cmd)
				return err != nil // Should error (NotFound)
			}, reconcileWait, pollingInt).Should(BeTrue())
		})
	})

	Context("NonResourceRules E2E", func() {
		const waNonResourceYAML = `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: wa-e2e-nonresource
spec:
  allowedPrincipals:
    - user: e2e-health-user
  nonResourceRules:
    - verbs: ["get"]
      nonResourceURLs: ["/healthz", "/readyz"]
`

		BeforeAll(func() {
			By("Creating WebhookAuthorizer with non-resource rules")
			applyYAML(waNonResourceYAML)
		})

		AfterAll(func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete",
				"webhookauthorizer", "wa-e2e-nonresource", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should have non-resource rules in spec", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get",
				"webhookauthorizer", "wa-e2e-nonresource",
				"-o", "jsonpath={.spec.nonResourceRules[0].nonResourceURLs}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("/healthz"))
		})
	})
})

func waitForWebhookAuthorizerReady(name string) {
	Eventually(func() string {
		cmd := utils.CommandContext(context.Background(), "kubectl", "get",
			"webhookauthorizer", name,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		output, err := utils.Run(cmd)
		if err != nil {
			return ""
		}
		return string(output)
	}, 30*time.Second, 3*time.Second).Should(Equal(statusTrue))
}

func resourceSAR(user string, groups []string, verb, resource, namespace string) authzv1.SubjectAccessReview {
	return authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: groups,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     "",
				Resource:  resource,
			},
		},
	}
}

func nonResourceSAR(user string, groups []string, verb, path string) authzv1.SubjectAccessReview {
	return authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: groups,
			NonResourceAttributes: &authzv1.NonResourceAttributes{
				Verb: verb,
				Path: path,
			},
		},
	}
}

func startWebhookAuthorizerPortForward(namespace, serviceName string) (int, func()) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	localPort := listener.Addr().(*net.TCPAddr).Port
	ExpectWithOffset(1, listener.Close()).To(Succeed())

	ctx, cancel := context.WithCancel(context.Background())
	cmd := utils.CommandContext(ctx, "kubectl", "port-forward",
		"--address", "127.0.0.1",
		"-n", namespace,
		fmt.Sprintf("svc/%s", serviceName),
		fmt.Sprintf("%d:9443", localPort))
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	ExpectWithOffset(1, cmd.Start()).To(Succeed())

	cleanup := func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}

	Eventually(func() error {
		dialer := net.Dialer{Timeout: time.Second}
		conn, dialErr := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if dialErr != nil {
			return dialErr
		}
		return conn.Close()
	}, 30*time.Second, 500*time.Millisecond).Should(Succeed())

	return localPort, cleanup
}

func requestAuthorizer(
	ctx context.Context,
	localPort int,
	sar authzv1.SubjectAccessReview,
) (authzv1.SubjectAccessReview, error) {
	body, err := json.Marshal(sar)
	if err != nil {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("marshal SubjectAccessReview: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- e2e port-forward to a self-signed webhook certificate.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("https://127.0.0.1:%d/authorize", localPort),
		bytes.NewReader(body),
	)
	if err != nil {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("build SubjectAccessReview request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("post SubjectAccessReview: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("read SubjectAccessReview response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("unexpected authorizer status %d: %s", resp.StatusCode, respBody)
	}

	var response authzv1.SubjectAccessReview
	if err := json.Unmarshal(respBody, &response); err != nil {
		return authzv1.SubjectAccessReview{}, fmt.Errorf("decode SubjectAccessReview response: %w", err)
	}
	return response, nil
}
