//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authzv1 "k8s.io/api/authorization/v1"

	"github.com/telekom/auth-operator/test/utils"
)

// /authorize request checks, webhook TLS pinning and their transitional
// opt-outs, exercised against the deployed webhook server through a port-forward.
var _ = Describe("Authorize request and webhook TLS hardening", Ordered, Label("helm", "authorize-hardening"), func() {
	const release = "auth-operator-authorize-e2e"
	const optOutFlags = "--disable-authorize-request-checks|--webhook-tls-go-defaults"

	var port int
	var stopForward func()
	forward := func() {
		if stopForward != nil {
			stopForward()
		}
		port, stopForward = startWebhookAuthorizerPortForward(release, release+"-webhook-service")
	}
	webhookArgs := func() string {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", "get", "deployment", release+"-webhook-server",
			"-n", release, "-o", "jsonpath={.spec.template.spec.containers[0].args}"))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		return string(out)
	}
	// send issues a raw request to /authorize and returns the status, headers and body.
	send := func(method, contentType string, body []byte) (int, http.Header, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("https://127.0.0.1:%d/authorize", port), bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- self-signed webhook certificate behind a port-forward.
		defer transport.CloseIdleConnections()
		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		respBody, err := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, respBody, err
	}
	post := func(method, contentType string, body []byte) (int, http.Header, []byte) {
		GinkgoHelper()
		status, header, respBody, err := send(method, contentType, body)
		Expect(err).NotTo(HaveOccurred())
		return status, header, respBody
	}
	sarBody := func(sar authzv1.SubjectAccessReview) []byte {
		GinkgoHelper()
		body, err := json.Marshal(sar)
		Expect(err).NotTo(HaveOccurred())
		return body
	}
	// answered asserts a SubjectAccessReview answer that is not allowed:
	// denied (fail closed) or no opinion.
	answered := func(status int, body []byte, denied bool, reason string) {
		GinkgoHelper()
		Expect(status).To(Equal(http.StatusOK), "%s", body)
		var sar authzv1.SubjectAccessReview
		Expect(json.Unmarshal(body, &sar)).To(Succeed(), "%s", body)
		Expect(sar.Status).To(And(HaveField("Allowed", false), HaveField("Denied", denied), HaveField("Reason", reason)))
	}
	deniedWith := func(status int, body []byte, reason string) {
		GinkgoHelper()
		answered(status, body, true, reason)
	}
	noOpinion := func(status int, body []byte) {
		GinkgoHelper()
		answered(status, body, false, "Access denied: no matching rules")
	}
	// refused asserts the server rejected the handshake with a TLS alert, not
	// that the port-forward or connection failed.
	refused := func(err error, what string) {
		GinkgoHelper()
		Expect(err).To(MatchError(ContainSubstring("remote error: tls:")), what)
	}
	// handshake completes a TLS handshake with the webhook server and returns
	// the negotiated version.
	handshake := func(minVersion, maxVersion uint16, suites ...uint16) (uint16, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
			InsecureSkipVerify: true,       // #nosec G402 -- self-signed webhook certificate behind a port-forward.
			MinVersion:         minVersion, // #nosec G402 -- probes that the server refuses legacy versions.
			MaxVersion:         maxVersion,
			CipherSuites:       suites,
		}}
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return 0, err
		}
		defer func() { _ = conn.Close() }()
		return conn.(*tls.Conn).ConnectionState().Version, nil
	}
	// Each pair covers the RSA and ECDSA variant so the probe does not depend
	// on the webhook certificate's key type.
	pinnedSuites := [][]uint16{
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
	}
	// ECDHE with CBC is in Go's default TLS 1.2 suites but not in the pinned set.
	cbcSuites := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	// Go's server default and the pinned config share the TLS 1.2 floor and
	// the AEAD ECDHE suites.
	expectTLS12Floor := func() {
		GinkgoHelper()
		_, err := handshake(tls.VersionTLS10, tls.VersionTLS11)
		refused(err, "TLS 1.0/1.1 must be refused")
		version, err := handshake(tls.VersionTLS13, tls.VersionTLS13)
		Expect(err).NotTo(HaveOccurred())
		Expect(version).To(Equal(uint16(tls.VersionTLS13)))
		for _, suites := range pinnedSuites {
			version, err = handshake(tls.VersionTLS12, tls.VersionTLS12, suites...)
			Expect(err).NotTo(HaveOccurred(), "pinned TLS 1.2 suite %s must be accepted", tls.CipherSuiteName(suites[0]))
			Expect(version).To(Equal(uint16(tls.VersionTLS12)))
		}
	}
	validSAR := resourceSAR("e2e-hardening-user", nil, "get", "pods", "default")

	BeforeAll(func() {
		Expect(utils.LoadImageToKindClusterWithName(projectImage)).To(Succeed())
		args := append([]string{"upgrade", "--install", release, "chart/auth-operator", "-n", release, "--create-namespace"}, imageSetArgs()...)
		args = append(args, "--set", "controller.replicas=1", "--set", "webhookServer.replicas=1",
			"--set", "webhookServer.allowUnauthenticatedAuthorize=true", "--set", "global.logFormat=json", "--wait", "--timeout", "5m")
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", args...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		forward()
	})

	AfterAll(func() {
		if stopForward != nil {
			stopForward()
		}
		if CurrentSpecReport().Failed() {
			utils.CollectOperatorLogs(release, 200)
		}
		_, err := utils.Run(utils.CommandContext(context.Background(), "helm", "uninstall", release, "-n", release, "--wait", "--timeout", "2m"))
		Expect(err).NotTo(HaveOccurred())
		utils.CleanupNamespace(release)
	})

	It("accepts only JSON POST requests on /authorize by default", func() {
		Expect(webhookArgs()).NotTo(MatchRegexp(optOutFlags), "the chart must not render opt-out flags by default")

		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			status, header, body := post(method, "application/json", sarBody(validSAR))
			Expect(status).To(Equal(http.StatusMethodNotAllowed), "%s: %s", method, body)
			Expect(header.Get("Allow")).To(Equal(http.MethodPost))
		}
		for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx", "not a media type;"} {
			status, _, body := post(http.MethodPost, contentType, sarBody(validSAR))
			Expect(status).To(Equal(http.StatusUnsupportedMediaType), "Content-Type %q: %s", contentType, body)
		}
		status, _, body := post(http.MethodPost, "application/json; charset=utf-8", sarBody(validSAR))
		noOpinion(status, body)
	})

	It("fails closed on malformed and oversized /authorize bodies", func() {
		status, _, body := post(http.MethodPost, "application/json", []byte(`{"spec":`))
		deniedWith(status, body, "invalid request body")
		status, _, body = post(http.MethodPost, "application/json", sarBody(authzv1.SubjectAccessReview{}))
		deniedWith(status, body, "empty user identity and no groups")
		status, _, body = post(http.MethodPost, "application/json", sarBody(authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "e2e-hardening-user"}}))
		deniedWith(status, body, "missing resource and non-resource attributes")
		both := validSAR
		both.Spec.NonResourceAttributes = &authzv1.NonResourceAttributes{Verb: "get", Path: "/healthz"}
		status, _, body = post(http.MethodPost, "application/json", sarBody(both))
		deniedWith(status, body, "resource and non-resource attributes are mutually exclusive")

		// A valid SAR padded just past the 1 MiB body cap, so the client has
		// sent everything before the server stops reading.
		oversized := validSAR
		oversized.Spec.Extra = map[string]authzv1.ExtraValue{"padding": {strings.Repeat("x", 1<<20)}}
		status, _, body = post(http.MethodPost, "application/json", sarBody(oversized))
		deniedWith(status, body, "invalid request body")
	})

	It("logs a denied authorization decision as one JSON object with global.logFormat=json", func() {
		Expect(webhookArgs()).To(ContainSubstring("--log-format=json"))
		// A fresh port-forward, in case the oversized body reset the previous one.
		forward()
		const user = "e2e-json-log-denied-user"
		applyYAML(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: e2e-json-log-deny
spec:
  resourceRules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get"]
  deniedPrincipals:
    - user: ` + user + "\n")
		DeferCleanup(func() {
			_, _ = utils.Run(utils.CommandContext(context.Background(), "kubectl", "delete", "webhookauthorizer", "e2e-json-log-deny", "--ignore-not-found"))
		})

		Eventually(func(g Gomega) {
			status, _, body, err := send(http.MethodPost, "application/json", sarBody(resourceSAR(user, nil, "get", "pods", "default")))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(status).To(Equal(http.StatusOK))
			var sar authzv1.SubjectAccessReview
			g.Expect(json.Unmarshal(body, &sar)).To(Succeed())
			g.Expect(sar.Status.Denied).To(BeTrue(), "%s", body)

			out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", "logs", "-n", release,
				"-l", "control-plane=webhook-server", "-c", "webhook", "--tail=-1"))
			g.Expect(err).NotTo(HaveOccurred(), "%s", out)
			var decision map[string]any
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.Contains(line, user) || !strings.Contains(line, "authorization decision") {
					continue
				}
				g.Expect(json.Unmarshal([]byte(line), &decision)).To(Succeed(), "decision line is not JSON: %s", line)
			}
			g.Expect(decision).To(And(HaveKeyWithValue("msg", "authorization decision"),
				HaveKeyWithValue("decision", "denied"), HaveKeyWithValue("user", user),
				HaveKeyWithValue("authorizer", "e2e-json-log-deny")))
		}, reconcileTimeout, pollingInterval).Should(Succeed())
	})

	It("requires TLS 1.2+ and only the pinned TLS 1.2 cipher suites by default", func() {
		// A fresh port-forward, in case the oversized body reset the previous one.
		forward()
		expectTLS12Floor()
		// Go's default suites accept ECDHE CBC, so this is what proves the pinning.
		_, err := handshake(tls.VersionTLS12, tls.VersionTLS12, cbcSuites...)
		refused(err, "ECDHE CBC suites must be refused")
		// Go's defaults also refuse static RSA key exchange; this only guards
		// against the pinned list growing to include it.
		_, err = handshake(tls.VersionTLS12, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
		refused(err, "static RSA key exchange must be refused")
	})

	It("restores the previous request handling and Go TLS defaults with the opt-outs", func() {
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", "upgrade", release, "chart/auth-operator", "-n", release,
			"--reuse-values", "--set", "webhookServer.disableAuthorizeRequestChecks=true", "--set", "webhookServer.tlsGoDefaults=true",
			"--wait", "--timeout", "5m"))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		args := webhookArgs()
		Expect(args).To(ContainSubstring("--disable-authorize-request-checks=true"))
		Expect(args).To(ContainSubstring("--webhook-tls-go-defaults=true"))

		// helm --wait does not wait for the old pod to terminate, and a
		// port-forward to the Service may pick it until it is gone.
		Eventually(func() ([]string, error) {
			out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", "get", "pods", "-n", release,
				"-l", "control-plane=webhook-server", "-o", "name"))
			return strings.Fields(string(out)), err
		}, deployTimeout, pollingInterval).Should(HaveLen(1))
		forward()
		// A GET that is no longer rejected with 405 marks the new pod.
		Eventually(func() (int, error) {
			status, _, _, err := send(http.MethodGet, "", nil)
			return status, err
		}, reconcileTimeout, pollingInterval).Should(Equal(http.StatusOK))

		_, err = handshake(tls.VersionTLS12, tls.VersionTLS12, cbcSuites...)
		Expect(err).NotTo(HaveOccurred(), "Go's default ECDHE CBC suites must be accepted again")
		expectTLS12Floor()

		status, header, body := post(http.MethodGet, "", nil)
		Expect(header.Get("Allow")).To(BeEmpty())
		deniedWith(status, body, "invalid request body")
		status, _, body = post(http.MethodPost, "text/plain", sarBody(validSAR))
		noOpinion(status, body)
	})

	It("writes only JSON lines, including TLS handshake errors, with global.logFormat=json", func() {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", "logs", "-n", release,
			"-l", "control-plane=webhook-server", "-c", "webhook", "--tail=-1"))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		handshakeErrors := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			var entry map[string]any
			Expect(json.Unmarshal([]byte(line), &entry)).To(Succeed(), "webhook log line is not JSON: %s", line)
			if msg, _ := entry["msg"].(string); strings.Contains(msg, "TLS handshake error") {
				Expect(entry).To(HaveKeyWithValue("logger", "stdlib"))
				handshakeErrors++
			}
		}
		// The refused TLS 1.0/1.1 handshakes of the previous spec.
		Expect(handshakeErrors).To(BeNumerically(">", 0))
	})
})
