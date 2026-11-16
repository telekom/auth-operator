//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

// This suite must run only in the cluster bootstrapped by
// PROVIDED_CA=true run-authorization-chain.sh, which generates ca1 and ca2
// before the cluster exists, installs the chart with ca1 and configures the API
// server to trust both for /authorize.
var _ = Describe("Provided webhook CA", Ordered, Label("authorization-chain", "provided-ca"), func() {
	const (
		release   = "auth-operator-chain"
		namespace = release
		secret    = release + "-webhook-certs"
		dnsName   = release + "-webhook-service." + namespace + ".svc"
		user      = "provided-ca-user"
	)
	var dir, ca1, ca2 string

	kubectl := func(args ...string) (string, error) {
		out, err := utils.Run(utils.CommandContext(context.Background(), "kubectl", args...))
		return string(out), err
	}
	readFile := func(name string) string {
		data, err := os.ReadFile(filepath.Join(dir, name))
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}
	secretData := func(key string) string {
		out, err := kubectl("get", "secret", secret, "-n", namespace, "-o", "jsonpath={.data."+strings.ReplaceAll(key, ".", `\.`)+"}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		data, err := base64.StdEncoding.DecodeString(out)
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}
	pool := func(pems ...string) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range pems {
			Expect(p.AppendCertsFromPEM([]byte(c))).To(BeTrue())
		}
		return p
	}
	// signedBy reports whether certPEM is valid for the webhook Service and chains to caPEM alone.
	signedBy := func(certPEM, caPEM string) error {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("no PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		_, err = cert.Verify(x509.VerifyOptions{DNSName: dnsName, Roots: pool(caPEM)})
		return err
	}
	// caBundles returns the caBundle of every admission webhook that calls this release's Service.
	caBundles := func() map[string]string {
		out, err := kubectl("get", "validatingwebhookconfigurations,mutatingwebhookconfigurations", "-o", "json")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		var list struct {
			Items []struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Webhooks []struct {
					Name         string `json:"name"`
					ClientConfig struct {
						CABundle []byte `json:"caBundle"`
						Service  *struct {
							Namespace string `json:"namespace"`
						} `json:"service"`
					} `json:"clientConfig"`
				} `json:"webhooks"`
			} `json:"items"`
		}
		Expect(json.Unmarshal([]byte(out), &list)).To(Succeed())
		bundles := map[string]string{}
		for _, item := range list.Items {
			for _, webhook := range item.Webhooks {
				if webhook.ClientConfig.Service != nil && webhook.ClientConfig.Service.Namespace == namespace {
					bundles[item.Kind+"/"+item.Metadata.Name+"/"+webhook.Name] = string(webhook.ClientConfig.CABundle)
				}
			}
		}
		return bundles
	}
	expectCABundles := func(want string) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			bundles := caBundles()
			g.Expect(bundles).NotTo(BeEmpty())
			for name, bundle := range bundles {
				g.Expect(bundle).To(Equal(want), "caBundle of %s", name)
			}
		}, time.Minute, time.Second).Should(Succeed())
	}
	// admission sends a request that the RoleDefinition validating webhook denies. A denial proves that
	// the API server reached the webhook over TLS; any other error is returned.
	admission := func(ctx context.Context) error {
		cmd := utils.CommandContext(ctx, "kubectl", "create", "--dry-run=server", "-f", "-")
		cmd.Stdin = strings.NewReader(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: provided-ca-probe
spec:
  targetRole: Role
  targetNamespace: default
  targetName: provided-ca-probe
  scopeNamespaced: true
  breakglassAllowed: true
`)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return fmt.Errorf("expected a webhook denial, got success: %s", out)
		}
		if strings.Contains(string(out), "denied the request") {
			return nil
		}
		return fmt.Errorf("expected a webhook denial: %w: %s", err, out)
	}
	canGetPods := func() string {
		out, _ := kubectl("auth", "can-i", "get", "pods", "-n", namespace, "--as="+user)
		return strings.TrimSpace(out)
	}
	webhookPods := func() []string {
		out, err := kubectl("get", "pods", "-n", namespace, "-l", "control-plane=webhook-server",
			"--field-selector=status.phase=Running", "-o", "jsonpath={.items[*].metadata.name}")
		Expect(err).NotTo(HaveOccurred(), "%s", out)
		return strings.Fields(out)
	}
	forwardedPort := regexp.MustCompile(`127\.0\.0\.1:(\d+) -> 9443`)
	// servesCertificateFrom checks the certificate a webhook pod serves, through a port-forward.
	servesCertificateFrom := func(pod, caPEM string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := utils.CommandContext(ctx, "kubectl", "port-forward", "-n", namespace, "pod/"+pod, ":9443")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		defer func() { cancel(); _ = cmd.Wait() }()
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			return fmt.Errorf("port-forward to %s: %w", pod, err)
		}
		match := forwardedPort.FindStringSubmatch(line)
		if match == nil {
			return fmt.Errorf("unexpected port-forward output %q", line)
		}
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config:    &tls.Config{RootCAs: pool(caPEM), ServerName: dnsName, MinVersion: tls.VersionTLS12},
		}
		conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:"+match[1])
		if err != nil {
			return fmt.Errorf("pod %s: %w", pod, err)
		}
		return conn.Close()
	}
	helmUpgrade := func(args ...string) {
		GinkgoHelper()
		out, err := utils.Run(utils.CommandContext(context.Background(), "helm", append([]string{
			"upgrade", release, "chart/auth-operator", "-n", namespace, "--reuse-values", "--wait", "--timeout", "5m",
		}, args...)...))
		Expect(err).NotTo(HaveOccurred(), "%s", out)
	}

	BeforeAll(func() {
		dir = os.Getenv("E2E_PROVIDED_CA_DIR")
		Expect(dir).NotTo(BeEmpty(), "use PROVIDED_CA=true run-authorization-chain.sh")
		ca1, ca2 = readFile("ca1.crt"), readFile("ca2.crt")

		cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "--server-side", "-f", "-")
		cmd.Stdin = strings.NewReader(`apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: provided-ca-rule
spec:
  allowedPrincipals:
  - user: ` + user + `
  resourceRules:
  - verbs: ["get"]
    apiGroups: [""]
    resources: ["pods"]
`)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
	})

	AfterAll(func() {
		_, _ = kubectl("delete", "webhookauthorizer", "provided-ca-rule", "--ignore-not-found", "--wait=false")
	})

	It("keeps the provided CA from the first install on", func() {
		By("Checking that the rotator kept the provided CA and issued the serving certificate with it")
		Expect(secretData("ca.crt")).To(Equal(ca1))
		Expect(secretData("ca.key")).To(Equal(readFile("ca1.key")))
		Expect(signedBy(secretData("tls.crt"), ca1)).To(Succeed())

		By("Checking that every admission webhook trusts only the provided CA")
		expectCABundles(ca1)

		By("Checking that every webhook replica serves a certificate from the provided CA")
		// Retry: a port-forward through the just restarted API server can drop the first connection.
		Eventually(func(g Gomega) {
			pods := webhookPods()
			g.Expect(pods).To(HaveLen(2))
			for _, pod := range pods {
				g.Expect(servesCertificateFrom(pod, ca1)).To(Succeed())
			}
		}, time.Minute, 2*time.Second).Should(Succeed())

		By("Sending an admission request and an /authorize request through the API server")
		Expect(admission(context.Background())).To(Succeed())
		// The webhook informers relist with backoff after the harness restarted the API server.
		Eventually(canGetPods, 3*time.Minute, 2*time.Second).Should(Equal("yes"))
		out, err := kubectl("auth", "can-i", "delete", "pods", "-n", namespace, "--as="+user)
		Expect(err).To(HaveOccurred(), "unexpected allow: %s", out)
	})

	It("rotates to a new CA without failing admission requests", func() {
		ca2Key := readFile("ca2.key")
		bundle := strings.TrimSpace(ca2) + "\n" + strings.TrimSpace(ca1) + "\n"

		By("Sending admission requests during the whole rotation")
		ctx, stop := context.WithCancel(context.Background())
		var (
			mu       sync.Mutex
			failures []string
			requests int
			wg       sync.WaitGroup
		)
		wg.Add(1)
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			for ctx.Err() == nil {
				err := admission(ctx)
				mu.Lock()
				if ctx.Err() == nil {
					requests++
					// Only TLS failures show a missing trust overlap. A replica that the rotator
					// restarts can refuse connections before it leaves the Service endpoints.
					if err != nil && (strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "tls:")) {
						failures = append(failures, err.Error())
					}
				}
				mu.Unlock()
				time.Sleep(200 * time.Millisecond)
			}
		}()
		DeferCleanup(func() { stop(); wg.Wait() })

		By("Trusting ca2 while the rotator still signs with ca1")
		helmUpgrade("--set-file", "webhookServer.certificateAuthority.additionalTrustedCertificates="+filepath.Join(dir, "ca2.crt"))
		Expect(secretData("ca.crt")).To(Equal(strings.TrimSpace(ca1) + "\n" + strings.TrimSpace(ca2) + "\n"))
		expectCABundles(strings.TrimSpace(ca1) + "\n" + strings.TrimSpace(ca2) + "\n")
		Expect(signedBy(secretData("tls.crt"), ca1)).To(Succeed())

		By("Switching to ca2 and keeping ca1 trusted")
		helmUpgrade(
			"--set-file", "webhookServer.certificateAuthority.certificate="+filepath.Join(dir, "ca2.crt"),
			"--set-file", "webhookServer.certificateAuthority.privateKey="+filepath.Join(dir, "ca2.key"),
			"--set-file", "webhookServer.certificateAuthority.additionalTrustedCertificates="+filepath.Join(dir, "ca1.crt"),
		)
		Expect(secretData("ca.crt")).To(Equal(bundle))
		Expect(secretData("ca.key")).To(Equal(ca2Key))
		expectCABundles(bundle)

		By("Waiting for the rotator to issue a serving certificate from ca2")
		Eventually(func() error { return signedBy(secretData("tls.crt"), ca2) }, 2*time.Minute, time.Second).Should(Succeed())
		By("Waiting for every webhook replica to serve it")
		Eventually(func(g Gomega) {
			pods := webhookPods()
			g.Expect(pods).To(HaveLen(2))
			for _, pod := range pods {
				g.Expect(servesCertificateFrom(pod, ca2)).To(Succeed())
			}
		}, 5*time.Minute, 2*time.Second).Should(Succeed())
		// The rotator keeps the bundle after it re-issued the serving certificate.
		Expect(secretData("ca.crt")).To(Equal(bundle))
		expectCABundles(bundle)

		stop()
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		Expect(requests).To(BeNumerically(">", 20), "too few admission requests during the rotation")
		Expect(failures).To(BeEmpty(), "admission requests failed TLS during the rotation (%d requests)", requests)
		_, _ = fmt.Fprintf(GinkgoWriter, "%d admission requests during the rotation\n", requests)

		By("Dropping ca1")
		helmUpgrade("--set", "webhookServer.certificateAuthority.additionalTrustedCertificates=")
		Expect(secretData("ca.crt")).To(Equal(ca2))
		expectCABundles(ca2)
		Expect(signedBy(secretData("tls.crt"), ca2)).To(Succeed())
		Expect(admission(context.Background())).To(Succeed())
		Expect(canGetPods()).To(Equal("yes"))
	})
})
