// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/onsi/gomega"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestPlatformMountedCertificateValidation(t *testing.T) {
	g := gomega.NewWithT(t)
	ctx := t.Context()
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	t.Cleanup(func() { g.Expect(env.Stop()).To(gomega.Succeed()) })
	initScheme()
	api, err := client.New(cfg, client.Options{Scheme: scheme})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "platform-mount-"}}
	g.Expect(api.Create(ctx, ns)).To(gomega.Succeed())
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-certs", Namespace: ns.Name}}
	g.Expect(api.Create(ctx, secret)).To(gomega.Succeed())
	holder := "another-webhook-replica"
	duration := int32(600)
	renewTime := metav1.NewMicroTime(time.Now())
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-webhook.t-caas.telekom.com", Namespace: ns.Name},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &renewTime,
		},
	}
	g.Expect(api.Create(ctx, lease)).To(gomega.Succeed())

	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	g.Expect(os.Mkdir(certDir, 0o700)).To(gomega.Succeed())
	kubeconfig := filepath.Join(dir, "kubeconfig")
	g.Expect(clientcmd.WriteToFile(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"envtest": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"envtest": {
			ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData,
		}},
		Contexts:       map[string]*clientcmdapi.Context{"envtest": {Cluster: "envtest", AuthInfo: "envtest"}},
		CurrentContext: "envtest",
	}, kubeconfig)).To(gomega.Succeed())
	t.Setenv("KUBECONFIG", kubeconfig)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dnsName := "webhook." + ns.Name + ".svc"
	certificate := func(key *ecdsa.PrivateKey, notBefore, notAfter time.Time) []byte {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
			NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, certErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		g.Expect(certErr).NotTo(gomega.HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	now := time.Now()
	validCert := certificate(key, now.Add(-time.Hour), now.Add(time.Hour))
	mount := func(cert []byte) {
		g.Expect(os.WriteFile(filepath.Join(certDir, "tls.crt"), cert, 0o600)).To(gomega.Succeed())
		g.Expect(os.WriteFile(filepath.Join(certDir, "tls.key"), keyPEM, 0o600)).To(gomega.Succeed())
	}
	mount([]byte("non-empty but invalid"))
	probeAddr, webhookAddr := platformFreeAddress(t), platformFreeAddress(t)
	_, port, err := net.SplitHostPort(webhookAddr)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	baseArgs := []string{
		"webhook", "--namespace=" + ns.Name, "--certs-dir=" + certDir,
		"--cert-rotation-dns-name=" + dnsName, "--cert-rotation-secret-name=" + secret.Name,
		"--health-probe-bind-address=" + probeAddr, "--port=" + port,
		"--metrics-bind-address=0", "--leader-elect=true",
	}
	executable, err := os.Executable()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	for _, tc := range []struct {
		name, flag, message string
	}{
		{"missing directory", "--certs-dir=", "certs-dir is undefined"},
		{"missing Secret", "--cert-rotation-secret-name=", "secret name is required"},
		{"missing DNS name", "--cert-rotation-dns-name=", "DNS name or service name is required"},
		{"empty validating webhook name", "--cert-rotation-validating-webhook=good,", "validating webhook names must not be empty"},
		{"empty mutating webhook name", "--cert-rotation-mutating-webhook=good,", "mutating webhook names must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			args, marshalErr := json.Marshal(append(append([]string(nil), baseArgs...), tc.flag))
			g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
			startupCtx, startupCancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer startupCancel()
			command := exec.CommandContext(startupCtx, executable, "-test.run=^TestPlatformWebhookProcess$", "-test.v")
			command.Env = append(os.Environ(), platformProcessArgs+"="+string(args))
			output, startupErr := command.CombinedOutput()
			g.Expect(startupCtx.Err()).NotTo(gomega.HaveOccurred(), string(output))
			g.Expect(startupErr).To(gomega.HaveOccurred(), "invalid rotation configuration must fail startup")
			g.Expect(string(output)).To(gomega.ContainSubstring(tc.message))
		})
	}
	args, err := json.Marshal(baseArgs)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	processCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	process := exec.CommandContext(processCtx, executable, "-test.run=^TestPlatformWebhookProcess$", "-test.v")
	process.Env = append(os.Environ(), platformProcessArgs+"="+string(args))
	var output bytes.Buffer
	process.Stdout, process.Stderr = &output, &output
	g.Expect(process.Start()).To(gomega.Succeed())
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGTERM)
		select {
		case exitErr := <-done:
			g.Expect(exitErr).NotTo(gomega.HaveOccurred(), output.String())
		case <-time.After(10 * time.Second):
			cancel()
			<-done
			t.Errorf("webhook process did not stop gracefully: %s", output.String())
		}
		cancel()
		if t.Failed() {
			t.Log(output.String())
		}
	})
	httpClient := &http.Client{Timeout: time.Second}
	readyStatus := func() int {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+probeAddr+"/readyz", nil)
		if requestErr != nil {
			return 0
		}
		response, requestErr := httpClient.Do(request)
		if requestErr != nil {
			return 0
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	g.Eventually(readyStatus, 20*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	for _, tc := range []struct {
		name string
		cert []byte
	}{
		{"malformed", []byte("non-empty but invalid")},
		{"mismatched key", certificate(otherKey, now.Add(-time.Hour), now.Add(time.Hour))},
		{"expired", certificate(key, now.Add(-2*time.Hour), now.Add(-time.Hour))},
		{"not yet valid", certificate(key, now.Add(time.Hour), now.Add(2*time.Hour))},
	} {
		t.Logf("%s mounted certificate must not register webhooks or mark the replica ready", tc.name)
		// Keep the key fixed so replacing an invalid certificate cannot
		// temporarily produce a valid pair and open the one-shot setup gate.
		mount(tc.cert)
		// Cover multiple one-second mount-watcher polls for each invalid pair.
		g.Consistently(readyStatus, 2500*time.Millisecond, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	}
	mount(validCert)
	g.Eventually(readyStatus, 30*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusOK))
	roots := x509.NewCertPool()
	g.Expect(roots.AppendCertsFromPEM(validCert)).To(gomega.BeTrue())
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: dnsName, MinVersion: tls.VersionTLS12,
	}}
	defer transport.CloseIdleConnections()
	tlsClient := &http.Client{Timeout: time.Second, Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+webhookAddr+"/authorize", nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	response, err := tlsClient.Do(request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(response.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(response.Body.Close()).To(gomega.Succeed())
	g.Expect(api.Get(ctx, client.ObjectKeyFromObject(lease), lease)).To(gomega.Succeed())
	g.Expect(*lease.Spec.HolderIdentity).To(gomega.Equal(holder))
	g.Expect(api.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(gomega.Succeed())
	g.Expect(secret.Data).To(gomega.BeEmpty())
}
