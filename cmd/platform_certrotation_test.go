// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authzv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const platformProcessArgs = "AUTH_OPERATOR_PLATFORM_PROCESS_ARGS"

// The upstream rotator calls os.Exit(0) on renewal, including bootstrap.
// Execute the real CLI in a subprocess so that this behavior is tested safely.
func TestPlatformWebhookProcess(t *testing.T) {
	argsJSON := os.Getenv(platformProcessArgs)
	if argsJSON == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformCertificateLifecycle(t *testing.T) {
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
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "platform-certs-"}}
	g.Expect(api.Create(ctx, ns)).To(gomega.Succeed())
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "webhook-certs", Namespace: ns.Name}}
	g.Expect(api.Create(ctx, secret)).To(gomega.Succeed())

	failurePolicy := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	servicePath := "/unused"
	wh := admissionregistrationv1.WebhookClientConfig{
		Service: &admissionregistrationv1.ServiceReference{Name: "webhook", Namespace: ns.Name, Path: &servicePath},
	}
	mutating := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: ns.Name},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "platform.example.com", ClientConfig: wh, FailurePolicy: &failurePolicy,
			SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
		}},
	}
	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: ns.Name},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "platform.example.com", ClientConfig: wh, FailurePolicy: &failurePolicy,
			SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
		}},
	}
	g.Expect(api.Create(ctx, mutating)).To(gomega.Succeed())
	g.Expect(api.Create(ctx, validating)).To(gomega.Succeed())

	dir := t.TempDir()
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
	certDir := filepath.Join(dir, "certs")
	g.Expect(os.Mkdir(certDir, 0o700)).To(gomega.Succeed())
	dnsName := "webhook." + ns.Name + ".svc"
	probeAddr := platformFreeAddress(t)
	webhookAddr := platformFreeAddress(t)
	_, webhookPortString, err := net.SplitHostPort(webhookAddr)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	baseArgs := []string{
		"webhook", "--namespace=" + ns.Name, "--certs-dir=" + certDir,
		"--cert-rotation-dns-name=" + dnsName, "--cert-rotation-secret-name=" + secret.Name,
		"--cert-rotation-mutating-webhook=" + mutating.Name,
		"--cert-rotation-validating-webhook=" + validating.Name,
		"--health-probe-bind-address=" + probeAddr, "--port=" + webhookPortString,
		"--metrics-bind-address=0", "--leader-elect=false",
	}
	executable, err := os.Executable()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	start := func(extra ...string) (chan error, func()) {
		args, marshalErr := json.Marshal(append(append([]string(nil), baseArgs...), extra...))
		g.Expect(marshalErr).NotTo(gomega.HaveOccurred())
		logFile, openErr := os.Create(filepath.Join(dir, fmt.Sprintf("process-%d.log", time.Now().UnixNano())))
		g.Expect(openErr).NotTo(gomega.HaveOccurred())
		processCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		process := exec.CommandContext(processCtx, executable, "-test.run=^TestPlatformWebhookProcess$", "-test.v")
		process.Env = append(os.Environ(), platformProcessArgs+"="+string(args))
		process.Stdout, process.Stderr = logFile, logFile
		g.Expect(process.Start()).To(gomega.Succeed())
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = process.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				cancel()
				<-done
			}
			cancel()
			_ = logFile.Close()
			if t.Failed() {
				output, readErr := os.ReadFile(logFile.Name())
				if readErr == nil {
					t.Logf("webhook process output:\n%s", output)
				}
			}
		}
		t.Cleanup(stop)
		return done, stop
	}
	restartForRefresh := func() {
		done, stop := start()
		select {
		case exitErr := <-done:
			done <- exitErr
			g.Expect(exitErr).NotTo(gomega.HaveOccurred(), "rotator must request restart with exit 0")
		case <-time.After(45 * time.Second):
			t.Fatal("rotator did not exit after refreshing the Secret")
		}
		stop()
		g.Expect(api.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(gomega.Succeed())
		pair, pairErr := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
		g.Expect(pairErr).NotTo(gomega.HaveOccurred())
		leaf, parseErr := x509.ParseCertificate(pair.Certificate[0])
		g.Expect(parseErr).NotTo(gomega.HaveOccurred())
		roots := x509.NewCertPool()
		g.Expect(roots.AppendCertsFromPEM(secret.Data["ca.crt"])).To(gomega.BeTrue())
		_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: dnsName, Roots: roots})
		g.Expect(verifyErr).NotTo(gomega.HaveOccurred())
		block, _ := pem.Decode(secret.Data["ca.crt"])
		g.Expect(block).NotTo(gomega.BeNil())
		ca, parseErr := x509.ParseCertificate(block.Bytes)
		g.Expect(parseErr).NotTo(gomega.HaveOccurred())
		g.Expect(ca.Subject.CommonName).To(gomega.Equal("cert"))
		g.Expect(ca.Subject.Organization).To(gomega.Equal([]string{"t-caas"}))
	}
	mount := func() {
		g.Expect(os.WriteFile(filepath.Join(certDir, "tls.crt"), secret.Data[corev1.TLSCertKey], 0o600)).To(gomega.Succeed())
		g.Expect(os.WriteFile(filepath.Join(certDir, "tls.key"), secret.Data[corev1.TLSPrivateKeyKey], 0o600)).To(gomega.Succeed())
	}
	httpClient := &http.Client{Timeout: 2 * time.Second}
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
	assertInjected := func() {
		g.Eventually(func() bool {
			if api.Get(ctx, client.ObjectKeyFromObject(mutating), mutating) != nil ||
				api.Get(ctx, client.ObjectKeyFromObject(validating), validating) != nil {
				return false
			}
			return bytes.Equal(mutating.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"]) &&
				bytes.Equal(validating.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"])
		}, 30*time.Second, 100*time.Millisecond).Should(gomega.BeTrue())
	}

	t.Log("bootstrap populates the existing Secret and requests a pod restart")
	restartForRefresh()
	t.Log("readiness remains false before the Secret volume is projected")
	_, stop := start()
	g.Eventually(readyStatus, 20*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	g.Consistently(readyStatus, time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	mount()
	g.Eventually(readyStatus, 30*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusOK))
	assertInjected()
	roots := x509.NewCertPool()
	g.Expect(roots.AppendCertsFromPEM(secret.Data["ca.crt"])).To(gomega.BeTrue())
	tlsClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: dnsName, MinVersion: tls.VersionTLS12},
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+webhookAddr+"/authorize", nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	response, err := tlsClient.Do(request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(response.StatusCode).To(gomega.Equal(http.StatusOK))
	var review authzv1.SubjectAccessReview
	g.Expect(json.NewDecoder(response.Body).Decode(&review)).To(gomega.Succeed())
	g.Expect(review.Status.Allowed).To(gomega.BeFalse())
	g.Expect(review.Status.Reason).NotTo(gomega.BeEmpty())
	g.Expect(response.Body.Close()).To(gomega.Succeed())
	stop()

	t.Log("invalid serving certificate rotates without replacing the valid CA")
	oldCA := append([]byte(nil), secret.Data["ca.crt"]...)
	oldCert := append([]byte(nil), secret.Data[corev1.TLSCertKey]...)
	secret.Data[corev1.TLSCertKey] = []byte("invalid")
	g.Expect(api.Update(ctx, secret)).To(gomega.Succeed())
	restartForRefresh()
	g.Expect(secret.Data["ca.crt"]).To(gomega.Equal(oldCA))
	g.Expect(secret.Data[corev1.TLSCertKey]).NotTo(gomega.Equal(oldCert))

	t.Log("invalid CA rotates both CA and serving certificate, then reinjects both bundles")
	secret.Data["ca.crt"] = []byte("invalid")
	g.Expect(api.Update(ctx, secret)).To(gomega.Succeed())
	restartForRefresh()
	g.Expect(secret.Data["ca.crt"]).NotTo(gomega.Equal(oldCA))
	mount()
	_, stop = start()
	g.Eventually(readyStatus, 30*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusOK))
	assertInjected()
	stop()

	t.Log("disabled rotation registers handlers using existing certificates without updating the Secret")
	resourceVersion := secret.ResourceVersion
	_, stop = start("--disable-cert-rotation", "--tracing-enabled",
		"--tracing-endpoint=http://127.0.0.1:4317", "--tracing-sampling-rate=0")
	g.Eventually(readyStatus, 30*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusOK))
	g.Expect(api.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(gomega.Succeed())
	g.Expect(secret.ResourceVersion).To(gomega.Equal(resourceVersion))
	stop()

	t.Log("a non-leader becomes ready from mounted certificates without owning rotation")
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
	g.Expect(os.Remove(filepath.Join(certDir, "tls.crt"))).To(gomega.Succeed())
	g.Expect(os.Remove(filepath.Join(certDir, "tls.key"))).To(gomega.Succeed())
	_, stop = start("--leader-elect=true")
	g.Eventually(readyStatus, 20*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	g.Consistently(readyStatus, time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusInternalServerError))
	mount()
	g.Eventually(readyStatus, 30*time.Second, 100*time.Millisecond).Should(gomega.Equal(http.StatusOK))
	g.Expect(api.Get(ctx, client.ObjectKeyFromObject(lease), lease)).To(gomega.Succeed())
	g.Expect(*lease.Spec.HolderIdentity).To(gomega.Equal(holder))
	g.Expect(api.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(gomega.Succeed())
	g.Expect(secret.ResourceVersion).To(gomega.Equal(resourceVersion))
	stop()
}

func platformFreeAddress(t *testing.T) string {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
