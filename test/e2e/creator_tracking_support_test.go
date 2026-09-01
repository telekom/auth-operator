//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/buildinfo"
	"debug/elf"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

const (
	creatorReinvocationService = "creator-reinvocation-webhook"
	creatorReinvocationWebhook = "creator-reinvocation-webhook"
	creatorReinvocationImage   = "auth-operator/creator-reinvocation-webhook:e2e"
	creatorReinvocationTrigger = "e2e.t-caas.telekom.com/reinvoke-trigger"
	creatorReinvocationMarker  = "e2e.t-caas.telekom.com/reinvoke-uid"
	creatorCreatorRole         = "e2e-creator-namespace-create"
	creatorCreatorBinding      = "e2e-creator-namespace-create"
	creatorEditorRole          = "e2e-creator-namespace-edit"
	creatorEditorBinding       = "e2e-creator-namespace-edit"
	creatorUserRole            = "e2e-creator-user-impersonate"
	creatorUserBinding         = "e2e-creator-user-impersonate"

	creatorReservedUser = "e2e-user%,comma"
)

type creatorTLSBundle struct {
	CA   []byte
	Cert []byte
	Key  []byte
}

type creatorExpectedManagedField struct {
	Manager   string
	Operation string
	Paths     [][]string
}

type creatorExactResource struct {
	Kind      string
	Name      string
	Namespace string
}

func creatorApplyIdentityRBAC(ctx context.Context) error {
	manifest := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata: {name: %[1]s, namespace: %[5]s}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: %[2]s, namespace: %[5]s}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: %[3]s, namespace: %[5]s}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: %[4]s, namespace: %[5]s}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: %[6]s, namespace: %[5]s}
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    resourceNames: ["%[2]s", "%[3]s", "%[4]s"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: %[7]s, namespace: %[5]s}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %[6]s
subjects:
  - {kind: ServiceAccount, name: %[1]s, namespace: %[5]s}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: %[15]s}
rules:
  # A reserved-character user exercises URL-safe annotation encoding.
  - apiGroups: [""]
    resources: ["users"]
    resourceNames: ["%[14]s"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: %[16]s}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[15]s
subjects:
  - {kind: ServiceAccount, name: %[1]s, namespace: %[5]s}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: %[8]s}
rules:
  # CREATE cannot use resourceNames because the name is not part of its URL.
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: %[9]s}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[8]s
subjects:
  - {kind: ServiceAccount, name: %[2]s, namespace: %[5]s}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: %[10]s}
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    resourceNames: ["%[11]s", "%[12]s", "%[17]s"]
    verbs: ["get", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: %[13]s}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[10]s
subjects:
  - {kind: ServiceAccount, name: %[2]s, namespace: %[5]s}
  - {kind: ServiceAccount, name: %[3]s, namespace: %[5]s}
  - {kind: ServiceAccount, name: %[4]s, namespace: %[5]s}
  - {kind: User, name: "%[14]s"}
`, creatorRequesterSA, creatorTargetSA, creatorEditorASA, creatorEditorBSA, creatorTestNS,
		creatorRoleName, creatorRoleBinding, creatorCreatorRole, creatorCreatorBinding,
		creatorEditorRole, creatorContributorsNS, creatorContributorLimitNS,
		creatorEditorBinding, creatorReservedUser, creatorUserRole, creatorUserBinding,
		creatorForgedCreateNS)
	return creatorApplyManifest(ctx, manifest)
}

func creatorRemoveTempFile(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("remove temporary file %s: %w", path, err)
}

func creatorPrivateRunDir() (string, error) {
	runDir := os.Getenv("E2E_CREATOR_TRACKING_RUN_DIR")
	if runDir == "" {
		return "", fmt.Errorf("E2E_CREATOR_TRACKING_RUN_DIR is required")
	}
	runDir, err := filepath.Abs(runDir)
	if err != nil {
		return "", fmt.Errorf("resolve creator tracking run directory: %w", err)
	}
	info, err := os.Lstat(runDir)
	if err != nil {
		return "", fmt.Errorf("inspect creator tracking run directory: %w", err)
	}
	if !info.Mode().IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("creator tracking run directory must be private: %s", runDir)
	}
	markerPath := filepath.Join(runDir, "provenance")
	markerInfo, markerErr := os.Lstat(markerPath)
	if markerErr != nil || markerInfo == nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("creator run provenance marker is missing or not private")
	}
	marker, markerErr := os.ReadFile(markerPath)
	if markerErr != nil || strings.TrimSpace(string(marker)) == "" {
		return "", fmt.Errorf("creator run provenance marker is empty")
	}
	if strings.TrimSpace(string(marker)) != "auth-operator-e2e-creator-tracking" {
		return "", fmt.Errorf("creator run provenance marker names a different run")
	}
	return runDir, nil
}

func creatorPrivateKubeconfig() (string, error) {
	runDir, err := creatorPrivateRunDir()
	if err != nil {
		return "", err
	}
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" || len(filepath.SplitList(kubeconfigPath)) != 1 {
		return "", fmt.Errorf("KUBECONFIG must contain exactly one private creator tracking kubeconfig")
	}
	kubeconfigPath, err = filepath.Abs(kubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("resolve creator tracking kubeconfig: %w", err)
	}
	if filepath.Dir(kubeconfigPath) != runDir {
		return "", fmt.Errorf("creator tracking kubeconfig %s must be inside run directory %s",
			kubeconfigPath, runDir)
	}
	fileInfo, err := os.Lstat(kubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("inspect creator tracking kubeconfig: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("creator tracking kubeconfig mode = %o, want 600", fileInfo.Mode().Perm())
	}
	return kubeconfigPath, nil
}

func creatorValidateIsolation(ctx context.Context) error {
	config, err := GetSuiteConfig("creator-tracking")
	if err != nil {
		return err
	}
	if err := ValidateClusterIsolation(config); err != nil {
		return err
	}
	kubeconfigPath, err := creatorPrivateKubeconfig()
	if err != nil {
		return err
	}
	active, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("load active creator tracking kubeconfig: %w", err)
	}
	expectedContext := "kind-" + config.ClusterName
	if active.CurrentContext != expectedContext {
		return fmt.Errorf("current context = %q, want %q", active.CurrentContext, expectedContext)
	}
	currentContextOutput, err := creatorKubectl(ctx, "", "config", "current-context")
	if err != nil {
		return fmt.Errorf("read kubectl current context: %w", err)
	}
	if currentContext := strings.TrimSpace(string(currentContextOutput)); currentContext != expectedContext {
		return fmt.Errorf("kubectl current context = %q, want %q", currentContext, expectedContext)
	}
	activeServer, err := creatorKubeconfigServer(active, "active creator tracking")
	if err != nil {
		return err
	}

	expectedPort, err := creatorRun(ctx, "", "docker", "port", config.ClusterName+"-control-plane", "6443/tcp")
	if err != nil {
		return fmt.Errorf("read reserved Kind API port: %w", err)
	}
	activeURL, err := url.Parse(activeServer)
	if err != nil {
		return fmt.Errorf("parse active API server: %w", err)
	}
	portLine := strings.TrimSpace(string(expectedPort))
	separator := strings.LastIndex(portLine, ":")
	if separator < 0 || separator == len(portLine)-1 {
		return fmt.Errorf("reserved Kind API port has an unexpected format")
	}
	if activeURL.Scheme != "https" || activeURL.Hostname() != "127.0.0.1" || activeURL.Port() != portLine[separator+1:] {
		return fmt.Errorf("active API server does not match the reserved Kind container")
	}
	if _, err := creatorKubectl(ctx, "", "get", "--raw", "/version"); err != nil {
		return fmt.Errorf("contact exact creator tracking API server: %w", err)
	}
	return nil
}

func creatorKubeconfigServer(config *clientcmdapi.Config, description string) (string, error) {
	contextConfig := config.Contexts[config.CurrentContext]
	if contextConfig == nil || config.Clusters[contextConfig.Cluster] == nil {
		return "", fmt.Errorf("%s kubeconfig has no cluster endpoint", description)
	}
	return config.Clusters[contextConfig.Cluster].Server, nil
}

func creatorCanI(ctx context.Context, kubeconfig string, args ...string) (bool, error) {
	commandArgs := append([]string{"auth", "can-i"}, args...)
	output, err := creatorKubectlAs(ctx, kubeconfig, "", "", commandArgs...)
	response := strings.TrimSpace(string(output))
	switch {
	case err != nil:
		return false, fmt.Errorf("check authorization %v: %w: %s", args, err, response)
	case response == "yes":
		return true, nil
	case response == "no":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected authorization response %q", response)
	}
}

func creatorGenerateTLS(service, namespace string) (creatorTLSBundle, error) {
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("generate webhook CA key: %w", err)
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("generate webhook CA serial: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "creator-reinvocation-e2e-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("create webhook CA certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("generate webhook server key: %w", err)
	}
	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("generate webhook server serial: %w", err)
	}
	serviceDNS := service + "." + namespace + ".svc"
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: serviceDNS},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			service,
			service + "." + namespace,
			serviceDNS,
			serviceDNS + ".cluster.local",
		},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("create webhook server certificate: %w", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return creatorTLSBundle{}, fmt.Errorf("marshal webhook server key: %w", err)
	}

	return creatorTLSBundle{
		CA:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	}, nil
}

func creatorKindNodeArchitecture(ctx context.Context) (string, error) {
	imageOutput, err := creatorRun(ctx, "", "docker", "inspect", kindClusterName+"-control-plane",
		"--format", "{{.Image}}")
	if err != nil {
		return "", fmt.Errorf("inspect Kind node image: %w", err)
	}
	output, err := creatorRun(ctx, "", "docker", "image", "inspect", strings.TrimSpace(string(imageOutput)),
		"--format", "{{.Architecture}} {{.Os}}")
	if err != nil {
		return "", fmt.Errorf("inspect Kind node platform: %w", err)
	}
	parts := strings.Fields(string(output))
	if len(parts) != 2 || parts[1] != "linux" {
		return "", fmt.Errorf("Kind node platform = %q, want linux/<architecture>", strings.TrimSpace(string(output)))
	}
	switch parts[0] {
	case "amd64", "arm64":
		return parts[0], nil
	default:
		return "", fmt.Errorf("unsupported Kind node architecture %q", parts[0])
	}
}

func creatorBuildReinvocationBinary(ctx context.Context, binary, architecture string) error {
	output, err := creatorRun(ctx, "", "env",
		"CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture,
		"go", "build", "-tags=e2e,netgo,osusergo", "-trimpath",
		"-ldflags=-linkmode=internal", "-o", binary,
		"./test/e2e/testserver/creator-reinvocation-webhook")
	if err != nil {
		return fmt.Errorf("build creator reinvocation webhook: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(binary, 0o555); err != nil {
		return fmt.Errorf("make creator reinvocation webhook executable: %w", err)
	}
	return nil
}

func creatorBuildAndLoadReinvocationImage(ctx context.Context) (resultErr error) {
	runDir, err := creatorPrivateRunDir()
	if err != nil {
		return err
	}
	buildDir, err := os.MkdirTemp(runDir, "creator-reinvocation-image-*")
	if err != nil {
		return fmt.Errorf("create webhook image context: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(buildDir); removeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove webhook image context %s: %w", buildDir, removeErr))
		}
	}()

	architecture, err := creatorKindNodeArchitecture(ctx)
	if err != nil {
		return err
	}
	binary := filepath.Join(buildDir, "creator-reinvocation-webhook")
	if err := creatorBuildReinvocationBinary(ctx, binary, architecture); err != nil {
		return err
	}
	buildInfo, err := buildinfo.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("read creator reinvocation webhook build info: %w", err)
	}
	settings := make(map[string]string, len(buildInfo.Settings))
	for _, setting := range buildInfo.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != architecture || settings["CGO_ENABLED"] != "0" {
		return fmt.Errorf("webhook build settings GOOS=%q GOARCH=%q CGO_ENABLED=%q, want linux/%s with CGO disabled",
			settings["GOOS"], settings["GOARCH"], settings["CGO_ENABLED"], architecture)
	}
	webhookELF, err := elf.Open(binary)
	if err != nil {
		return fmt.Errorf("inspect creator reinvocation webhook: %w", err)
	}
	expectedMachine := elf.EM_X86_64
	if architecture == "arm64" {
		expectedMachine = elf.EM_AARCH64
	}
	if webhookELF.Machine != expectedMachine {
		_ = webhookELF.Close()
		return fmt.Errorf("webhook ELF machine = %s, want %s", webhookELF.Machine, expectedMachine)
	}
	for _, program := range webhookELF.Progs {
		if program.Type == elf.PT_INTERP {
			_ = webhookELF.Close()
			return fmt.Errorf("creator reinvocation webhook is dynamically linked")
		}
	}
	if err := webhookELF.Close(); err != nil {
		return fmt.Errorf("close creator reinvocation webhook ELF: %w", err)
	}
	dockerfile := `FROM scratch
COPY creator-reinvocation-webhook /creator-reinvocation-webhook
USER 65532:65532
ENTRYPOINT ["/creator-reinvocation-webhook"]
`
	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return fmt.Errorf("write webhook Dockerfile: %w", err)
	}
	if output, buildErr := creatorRun(ctx, "", "docker", "build", "-t", creatorReinvocationImage, buildDir); buildErr != nil {
		return fmt.Errorf("build webhook image: %w: %s", buildErr, strings.TrimSpace(string(output)))
	}
	if output, loadErr := creatorRun(ctx, "", "kind", "load", "docker-image", creatorReinvocationImage,
		"--name", kindClusterName); loadErr != nil {
		return fmt.Errorf("load webhook image: %w: %s", loadErr, strings.TrimSpace(string(output)))
	}
	return nil
}

func creatorInstallReinvocationWebhook(ctx context.Context) error {
	if err := creatorBuildAndLoadReinvocationImage(ctx); err != nil {
		return err
	}
	tlsBundle, err := creatorGenerateTLS(creatorReinvocationService, creatorTestNS)
	if err != nil {
		return err
	}
	manifest := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %[1]s
  namespace: %[2]s
type: kubernetes.io/tls
data:
  tls.crt: %[3]s
  tls.key: %[4]s
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app.kubernetes.io/name: %[1]s
  ports:
    - name: https
      port: 443
      targetPort: 8443
---
apiVersion: v1
kind: Pod
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app.kubernetes.io/name: %[1]s
spec:
  containers:
    - name: webhook
      image: %[5]s
      imagePullPolicy: IfNotPresent
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
      env:
        - name: FIXTURE_NAME
          value: %[6]s
      ports:
        - name: https
          containerPort: 8443
      readinessProbe:
        httpGet:
          scheme: HTTPS
          path: /healthz
          port: https
        periodSeconds: 1
        failureThreshold: 30
      volumeMounts:
        - name: tls
          mountPath: /tls
          readOnly: true
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  volumes:
    - name: tls
      secret:
        secretName: %[1]s
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: %[1]s
webhooks:
  - name: creator-reinvocation.e2e.t-caas.telekom.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    reinvocationPolicy: Never
    timeoutSeconds: 5
    clientConfig:
      caBundle: %[7]s
      service:
        name: %[1]s
        namespace: %[2]s
        path: /mutate
        port: 443
    rules:
      - operations: ["UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["namespaces"]
        scope: Cluster
    objectSelector:
      matchLabels:
        %[8]s: "true"
    matchConditions:
      - name: exact-fixture
        expression: "object.metadata.name == '%[6]s'"
      - name: explicit-trigger
        expression: "has(object.metadata.labels) && object.metadata.labels['%[8]s'] == 'true'"
`, creatorReinvocationService, creatorTestNS,
		base64.StdEncoding.EncodeToString(tlsBundle.Cert),
		base64.StdEncoding.EncodeToString(tlsBundle.Key),
		creatorReinvocationImage, creatorReinvokeNS,
		base64.StdEncoding.EncodeToString(tlsBundle.CA), creatorReinvocationTrigger)
	if err := creatorApplyManifest(ctx, manifest); err != nil {
		return err
	}
	if output, waitErr := creatorKubectl(ctx, "", "wait", "pod/"+creatorReinvocationService,
		"-n", creatorTestNS, "--for=condition=Ready", "--timeout=2m"); waitErr != nil {
		return fmt.Errorf("wait for reinvocation webhook pod: %w: %s", waitErr, strings.TrimSpace(string(output)))
	}
	deadline := time.Now().Add(time.Minute)
	for {
		output, endpointErr := creatorKubectl(ctx, "", "get", "endpoints", creatorReinvocationService,
			"-n", creatorTestNS, "-o", "jsonpath={.subsets[0].addresses[0].ip}")
		if endpointErr == nil && strings.TrimSpace(string(output)) != "" {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("wait for reinvocation webhook endpoint: %w", endpointErr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for reinvocation webhook endpoint: %w", ctx.Err())
		case <-time.After(creatorPollInterval):
		}
	}
}

func creatorVerifyPolicyAPI(ctx context.Context) error {
	expected, err := creatorExpectedAPI()
	if err != nil {
		return err
	}
	manifest, err := creatorRun(ctx, "", "helm", "get", "manifest", creatorRelease,
		"--namespace", creatorOperatorNS)
	if err != nil {
		return fmt.Errorf("read Helm release manifest: %w", err)
	}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	found := make(map[string]string)
	for {
		var document map[string]any
		decodeErr := decoder.Decode(&document)
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		if decodeErr != nil {
			return fmt.Errorf("decode Helm release manifest: %w", decodeErr)
		}
		kind, _ := document["kind"].(string)
		metadata, _ := document["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		apiVersion, _ := document["apiVersion"].(string)
		if kind == "MutatingAdmissionPolicy" || kind == "MutatingAdmissionPolicyBinding" {
			found[kind+"/"+name] = apiVersion
		}
	}
	for _, name := range []string{creatorPolicyName, contributorPolicyName} {
		for _, kind := range []string{"MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding"} {
			key := kind + "/" + name
			if found[key] != expected {
				return fmt.Errorf("Helm rendered %s as %q, want %q", key, found[key], expected)
			}
		}
	}

	version := creatorExpectedAPIVersionName(expected)
	for _, resource := range []struct {
		plural string
		name   string
	}{
		{plural: "mutatingadmissionpolicies", name: creatorPolicyName},
		{plural: "mutatingadmissionpolicies", name: contributorPolicyName},
		{plural: "mutatingadmissionpolicybindings", name: creatorPolicyName},
		{plural: "mutatingadmissionpolicybindings", name: contributorPolicyName},
	} {
		path := fmt.Sprintf("/apis/admissionregistration.k8s.io/%s/%s/%s", version, resource.plural, resource.name)
		output, getErr := creatorKubectl(ctx, "", "get", "--raw", path)
		if getErr != nil {
			return fmt.Errorf("read live %s/%s through %s: %w", resource.plural, resource.name, version, getErr)
		}
		var live map[string]any
		if unmarshalErr := json.Unmarshal(output, &live); unmarshalErr != nil {
			return fmt.Errorf("decode live %s/%s: %w", resource.plural, resource.name, unmarshalErr)
		}
		if live["apiVersion"] != expected {
			return fmt.Errorf("live %s/%s apiVersion = %q, want %q", resource.plural, resource.name,
				live["apiVersion"], expected)
		}
	}
	return nil
}

func creatorPolicyReinvocation(ctx context.Context) (string, error) {
	expected, err := creatorExpectedAPI()
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/apis/admissionregistration.k8s.io/%s/mutatingadmissionpolicies/%s",
		creatorExpectedAPIVersionName(expected), creatorPolicyName)
	output, err := creatorKubectl(ctx, "", "get", "--raw", path)
	if err != nil {
		return "", fmt.Errorf("read creator policy: %w", err)
	}
	var policy map[string]any
	if err := json.Unmarshal(output, &policy); err != nil {
		return "", fmt.Errorf("decode creator policy: %w", err)
	}
	spec, _ := policy["spec"].(map[string]any)
	reinvocation, _ := spec["reinvocationPolicy"].(string)
	return reinvocation, nil
}

func creatorManagedFieldMap(entry creatorManagedField) (map[string]any, error) {
	fields := make(map[string]any)
	if len(entry.FieldsV1) == 0 {
		return fields, nil
	}
	if err := json.Unmarshal(entry.FieldsV1, &fields); err != nil {
		return nil, fmt.Errorf("decode managedFields for %s: %w", entry.Manager, err)
	}
	return fields, nil
}

func creatorFieldPathExists(fields map[string]any, path ...string) bool {
	current := any(fields)
	for _, component := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[component]
		if !ok {
			return false
		}
	}
	return true
}

func creatorManagedFieldKey(key string) string {
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return "f:" + key
}

func creatorValidateManagedFields(object creatorObject, expected []creatorExpectedManagedField) error {
	entries := make(map[string][]creatorManagedField, len(object.Metadata.ManagedFields))
	for _, entry := range object.Metadata.ManagedFields {
		fields, err := creatorManagedFieldMap(entry)
		if err != nil {
			return err
		}
		for _, key := range []string{createdByAnnotation, createdByGroupsAnnotation, updatedByAnnotation} {
			if creatorFieldPathExists(fields, "f:metadata", "f:annotations", creatorManagedFieldKey(key)) {
				return fmt.Errorf("manager %s owns tracking annotation %s", entry.Manager, key)
			}
		}
		entries[entry.Manager] = append(entries[entry.Manager], entry)
	}
	for _, want := range expected {
		candidates := entries[want.Manager]
		if len(candidates) == 0 {
			return fmt.Errorf("managedFields does not contain manager %s", want.Manager)
		}
		matched := false
		for _, entry := range candidates {
			if entry.Operation != want.Operation {
				continue
			}
			fields, err := creatorManagedFieldMap(entry)
			if err != nil {
				return err
			}
			ownsAll := true
			for _, path := range want.Paths {
				if !creatorFieldPathExists(fields, path...) {
					ownsAll = false
					break
				}
			}
			if ownsAll {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("manager %s has no %s entry owning every expected path", want.Manager, want.Operation)
		}
	}
	return nil
}

func creatorRemoveExactFinalizer(finalizers []string, target string) []string {
	remaining := make([]string, 0, len(finalizers))
	for _, finalizer := range finalizers {
		if finalizer != target {
			remaining = append(remaining, finalizer)
		}
	}
	return remaining
}

// creatorCleanupPlan describes cleanup ordering independently of command execution.
func creatorCleanupPlan(frontendsSafe, childrenSafe, finalizerSafe bool) []string {
	plan := []string{"binddefinition", "admission-frontends"}
	if !frontendsSafe {
		return append(plan, "test-bindings", "test-roles", "test-namespaces")
	}
	plan = append(plan, "admission-policies", "reinvocation-backend")
	if childrenSafe {
		plan = append(plan, "generated-children")
	}
	if childrenSafe && finalizerSafe {
		plan = append(plan, "binddefinition-finalizer", "binddefinition")
	}
	// The exact sweep remains independent of Helm uninstall success.
	plan = append(plan, "helm-uninstall", "release-sweep")
	if finalizerSafe {
		plan = append(plan, "namespaces")
	}
	return plan
}

func creatorIsAbsentError(output []byte, err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(string(output) + " " + err.Error())
	return strings.Contains(message, "notfound") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "release: not found") ||
		strings.Contains(message, "the server doesn't have a resource type") ||
		strings.Contains(message, "the server could not find the requested resource")
}

func creatorResourceKey(resource creatorExactResource) string {
	if resource.Namespace == "" {
		return resource.Kind + "/" + resource.Name
	}
	return resource.Kind + "/" + resource.Namespace + "/" + resource.Name
}

func creatorDeleteRequest(ctx context.Context, resource creatorExactResource) error {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"delete", resource.Kind, resource.Name, "--ignore-not-found=true", "--wait=false"}
	if resource.Namespace != "" {
		args = append(args, "-n", resource.Namespace)
	}
	output, err := creatorKubectl(commandCtx, "", args...)
	if err == nil || creatorIsAbsentError(output, err) {
		return nil
	}
	return fmt.Errorf("delete %s: %w: %s", creatorResourceKey(resource), err, strings.TrimSpace(string(output)))
}

func creatorCheckResourcesAbsent(ctx context.Context, resources []creatorExactResource) (
	[]creatorExactResource,
	map[string]error,
) {
	remaining := make([]creatorExactResource, 0, len(resources))
	checkErrors := make(map[string]error)
	for _, resource := range resources {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		absent, err := creatorResourceAbsent(checkCtx, resource.Kind, resource.Name, resource.Namespace)
		cancel()
		if err != nil {
			remaining = append(remaining, resource)
			checkErrors[creatorResourceKey(resource)] = err
			continue
		}
		if !absent {
			remaining = append(remaining, resource)
		}
	}
	return remaining, checkErrors
}

func creatorWaitResourcesAbsent(ctx context.Context, resources []creatorExactResource) (
	bool,
	[]creatorExactResource,
	[]error,
) {
	for {
		remaining, checkErrors := creatorCheckResourcesAbsent(ctx, resources)
		if len(remaining) == 0 {
			return true, nil, nil
		}
		select {
		case <-ctx.Done():
			errorsFound := make([]error, 0, len(remaining))
			for _, resource := range remaining {
				key := creatorResourceKey(resource)
				if checkErr := checkErrors[key]; checkErr != nil {
					errorsFound = append(errorsFound, fmt.Errorf("confirm %s absent: %w", key, checkErr))
				} else {
					errorsFound = append(errorsFound, fmt.Errorf("%s is still present", key))
				}
			}
			return false, remaining, errorsFound
		case <-time.After(creatorPollInterval):
		}
	}
}

func creatorDeletePhase(
	parent context.Context,
	resources []creatorExactResource,
	timeout time.Duration,
) (bool, []error) {
	phaseCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	requestErrors := make(map[string]error)
	for _, resource := range resources {
		if err := creatorDeleteRequest(phaseCtx, resource); err != nil {
			requestErrors[creatorResourceKey(resource)] = err
		}
	}
	safe, remaining, waitErrors := creatorWaitResourcesAbsent(phaseCtx, resources)
	if safe {
		return true, nil
	}
	for _, resource := range remaining {
		if requestErr := requestErrors[creatorResourceKey(resource)]; requestErr != nil {
			waitErrors = append(waitErrors, requestErr)
		}
	}
	return false, waitErrors
}

func creatorDeleteAndWait(resource creatorExactResource) error {
	const timeout = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
	defer cancel()
	safe, errs := creatorDeletePhase(ctx, []creatorExactResource{resource}, timeout)
	if safe {
		return nil
	}
	return errors.Join(errs...)
}

func creatorRemoveBindDefinitionFinalizer(ctx context.Context) error {
	for range 5 {
		getCtx, cancelGet := context.WithTimeout(ctx, 10*time.Second)
		object, err := creatorGetObject(getCtx, "binddefinition", creatorBindDefinition, "")
		cancelGet()
		if err != nil {
			if creatorIsAbsentError(nil, err) {
				return nil
			}
			return err
		}
		if len(object.Metadata.Finalizers) == 0 {
			return nil
		}
		remaining := make([]string, 0, len(object.Metadata.Finalizers))
		found := false
		for _, finalizer := range object.Metadata.Finalizers {
			if finalizer == authorizationv1alpha1.BindDefinitionFinalizer {
				found = true
				continue
			}
			remaining = append(remaining, finalizer)
		}
		if !found {
			return fmt.Errorf("BindDefinition has unrelated finalizers that must be preserved: %v", remaining)
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{
			"resourceVersion": object.Metadata.ResourceVersion,
			"finalizers":      remaining,
		}})
		if err != nil {
			return fmt.Errorf("encode BindDefinition finalizer patch: %w", err)
		}
		patchCtx, cancelPatch := context.WithTimeout(ctx, 10*time.Second)
		output, patchErr := creatorKubectl(patchCtx, string(patch), "patch", "binddefinition", creatorBindDefinition,
			"--type=merge", "--patch-file=/dev/stdin")
		cancelPatch()
		if creatorIsAbsentError(output, patchErr) {
			return nil
		}
		if patchErr == nil {
			if len(remaining) > 0 {
				return fmt.Errorf("removed %s but preserved unrelated BindDefinition finalizers: %v",
					authorizationv1alpha1.BindDefinitionFinalizer, remaining)
			}
			return nil
		}
		if !strings.Contains(strings.ToLower(string(output)), "conflict") {
			return fmt.Errorf("remove exact BindDefinition finalizer: %w: %s", patchErr, strings.TrimSpace(string(output)))
		}
	}
	return fmt.Errorf("remove exact BindDefinition finalizer: retry limit reached")
}

func creatorCleanupDiagnostics(parent context.Context) {
	commands := []struct {
		filename string
		args     []string
	}{
		{filename: "creator-cleanup-resources.yaml", args: []string{"get", "all", "-n", creatorOperatorNS, "-o", "yaml"}},
		{filename: "creator-cleanup-binddefinition.yaml", args: []string{"get", "binddefinition", creatorBindDefinition, "-o", "yaml"}},
		{filename: "creator-cleanup-managed-sa.yaml", args: []string{"get", "serviceaccount", creatorManagedSA, "-n", creatorTestNS, "-o", "yaml", "--show-managed-fields=true"}},
		{filename: "creator-cleanup-policies.yaml", args: []string{"get", "mutatingadmissionpolicies,mutatingadmissionpolicybindings", "-o", "yaml"}},
		{filename: "creator-cleanup-webhook-configurations.yaml", args: []string{"get", "mutatingwebhookconfigurations,validatingwebhookconfigurations", "-o", "yaml"}},
		{filename: "creator-cleanup-reinvocation-webhook.log", args: []string{"logs", creatorReinvocationService, "-n", creatorTestNS}},
		{filename: "creator-cleanup-controller.log", args: []string{"logs", "deployment/" + creatorRelease + "-controller-manager", "-n", creatorOperatorNS, "--tail=500"}},
		{filename: "creator-cleanup-webhook-server.log", args: []string{"logs", "deployment/" + creatorRelease + "-webhook-server", "-n", creatorOperatorNS, "--tail=500"}},
	}
	phaseCtx, cancelPhase := context.WithTimeout(parent, 90*time.Second)
	defer cancelPhase()
	for _, command := range commands {
		ctx, cancel := context.WithTimeout(phaseCtx, 12*time.Second)
		output, err := creatorKubectl(ctx, "", command.args...)
		cancel()
		if err != nil {
			output = append(output, []byte("\ncommand error: "+err.Error()+"\n")...)
		}
		saveOutput(command.filename, output)
	}
}

func creatorAppendErrors(target *[]error, errs []error) {
	*target = append(*target, errs...)
}

func creatorAdmissionFrontends() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "mutatingwebhookconfiguration", Name: creatorReinvocationWebhook},
		{Kind: "mutatingwebhookconfiguration", Name: creatorRelease + "-namespace-mutating-webhook-configuration"},
		{Kind: "validatingwebhookconfiguration", Name: creatorRelease + "-namespace-validating-webhook-configuration"},
		{Kind: "validatingwebhookconfiguration", Name: creatorRelease + "-binder-validating-webhook-configuration"},
		{Kind: "mutatingadmissionpolicybinding", Name: contributorPolicyName},
		{Kind: "mutatingadmissionpolicybinding", Name: creatorPolicyName},
		{Kind: "mutatingadmissionpolicybinding", Name: creatorMigrationPolicyName},
		{Kind: "validatingadmissionpolicybinding", Name: creatorRelease + "-namespace-deletion-protection"},
	}
}

func creatorAdmissionFrontendsForRelease(release string) []creatorExactResource {
	fullname := creatorReleaseFullname(release)
	return []creatorExactResource{
		{Kind: "mutatingwebhookconfiguration", Name: fullname + "-namespace-mutating-webhook-configuration"},
		{Kind: "validatingwebhookconfiguration", Name: fullname + "-namespace-validating-webhook-configuration"},
		{Kind: "validatingwebhookconfiguration", Name: fullname + "-binder-validating-webhook-configuration"},
	}
}

func creatorAdmissionPolicies() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "mutatingadmissionpolicy", Name: contributorPolicyName},
		{Kind: "mutatingadmissionpolicy", Name: creatorPolicyName},
		{Kind: "mutatingadmissionpolicy", Name: creatorMigrationPolicyName},
		{Kind: "validatingadmissionpolicy", Name: creatorRelease + "-namespace-deletion-protection"},
	}
}

func creatorAdmissionPoliciesForRelease(release string) []creatorExactResource {
	fullname := creatorReleaseFullname(release)
	return []creatorExactResource{
		{Kind: "mutatingadmissionpolicy", Name: fullname + "-creator-tracking"},
		{Kind: "mutatingadmissionpolicybinding", Name: fullname + "-creator-tracking"},
		{Kind: "mutatingadmissionpolicy", Name: fullname + "-contributor-tracking"},
		{Kind: "mutatingadmissionpolicybinding", Name: fullname + "-contributor-tracking"},
	}
}

func creatorReinvocationBackend() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "pod", Name: creatorReinvocationService, Namespace: creatorTestNS},
		{Kind: "service", Name: creatorReinvocationService, Namespace: creatorTestNS},
		{Kind: "secret", Name: creatorReinvocationService, Namespace: creatorTestNS},
	}
}

func creatorGeneratedChildren() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "clusterrolebinding", Name: creatorManagedBinding},
		{Kind: "serviceaccount", Name: creatorManagedSA, Namespace: creatorTestNS},
	}
}

func creatorReleaseBindingResources(releases ...string) []creatorExactResource {
	release := creatorRelease
	if len(releases) > 0 {
		release = creatorReleaseFullname(releases[0])
	}
	return []creatorExactResource{
		{Kind: "clusterrolebinding", Name: release + "-auth-delegator"},
		{Kind: "clusterrolebinding", Name: release + "-controller-manager"},
		{Kind: "clusterrolebinding", Name: release + "-webhook-server"},
	}
}

func creatorReleaseRoleResources(releases ...string) []creatorExactResource {
	release := creatorRelease
	if len(releases) > 0 {
		release = creatorReleaseFullname(releases[0])
	}
	return []creatorExactResource{
		{Kind: "clusterrole", Name: release + "-controller-manager"},
		{Kind: "clusterrole", Name: release + "-webhook-server"},
	}
}

func creatorReleaseNamespacedResources(releases ...string) []creatorExactResource {
	release := creatorRelease
	if len(releases) > 0 {
		release = creatorReleaseFullname(releases[0])
	}
	return []creatorExactResource{
		{Kind: "deployment", Name: release + "-controller-manager", Namespace: creatorOperatorNS},
		{Kind: "deployment", Name: release + "-webhook-server", Namespace: creatorOperatorNS},
		{Kind: "poddisruptionbudget", Name: release + "-webhook-server", Namespace: creatorOperatorNS},
		{Kind: "service", Name: release + "-metrics", Namespace: creatorOperatorNS},
		{Kind: "service", Name: release + "-webhook-service", Namespace: creatorOperatorNS},
		{Kind: "serviceaccount", Name: release + "-controller-manager", Namespace: creatorOperatorNS},
		{Kind: "serviceaccount", Name: release + "-webhook-server", Namespace: creatorOperatorNS},
		{Kind: "secret", Name: release + "-webhook-certs", Namespace: creatorOperatorNS},
		{Kind: "rolebinding", Name: release + "-leader-election-rolebinding", Namespace: creatorOperatorNS},
		{Kind: "rolebinding", Name: release + "-webhook-secrets", Namespace: creatorOperatorNS},
		{Kind: "role", Name: release + "-leader-election-role", Namespace: creatorOperatorNS},
		{Kind: "role", Name: release + "-webhook-secrets", Namespace: creatorOperatorNS},
	}
}

func creatorReleaseFullname(release string) string {
	fullname := release
	if !strings.Contains(release, "auth-operator") {
		fullname += "-auth-operator"
	}
	if len(fullname) > 63 {
		fullname = fullname[:63]
	}
	return strings.TrimSuffix(fullname, "-")
}

func creatorTestBindingResources() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "clusterrolebinding", Name: creatorCreatorBinding},
		{Kind: "clusterrolebinding", Name: creatorEditorBinding},
		{Kind: "clusterrolebinding", Name: creatorUserBinding},
	}
}

func creatorTestRoleResources() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "clusterrole", Name: creatorCreatorRole},
		{Kind: "clusterrole", Name: creatorEditorRole},
		{Kind: "clusterrole", Name: creatorUserRole},
	}
}

func creatorTestNamespacedResources() []creatorExactResource {
	return []creatorExactResource{
		{Kind: "rolebinding", Name: creatorRoleBinding, Namespace: creatorTestNS},
		{Kind: "role", Name: creatorRoleName, Namespace: creatorTestNS},
		{Kind: "serviceaccount", Name: creatorRequesterSA, Namespace: creatorTestNS},
		{Kind: "serviceaccount", Name: creatorTargetSA, Namespace: creatorTestNS},
		{Kind: "serviceaccount", Name: creatorEditorASA, Namespace: creatorTestNS},
		{Kind: "serviceaccount", Name: creatorEditorBSA, Namespace: creatorTestNS},
	}
}

func creatorAllExactResources() []creatorExactResource {
	resources := make([]creatorExactResource, 0, 40)
	resources = append(resources, creatorAdmissionFrontends()...)
	resources = append(resources, creatorAdmissionPolicies()...)
	resources = append(resources, creatorReinvocationBackend()...)
	resources = append(resources, creatorGeneratedChildren()...)
	resources = append(resources, creatorReleaseBindingResources()...)
	resources = append(resources, creatorReleaseRoleResources()...)
	resources = append(resources, creatorReleaseNamespacedResources()...)
	resources = append(resources, creatorTestBindingResources()...)
	resources = append(resources, creatorTestRoleResources()...)
	resources = append(resources, creatorTestNamespacedResources()...)
	resources = append(resources, creatorExactResource{Kind: "binddefinition", Name: creatorBindDefinition})
	for _, namespace := range creatorNamespaces {
		resources = append(resources, creatorExactResource{Kind: "namespace", Name: namespace})
	}
	return resources
}

func creatorCleanup(collectDiagnostics bool) []error {
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelCleanup()
	cleanupErrors := make([]error, 0)
	appendError := func(err error) {
		if err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	validationCtx, cancelValidation := context.WithTimeout(cleanupCtx, 20*time.Second)
	validationErr := creatorValidateIsolation(validationCtx)
	cancelValidation()
	if validationErr != nil {
		return []error{fmt.Errorf("refuse creator cleanup outside the exact dedicated cluster: %w", validationErr)}
	}
	if collectDiagnostics {
		creatorCleanupDiagnostics(cleanupCtx)
	}

	// Ask the live controller to finalize its exact custom resource first.
	appendError(creatorDeleteRequest(cleanupCtx, creatorExactResource{Kind: "binddefinition", Name: creatorBindDefinition}))
	waitBDCtx, cancelWaitBD := context.WithTimeout(cleanupCtx, 25*time.Second)
	_, remainingBindDefinitions, initialBindErrors := creatorWaitResourcesAbsent(
		waitBDCtx, []creatorExactResource{{Kind: "binddefinition", Name: creatorBindDefinition}})
	_ = remainingBindDefinitions
	creatorAppendErrors(&cleanupErrors, initialBindErrors)
	cancelWaitBD()

	frontendsSafe, frontendErrors := creatorDeletePhase(cleanupCtx, creatorAdmissionFrontends(), 75*time.Second)
	creatorAppendErrors(&cleanupErrors, frontendErrors)
	if !frontendsSafe {
		appendError(fmt.Errorf("admission frontend barrier failed; preserving policies, backends, release resources, and namespaces"))
		_, bindingErrors := creatorDeletePhase(cleanupCtx, creatorTestBindingResources(), 30*time.Second)
		creatorAppendErrors(&cleanupErrors, bindingErrors)
		_, roleErrors := creatorDeletePhase(cleanupCtx, creatorTestRoleResources(), 30*time.Second)
		creatorAppendErrors(&cleanupErrors, roleErrors)
		_, namespacedErrors := creatorDeletePhase(cleanupCtx, creatorTestNamespacedResources(), 30*time.Second)
		creatorAppendErrors(&cleanupErrors, namespacedErrors)
		creatorRemoveLocalWebhookImage(cleanupCtx, &cleanupErrors)
		return cleanupErrors
	}

	// Policies are safe to remove only after every binding is confirmed absent.
	_, policyErrors := creatorDeletePhase(cleanupCtx, creatorAdmissionPolicies(), 60*time.Second)
	creatorAppendErrors(&cleanupErrors, policyErrors)
	_, backendErrors := creatorDeletePhase(cleanupCtx, creatorReinvocationBackend(), 45*time.Second)
	creatorAppendErrors(&cleanupErrors, backendErrors)

	childrenSafe, childErrors := creatorDeletePhase(cleanupCtx, creatorGeneratedChildren(), 45*time.Second)
	creatorAppendErrors(&cleanupErrors, childErrors)
	bindDefinitionSafe := false
	if childrenSafe {
		finalizerErr := creatorRemoveBindDefinitionFinalizer(cleanupCtx)
		appendError(finalizerErr)
		if finalizerErr == nil {
			bindDefinitionSafe, childErrors = creatorDeletePhase(cleanupCtx,
				[]creatorExactResource{{Kind: "binddefinition", Name: creatorBindDefinition}}, 45*time.Second)
			creatorAppendErrors(&cleanupErrors, childErrors)
		} else {
			appendError(fmt.Errorf("BindDefinition finalizer barrier failed; preserving the BindDefinition and namespaces"))
		}
	} else {
		appendError(fmt.Errorf("generated child barrier failed; preserving the exact BindDefinition finalizer"))
	}

	uninstallCtx, cancelUninstall := context.WithTimeout(cleanupCtx, 2*time.Minute)
	uninstallOutput, uninstallErr := creatorRun(uninstallCtx, "", "helm", "uninstall", creatorRelease,
		"--namespace", creatorOperatorNS, "--ignore-not-found", "--wait", "--timeout", "90s")
	cancelUninstall()
	if uninstallErr != nil && !creatorIsAbsentError(uninstallOutput, uninstallErr) {
		appendError(fmt.Errorf("helm uninstall: %w: %s", uninstallErr, strings.TrimSpace(string(uninstallOutput))))
	}

	// The release sweep is safe because all admission frontends are absent.
	for _, phase := range []struct {
		resources []creatorExactResource
		timeout   time.Duration
	}{
		{resources: creatorReleaseBindingResources(), timeout: 45 * time.Second},
		{resources: creatorReleaseRoleResources(), timeout: 45 * time.Second},
		{resources: creatorReleaseNamespacedResources(), timeout: 60 * time.Second},
		{resources: creatorTestBindingResources(), timeout: 45 * time.Second},
		{resources: creatorTestRoleResources(), timeout: 45 * time.Second},
		{resources: creatorTestNamespacedResources(), timeout: 45 * time.Second},
	} {
		_, phaseErrors := creatorDeletePhase(cleanupCtx, phase.resources, phase.timeout)
		creatorAppendErrors(&cleanupErrors, phaseErrors)
	}

	if bindDefinitionSafe {
		namespaces := make([]creatorExactResource, 0, len(creatorNamespaces))
		for _, namespace := range creatorNamespaces {
			namespaces = append(namespaces, creatorExactResource{Kind: "namespace", Name: namespace})
		}
		_, namespaceErrors := creatorDeletePhase(cleanupCtx, namespaces, 90*time.Second)
		creatorAppendErrors(&cleanupErrors, namespaceErrors)
	} else {
		appendError(fmt.Errorf("BindDefinition barrier failed; preserving namespaces"))
	}

	statusCtx, cancelStatus := context.WithTimeout(cleanupCtx, 15*time.Second)
	statusOutput, statusErr := creatorRun(statusCtx, "", "helm", "status", creatorRelease, "--namespace", creatorOperatorNS)
	cancelStatus()
	if statusErr == nil || !creatorIsAbsentError(statusOutput, statusErr) {
		appendError(fmt.Errorf("Helm release %s is still visible: %s", creatorRelease, strings.TrimSpace(string(statusOutput))))
	}

	verifyCtx, cancelVerify := context.WithTimeout(cleanupCtx, 45*time.Second)
	allAbsent, _, verifyErrors := creatorWaitResourcesAbsent(verifyCtx, creatorAllExactResources())
	cancelVerify()
	if !allAbsent {
		creatorAppendErrors(&cleanupErrors, verifyErrors)
	}
	creatorRemoveLocalWebhookImage(cleanupCtx, &cleanupErrors)
	if cleanupCtx.Err() != nil {
		appendError(fmt.Errorf("creator cleanup exceeded its 10 minute deadline: %w", cleanupCtx.Err()))
	}
	return cleanupErrors
}

func creatorRemoveLocalWebhookImage(ctx context.Context, cleanupErrors *[]error) {
	imageCtx, cancelImage := context.WithTimeout(ctx, 30*time.Second)
	removeOutput, removeErr := creatorRun(imageCtx, "", "docker", "image", "rm", creatorReinvocationImage)
	cancelImage()
	if removeErr != nil && !creatorDockerImageKnownAbsent(removeOutput) {
		*cleanupErrors = append(*cleanupErrors,
			fmt.Errorf("remove test webhook image: %w: %s", removeErr, strings.TrimSpace(string(removeOutput))))
	}
	verifyCtx, cancelVerify := context.WithTimeout(ctx, 10*time.Second)
	imageOutput, imageErr := creatorRun(verifyCtx, "", "docker", "image", "inspect", creatorReinvocationImage)
	cancelVerify()
	if imageErr == nil {
		*cleanupErrors = append(*cleanupErrors, fmt.Errorf("test webhook image %s still exists", creatorReinvocationImage))
	} else if !creatorDockerImageKnownAbsent(imageOutput) {
		*cleanupErrors = append(*cleanupErrors, fmt.Errorf("inspect test webhook image: %w", imageErr))
	}
}

func creatorDockerImageKnownAbsent(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "no such image") || strings.Contains(message, "no such object")
}

func creatorFormatErrors(errs []error) string {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "\n")
}

func creatorExpectedAPI() (string, error) {
	expected := os.Getenv("E2E_CREATOR_TRACKING_API_VERSION")
	switch expected {
	case "admissionregistration.k8s.io/v1", "admissionregistration.k8s.io/v1beta1":
		return expected, nil
	case "":
		return "", fmt.Errorf("E2E_CREATOR_TRACKING_API_VERSION is required")
	default:
		return "", fmt.Errorf("unsupported creator tracking API version %q", expected)
	}
}

func creatorExpectedAPIVersionName(expected string) string {
	return strings.TrimPrefix(expected, "admissionregistration.k8s.io/")
}
