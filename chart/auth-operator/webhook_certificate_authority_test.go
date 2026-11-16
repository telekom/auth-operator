// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authoperator_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	webhookCertsSecretName = "auth-operator-webhook-certs"
	caCertificateValue     = "webhookServer.certificateAuthority.certificate"
	caPrivateKeyValue      = "webhookServer.certificateAuthority.privateKey"
	caAdditionalValue      = "webhookServer.certificateAuthority.additionalTrustedCertificates"
)

func TestWebhookCertificateAuthoritySchemaDefaults(t *testing.T) {
	data, err := os.ReadFile("values.schema.json")
	if err != nil {
		t.Fatalf("read values schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse values schema: %v", err)
	}

	ca := nestedMap(t, schema, "properties", "webhookServer", "properties", "certificateAuthority")
	if additional, ok := ca["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("certificateAuthority must not allow additional properties, got %v", ca["additionalProperties"])
	}
	description, _ := ca["description"].(string)
	if !strings.Contains(description, `DNS name "cert"`) || !strings.Contains(description, "PKCS#1") {
		t.Fatalf("certificateAuthority description should document the cert rotator requirements, got %q", description)
	}
	for _, name := range []string{"certificate", "privateKey", "additionalTrustedCertificates"} {
		prop := nestedMap(t, ca, "properties", name)
		if prop["type"] != "string" || prop["default"] != "" {
			t.Fatalf("certificateAuthority.%s should be a string defaulting to empty, got type %v default %v",
				name, prop["type"], prop["default"])
		}
	}
}

func TestWebhookCertsSecretShouldHaveNoDataWithoutCertificateAuthority(t *testing.T) {
	requireHelm(t)

	documents := decodeYAMLDocuments(t, []byte(helmTemplate(t, "--set", "namespaceAdmission.enabled=true")))

	secret := selectCreatorDocument(t, documents, "Secret", webhookCertsSecretName)
	if _, ok := secret["data"]; ok {
		t.Fatalf("webhook certs Secret should leave data to the cert rotator, got %v", secret["data"])
	}
	for _, webhook := range renderedWebhooks(t, documents) {
		if _, ok := nestedObject(t, webhook, "clientConfig")["caBundle"]; ok {
			t.Fatalf("webhook %v should have no caBundle on a fresh install", webhook["name"])
		}
	}
}

func TestWebhookCertsSecretShouldContainTheProvidedCertificateAuthority(t *testing.T) {
	requireHelm(t)
	certificatePath, privateKeyPath := writeTestCertificateAuthority(t)
	certificate := readFile(t, certificatePath)
	privateKey := readFile(t, privateKeyPath)

	documents := decodeYAMLDocuments(t, []byte(helmTemplate(t,
		"--set", "namespaceAdmission.enabled=true",
		"--set-file", caCertificateValue+"="+certificatePath,
		"--set-file", caPrivateKeyValue+"="+privateKeyPath,
	)))

	data := nestedObject(t, selectCreatorDocument(t, documents, "Secret", webhookCertsSecretName), "data")
	if keys := mapKeys(data); !slices.Equal(keys, []string{"ca.crt", "ca.key"}) {
		t.Fatalf("webhook certs Secret should only contain the CA and leave tls.* to the cert rotator, got keys %v", keys)
	}
	if got := decodeBase64(t, data["ca.crt"]); got != certificate {
		t.Fatalf("ca.crt should contain the provided certificate, got %q", got)
	}
	if got := decodeBase64(t, data["ca.key"]); got != privateKey {
		t.Fatal("ca.key should contain the provided private key")
	}
}

func TestWebhookConfigurationsShouldTrustTheProvidedCertificateAuthority(t *testing.T) {
	requireHelm(t)
	certificatePath, privateKeyPath := writeTestCertificateAuthority(t)
	certificate := readFile(t, certificatePath)

	documents := decodeYAMLDocuments(t, []byte(helmTemplate(t,
		"--set", "namespaceAdmission.enabled=true",
		"--set-file", caCertificateValue+"="+certificatePath,
		"--set-file", caPrivateKeyValue+"="+privateKeyPath,
	)))

	webhooks := renderedWebhooks(t, documents)
	if len(webhooks) == 0 {
		t.Fatal("expected rendered webhooks")
	}
	for _, webhook := range webhooks {
		if got := decodeBase64(t, nestedObject(t, webhook, "clientConfig")["caBundle"]); got != certificate {
			t.Fatalf("webhook %v should trust the provided CA, got caBundle %q", webhook["name"], got)
		}
	}
}

// During a staged CA rotation the admission webhooks must trust both CAs. The cert rotator signs with the
// first certificate in ca.crt, keeps the rest unchanged and injects the whole ca.crt as caBundle, so the
// chart must render the signing CA first and the same bundle everywhere.
func TestWebhookCertificateAuthorityShouldTrustAdditionalCertificates(t *testing.T) {
	requireHelm(t)
	certificatePath, privateKeyPath := writeTestCertificateAuthority(t)
	previousPath, _ := writeTestCertificateAuthority(t)
	certificate := readFile(t, certificatePath)
	previous := readFile(t, previousPath)
	want := strings.TrimSpace(certificate) + "\n" + strings.TrimSpace(previous) + "\n"

	documents := decodeYAMLDocuments(t, []byte(helmTemplate(t,
		"--set", "namespaceAdmission.enabled=true",
		"--set-file", caCertificateValue+"="+certificatePath,
		"--set-file", caPrivateKeyValue+"="+privateKeyPath,
		"--set-file", caAdditionalValue+"="+previousPath,
	)))

	data := nestedObject(t, selectCreatorDocument(t, documents, "Secret", webhookCertsSecretName), "data")
	if got := decodeBase64(t, data["ca.crt"]); got != want {
		t.Fatalf("ca.crt should contain the signing CA followed by the additional CA, got %q", got)
	}
	if got := decodeBase64(t, data["ca.key"]); got != readFile(t, privateKeyPath) {
		t.Fatal("ca.key should contain the provided private key")
	}
	webhooks := renderedWebhooks(t, documents)
	if len(webhooks) == 0 {
		t.Fatal("expected rendered webhooks")
	}
	for _, webhook := range webhooks {
		if got := decodeBase64(t, nestedObject(t, webhook, "clientConfig")["caBundle"]); got != want {
			t.Fatalf("webhook %v should trust both CAs, got caBundle %q", webhook["name"], got)
		}
	}
}

func TestWebhookCertificateAuthorityShouldRequireCertificateForAdditionalCertificates(t *testing.T) {
	requireHelm(t)
	previousPath, _ := writeTestCertificateAuthority(t)
	args := []string{"--set-file", caAdditionalValue + "=" + previousPath}

	t.Run("schema", func(t *testing.T) {
		assertHelmTemplateFails(t, "minLength", args...)
	})
	t.Run("template when the schema is skipped", func(t *testing.T) {
		assertHelmTemplateFails(t, "additionalTrustedCertificates requires", append([]string{"--skip-schema-validation"}, args...)...)
	})
	t.Run("schema rejects a private key", func(t *testing.T) {
		certificatePath, privateKeyPath := writeTestCertificateAuthority(t)
		assertHelmTemplateFails(t, "does not match pattern",
			"--set-file", caCertificateValue+"="+certificatePath,
			"--set-file", caPrivateKeyValue+"="+privateKeyPath,
			"--set-file", caAdditionalValue+"="+privateKeyPath,
		)
	})
}

func TestWebhookCertificateAuthorityShouldRequireCertificateAndPrivateKeyTogether(t *testing.T) {
	requireHelm(t)
	certificatePath, privateKeyPath := writeTestCertificateAuthority(t)

	tests := []struct {
		name string
		args []string
	}{
		{"only the certificate", []string{"--set-file", caCertificateValue + "=" + certificatePath}},
		{"only the private key", []string{"--set-file", caPrivateKeyValue + "=" + privateKeyPath}},
		{"the certificate with an empty private key", []string{
			"--set-file", caCertificateValue + "=" + certificatePath, "--set", caPrivateKeyValue + "=",
		}},
	}
	for _, tt := range tests {
		t.Run("schema should reject "+tt.name, func(t *testing.T) {
			assertHelmTemplateFails(t, "minLength", tt.args...)
		})
		t.Run("template should reject "+tt.name+" when the schema is skipped", func(t *testing.T) {
			assertHelmTemplateFails(t, "must be set together", append([]string{"--skip-schema-validation"}, tt.args...)...)
		})
	}
}

// The cert rotator keeps a CA with any parseable key, but signs the serving certificate only with a
// PKCS#1 RSA key. Other key formats must therefore fail the render instead of a webhook that never
// becomes ready.
func TestWebhookCertificateAuthorityShouldRejectPrivateKeysTheRotatorCannotSignWith(t *testing.T) {
	requireHelm(t)
	certificatePath, _ := writeTestCertificateAuthority(t)
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}

	tests := []struct {
		name  string
		block *pem.Block
	}{
		{"a PKCS#8 RSA key", &pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8}},
		{"an EC key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecSEC1}},
	}
	for _, tt := range tests {
		privateKeyPath := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-")+".key")
		writeTestFile(t, privateKeyPath, string(pem.EncodeToMemory(tt.block)))
		args := []string{
			"--set-file", caCertificateValue + "=" + certificatePath,
			"--set-file", caPrivateKeyValue + "=" + privateKeyPath,
		}
		t.Run("schema should reject "+tt.name, func(t *testing.T) {
			assertHelmTemplateFails(t, "does not match pattern", args...)
		})
		t.Run("template should reject "+tt.name+" when the schema is skipped", func(t *testing.T) {
			assertHelmTemplateFails(t, "must be a PKCS#1 RSA key", append([]string{"--skip-schema-validation"}, args...)...)
		})
	}
}

func TestWebhookCertificateAuthorityShouldAcceptARemovedPrivateKeyWithoutCertificate(t *testing.T) {
	requireHelm(t)

	documents := decodeYAMLDocuments(t, []byte(helmTemplate(t, "--set", caPrivateKeyValue+"=null")))

	if _, ok := selectCreatorDocument(t, documents, "Secret", webhookCertsSecretName)["data"]; ok {
		t.Fatal("webhook certs Secret should have no data without a CA")
	}
}

func renderedWebhooks(t *testing.T, documents []map[string]any) []map[string]any {
	t.Helper()
	var webhooks []map[string]any
	for _, document := range documents {
		if document["kind"] != "ValidatingWebhookConfiguration" && document["kind"] != "MutatingWebhookConfiguration" {
			continue
		}
		for _, webhook := range nestedSlice(t, document, "webhooks") {
			webhooks = append(webhooks, schemaObject(t, webhook, "webhooks[]"))
		}
	}
	return webhooks
}

// writeTestCertificateAuthority writes a CA in the format the cert rotator keeps: self-signed, RSA with a
// PKCS#1 key and the DNS name "cert".
func writeTestCertificateAuthority(t *testing.T) (certificatePath, privateKeyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert"},
		DNSNames:              []string{"cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	dir := t.TempDir()
	certificatePath = filepath.Join(dir, "ca.crt")
	privateKeyPath = filepath.Join(dir, "ca.key")
	writeTestFile(t, certificatePath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeTestFile(t, privateKeyPath, string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})))
	return certificatePath, privateKeyPath
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func decodeBase64(t *testing.T, value any) string {
	t.Helper()
	encoded, ok := value.(string)
	if !ok {
		t.Fatalf("expected a base64 string, got %T", value)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return string(decoded)
}

func mapKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
