// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
	"github.com/telekom/auth-operator/pkg/indexer"
)

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		env     map[string]string
		want    Options
		wantErr string
	}{
		{name: "defaults", want: Options{Format: "text", Verbosity: 2}},
		{name: "flags", args: []string{"--log-format=json", "-v=4"}, want: Options{Format: "json", Verbosity: 4}},
		{name: "env", env: map[string]string{EnvFormat: "json", EnvVerbosity: "3"}, want: Options{Format: "json", Verbosity: 3}},
		{
			name: "flag wins over env", args: []string{"--verbosity=1", "--log-format=text"},
			env: map[string]string{EnvFormat: "json", EnvVerbosity: "3"}, want: Options{Format: "text", Verbosity: 1},
		},
		{name: "named level", args: []string{"--log-level=error"}, want: Options{Format: "text", Level: "error", Verbosity: ErrorsOnly}},
		{name: "named level from env", env: map[string]string{EnvLevel: "debug"}, want: Options{Format: "text", Level: "debug", Verbosity: 4}},
		{name: "level agrees with verbosity", args: []string{"--log-level=info", "--verbosity=0"}, want: Options{Format: "text", Level: "info", Verbosity: 0}},
		{name: "level conflicts with verbosity", args: []string{"--log-level=info", "--verbosity=2"}, wantErr: "conflicts"},
		{name: "level conflicts with env verbosity", args: []string{"--log-level=debug"}, env: map[string]string{EnvVerbosity: "2"}, wantErr: "conflicts"},
		{name: "unknown level", args: []string{"--log-level=trace"}, wantErr: "invalid log level"},
		{name: "unknown format", args: []string{"--log-format=xml"}, wantErr: "invalid log format"},
		{name: "bad env verbosity", env: map[string]string{EnvVerbosity: "high"}, wantErr: EnvVerbosity},
		{name: "negative verbosity", args: []string{"-v=-1"}, wantErr: "negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{EnvFormat, EnvLevel, EnvVerbosity} {
				t.Setenv(k, tc.env[k])
			}
			var o Options
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			o.BindFlags(fs, 2)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			err := o.Resolve(Visited(fs))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Resolve() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o != tc.want {
				t.Fatalf("Resolve() = %+v, want %+v", o, tc.want)
			}
		})
	}
}

func jsonLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("log line is not JSON: %v\n%s", err, scanner.Text())
		}
		lines = append(lines, entry)
	}
	return lines
}

func TestJSONLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		verbosity int
		want      []string
	}{
		{ErrorsOnly, []string{"error"}},
		{0, []string{"v0", "error"}},
		{2, []string{"v0", "v1", "v2", "error"}},
	} {
		var buf bytes.Buffer
		log, err := Options{Format: "json", Verbosity: tc.verbosity}.Logger(&buf)
		if err != nil {
			t.Fatal(err)
		}
		log.Info("v0")
		log.V(1).Info("v1")
		log.V(2).Info("v2")
		log.V(3).Info("v3")
		log.Error(nil, "error")
		lines := jsonLines(t, &buf)
		got := make([]string, 0, len(lines))
		for _, l := range lines {
			got = append(got, l["msg"].(string))
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("verbosity %d logged %v, want %v", tc.verbosity, got, tc.want)
		}
	}
}

// TestJSONLoggerDoesNotSample guards against zap sampling, which drops
// repeated messages after the first 100 per second.
func TestJSONLoggerDoesNotSample(t *testing.T) {
	for _, v := range []int{ErrorsOnly, 0, 1} {
		var buf bytes.Buffer
		log, err := Options{Format: "json", Verbosity: v}.Logger(&buf)
		if err != nil {
			t.Fatal(err)
		}
		for range 1000 {
			log.Info("authorization decision", "decision", "denied", "user", "alice")
			log.Error(nil, "repeated error")
		}
		want := 2000
		if v == ErrorsOnly {
			want = 1000
		}
		if got := len(jsonLines(t, &buf)); got != want {
			t.Errorf("verbosity %d: 1000 identical calls of each message wrote %d lines, want %d", v, got, want)
		}
	}
}

// lockedBuffer is written by the HTTP server goroutine and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestJSONLoggerStdlibAndTLSHandshakeErrors checks that net/http servers
// without an ErrorLog, like controller-runtime's webhook and metrics servers,
// log TLS handshake errors as JSON.
func TestJSONLoggerStdlibAndTLSHandshakeErrors(t *testing.T) {
	t.Cleanup(func() {
		stdlog.SetOutput(os.Stderr)
		stdlog.SetFlags(stdlog.LstdFlags)
	})
	var out lockedBuffer
	if _, err := (Options{Format: "json"}).Logger(&out); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "TLS handshake error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %v\n%s", err, line)
		}
		msg, _ := entry["msg"].(string)
		if strings.Contains(msg, "TLS handshake error") && entry["logger"] == "stdlib" && entry["level"] == "error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no JSON TLS handshake error line, got:\n%s", out.String())
	}
}

func TestErrorsOnlySink(t *testing.T) {
	var out []string
	base := funcr.New(func(prefix, args string) { out = append(out, prefix+" "+args) }, funcr.Options{Verbosity: 9})
	log := logr.New(errorsOnly{base.GetSink()}).WithName("n").WithValues("k", "v")
	log.Info("info")
	log.V(1).Info("debug")
	log.Error(nil, "error")
	if len(out) != 1 || !strings.Contains(out[0], `"msg"="error"`) || !strings.Contains(out[0], `"k"="v"`) {
		t.Fatalf("errorsOnly logged %q, want only the error line with its values", out)
	}
}

// TestJSONDenyDecision drives a denied SubjectAccessReview through the
// authorizer with the --log-format=json logger at verbosity 0 and parses the
// resulting authorization decision line.
func TestJSONDenyDecision(t *testing.T) {
	var buf bytes.Buffer
	log, err := Options{Format: "json"}.Logger(&buf)
	if err != nil {
		t.Fatal(err)
	}

	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	wa := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-wa"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authorizationv1alpha1.Principal{{User: "baduser"}},
			ResourceRules:    []authzv1.ResourceRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(wa).
		WithIndex(&authorizationv1alpha1.WebhookAuthorizer{}, indexer.WebhookAuthorizerHasNamespaceSelectorField, indexer.WebhookAuthorizerHasNamespaceSelectorFunc).
		WithIndex(&authorizationv1alpha1.BindDefinition{}, indexer.BindDefinitionBridgeSubjectField, indexer.BindDefinitionBridgeSubjectFunc).
		Build()
	handler := &webhooks.Authorizer{AllowUnauthenticatedAuthorize: true, Client: cl, Log: log.WithName("Authorizer")}

	body, err := json.Marshal(authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User:               "baduser",
		ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var decisions []map[string]any
	for _, l := range jsonLines(t, &buf) {
		if l["msg"] == "authorization decision" {
			decisions = append(decisions, l)
		}
	}
	if len(decisions) != 1 {
		t.Fatalf("expected one decision line at verbosity 0, got %d:\n%s", len(decisions), buf.String())
	}
	got := decisions[0]
	if got["user"] != "baduser" || got["decision"] != "denied" || got["authorizer"] != "deny-wa" || got["logger"] != "Authorizer" {
		t.Errorf("unexpected decision fields: %v", got)
	}
	if ts, _ := got["ts"].(string); got["level"] != "info" || !strings.Contains(ts, "T") {
		t.Errorf("expected level=info and an RFC 3339 ts, got %v", got)
	}
}
