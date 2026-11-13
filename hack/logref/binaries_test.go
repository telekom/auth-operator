// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package logref

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// binaries lists every main package in the repository. Each one with smoke
// arguments takes the shared logging flags and is run with --log-format=json
// on an input that makes it fail right after logging.
type binary struct {
	dir, name string
	smoke     []string // nil: does not take the logging flags (see doc)
	message   string   // msg of the error line the smoke run must log
}

var binaries = []binary{
	{".", "auth-operator controller", []string{"controller"}, "command failed"},
	{".", "auth-operator webhook", []string{"webhook"}, "command failed"},
	{"hack", "verify-rendered-rbac", []string{"missing.yaml"}, "rendered RBAC verification failed"},
	{"hack/benchmark", "creator-tracking-benchmark", []string{"--concurrency=0"}, "creator-tracking benchmark failed"},
	{"test/e2e/testserver/creator-reinvocation-webhook", "creator-reinvocation-webhook", nil, ""},
}

// mainDirs returns the directories that hold a non-test main package.
func mainDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "bin" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		if f.Name.Name == "main" && !slices.Contains(dirs, filepath.ToSlash(rel)) {
			dirs = append(dirs, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// TestEveryBinaryIsDocumented fails when a main package is missing from the
// binaries table or from the "## Binaries" table of the logging reference.
func TestEveryBinaryIsDocumented(t *testing.T) {
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	documented := tableKeys(t, string(data), "## Binaries")
	for _, dir := range mainDirs(t) {
		if !slices.ContainsFunc(binaries, func(b binary) bool { return b.dir == dir }) {
			t.Errorf("main package %s is not in the binaries table of %s", dir, "hack/logref/binaries_test.go")
		}
	}
	for _, b := range binaries {
		if !slices.Contains(documented, b.name) {
			t.Errorf("binary %q is not in the \"## Binaries\" table of %s", b.name, docPath)
		}
	}
}

// TestBinariesLogJSON builds every binary that takes the logging flags and
// checks that a failing run with --log-format=json writes only JSON lines,
// including the expected error line.
func TestBinariesLogJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("builds every binary")
	}
	tmp := t.TempDir()
	built := map[string]string{}
	for _, b := range binaries {
		if b.smoke == nil {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			bin, ok := built[b.dir]
			if !ok {
				bin = filepath.Join(tmp, strings.ReplaceAll(b.dir, "/", "_")+".bin")
				build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./"+b.dir) // #nosec G204
				build.Dir = root
				if out, err := build.CombinedOutput(); err != nil {
					t.Fatalf("build %s: %v\n%s", b.dir, err, out)
				}
				built[b.dir] = bin
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, append([]string{"--log-format=json"}, b.smoke...)...) // #nosec G204
			cmd.Dir = tmp
			cmd.Env = append(os.Environ(), "KUBECONFIG="+filepath.Join(tmp, "missing-kubeconfig"), "KUBERNETES_SERVICE_HOST=",
				"LOG_FORMAT=", "LOG_LEVEL=", "LOG_VERBOSITY=")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				t.Fatalf("expected the smoke run to fail, stderr:\n%s", stderr.String())
			}
			var msgs []string
			scanner := bufio.NewScanner(&stderr)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			for scanner.Scan() {
				var line map[string]any
				if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
					t.Fatalf("stderr line is not JSON: %v\n%s", err, scanner.Text())
				}
				for _, k := range []string{"level", "ts", "msg"} {
					if _, ok := line[k]; !ok {
						t.Errorf("line has no %q key: %s", k, scanner.Text())
					}
				}
				if line["level"] == "error" {
					msgs = append(msgs, line["msg"].(string))
				}
			}
			if !slices.Contains(msgs, b.message) {
				t.Errorf("error messages %q do not include %q", msgs, b.message)
			}
		})
	}
}
