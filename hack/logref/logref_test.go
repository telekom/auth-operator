// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package logref keeps docs/logging-reference.md in sync with the logger call
// sites. The generated message catalog is rewritten with
//
//	go test ./hack/logref -update
//
// and every other run fails when the catalog, the component map or the
// hand-written field tables drift from the code.
package logref

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the generated catalog in docs/logging-reference.md")

const (
	root      = "../.."
	docPath   = root + "/docs/logging-reference.md"
	beginMark = "<!-- BEGIN GENERATED LOG CATALOG: go test ./hack/logref -update -->"
	endMark   = "<!-- END GENERATED LOG CATALOG -->"
)

// sourceDirs hold the code of every binary that takes the logging flags.
var sourceDirs = []string{"api", "cmd", "internal", "pkg", "hack"}

// components maps a source path prefix to the documented component and the
// binary or auth-operator command it runs in. Every file with a log call must match.
var components = []struct{ prefix, name, process string }{
	{"cmd/root.go", "Startup", "controller, webhook"},
	{"cmd/controller.go", "Controller manager setup", "controller"},
	{"cmd/webhook.go", "Webhook server setup", "webhook"},
	{"internal/controller/", "Reconcilers", "controller"},
	{"internal/webhook/authorization/webhook_authorizer.go", "Authorization webhook (/authorize)", "webhook"},
	{"internal/webhook/authorization/binddefinition_bridge.go", "Authorization webhook (/authorize)", "webhook"},
	{"internal/webhook/authorization/emergency_authorization.go", "Authorization webhook (/authorize)", "webhook"},
	{"internal/webhook/authorization/", "Namespace admission webhooks", "webhook"},
	{"api/", "CRD validation webhooks", "webhook"},
	{"pkg/discovery/", "API discovery", "controller"},
	{"pkg/capabilities/", "Capability detection", "controller"},
	{"hack/verify-rendered-rbac.go", "Rendered RBAC verification", "verify-rendered-rbac"},
	{"hack/benchmark/", "Creator-tracking benchmark", "creator-tracking-benchmark"},
}

// loggerBase matches the receivers that hold a logr.Logger.
var loggerBase = regexp.MustCompile(`^(logger|log|setupLog|wa\.Log|w\.log|log\.FromContext\(ctx\))$`)

type entry struct {
	file, level, msg string
	keys             []string
}

func componentOf(file string) (name, process string, ok bool) {
	for _, c := range components {
		if strings.HasPrefix(file, c.prefix) {
			return c.name, c.process, true
		}
	}
	return "", "", false
}

func render(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	return b.String()
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// message renders the msg argument: a literal, the format of fmt.Sprintf, or
// <name> for a variable.
func message(fset *token.FileSet, e ast.Expr) (string, bool) {
	if s, ok := stringLit(e); ok {
		return s, true
	}
	if call, ok := e.(*ast.CallExpr); ok && render(fset, call.Fun) == "fmt.Sprintf" && len(call.Args) > 0 {
		return stringLit(call.Args[0])
	}
	if id, ok := e.(*ast.Ident); ok {
		return "<" + id.Name + ">", true
	}
	if bin, ok := e.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		x, okX := message(fset, bin.X)
		y, okY := message(fset, bin.Y)
		return x + y, okX && okY
	}
	return "", false
}

// collect parses the production sources and returns every logr Info and
// Error call, or the problems that stop it from being documented.
func collect(t *testing.T) ([]entry, map[string][]string) {
	t.Helper()
	fset := token.NewFileSet()
	var entries []entry
	withValues := map[string][]string{}
	var problems []string
	for _, dir := range sourceDirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			// Each top-level function, or function literal in a declaration
			// such as a cobra hook, is the scope for spread key/value slices.
			var bodies []*ast.BlockStmt
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					if fn.Body != nil {
						bodies = append(bodies, fn.Body)
					}
					continue
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok {
						bodies = append(bodies, lit.Body)
						return false
					}
					return true
				})
			}
			for _, body := range bodies {
				ast.Inspect(body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pos := fset.Position(call.Pos())
					where := fmt.Sprintf("%s:%d", rel, pos.Line)
					if sel.Sel.Name == "WithValues" && loggerBase.MatchString(render(fset, sel.X)) {
						for i := 0; i < len(call.Args); i += 2 {
							if k, ok := stringLit(call.Args[i]); ok {
								withValues[rel] = append(withValues[rel], k)
							}
						}
						return true
					}
					if sel.Sel.Name != "Info" && sel.Sel.Name != "Error" {
						return true
					}
					base, level := sel.X, "V(0)"
					if v, ok := base.(*ast.CallExpr); ok {
						if vs, ok := v.Fun.(*ast.SelectorExpr); ok && vs.Sel.Name == "V" && len(v.Args) == 1 {
							lit, ok := v.Args[0].(*ast.BasicLit)
							if !ok {
								problems = append(problems, where+": V() level is not a literal")
								return true
							}
							base, level = vs.X, "V("+lit.Value+")"
						}
					}
					args := call.Args
					if sel.Sel.Name == "Error" {
						if len(args) < 2 {
							return true // err.Error()
						}
						level, args = "error", args[1:]
					}
					if len(args) == 0 {
						return true
					}
					if !loggerBase.MatchString(render(fset, base)) {
						if _, isLit := stringLit(args[0]); isLit && render(fset, base) != "http" {
							problems = append(problems, where+": log-shaped call on unknown receiver "+render(fset, base))
						}
						return true
					}
					msg, ok := message(fset, args[0])
					if !ok {
						problems = append(problems, where+": message is not a literal, fmt.Sprintf format or variable")
						return true
					}
					e := entry{file: rel, level: level, msg: msg}
					kv := args[1:]
					for i := 0; i < len(kv); i += 2 {
						if call.Ellipsis.IsValid() && i == len(kv)-1 {
							id, ok := kv[i].(*ast.Ident)
							if !ok {
								problems = append(problems, where+": spread key/value argument is not a local variable")
								continue
							}
							e.keys = append(e.keys, sliceKeys(body, id.Name)...)
							continue
						}
						k, ok := stringLit(kv[i])
						if !ok {
							problems = append(problems, where+": key is not a string literal")
							continue
						}
						e.keys = append(e.keys, k)
					}
					if _, _, ok := componentOf(rel); !ok {
						problems = append(problems, where+": file has no entry in the components map")
					}
					entries = append(entries, e)
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(problems) > 0 {
		t.Fatalf("log call sites cannot be documented:\n%s", strings.Join(problems, "\n"))
	}
	return entries, withValues
}

// sliceKeys returns the literal keys assigned to the []any key/value slice
// name in body, from its composite literal and append calls.
func sliceKeys(body *ast.BlockStmt, name string) []string {
	var keys []string
	add := func(elts []ast.Expr) {
		for i := 0; i < len(elts); i += 2 {
			if k, ok := stringLit(elts[i]); ok && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Name != name {
			return true
		}
		switch rhs := as.Rhs[0].(type) {
		case *ast.CompositeLit:
			add(rhs.Elts)
		case *ast.CallExpr:
			if fn, ok := rhs.Fun.(*ast.Ident); ok && fn.Name == "append" && len(rhs.Args) > 1 {
				add(rhs.Args[1:])
			}
		}
		return true
	})
	return keys
}

var levelOrder = map[string]int{"error": 0, "V(0)": 1, "V(1)": 2, "V(2)": 3, "V(3)": 4, "V(4)": 5}

func catalog(entries []entry, withValues map[string][]string) string {
	byFile := map[string][]string{}
	for _, e := range entries {
		keys := "—"
		if len(e.keys) > 0 {
			keys = "`" + strings.Join(e.keys, "`, `") + "`"
		}
		msg := strings.ReplaceAll(e.msg, "|", `\|`)
		row := fmt.Sprintf("%d\x00| %s | `%s` | %s |", levelOrder[e.level], e.level, msg, keys)
		if !slices.Contains(byFile[e.file], row) {
			byFile[e.file] = append(byFile[e.file], row)
		}
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	// Group by component in map order, then by file.
	rank := func(f string) int {
		for i, c := range components {
			if strings.HasPrefix(f, c.prefix) {
				return i
			}
		}
		return len(components)
	}
	slices.SortFunc(files, func(a, b string) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})

	var b strings.Builder
	b.WriteString(beginMark + "\n")
	current := ""
	for _, f := range files {
		name, process, _ := componentOf(f)
		if name != current {
			fmt.Fprintf(&b, "\n### %s\n\nRuns in: `%s`.\n", name, process)
			current = name
		}
		fmt.Fprintf(&b, "\n#### `%s`\n\n", f)
		if keys := withValues[f]; len(keys) > 0 {
			slices.Sort(keys)
			fmt.Fprintf(&b, "Context keys added with `WithValues`: `%s`.\n\n", strings.Join(slices.Compact(keys), "`, `"))
		}
		b.WriteString("| Level | Message | Keys |\n|-------|---------|------|\n")
		rows := byFile[f]
		slices.Sort(rows)
		for _, r := range rows {
			b.WriteString(r[strings.IndexByte(r, 0)+1:] + "\n")
		}
	}
	b.WriteString("\n" + endMark)
	return b.String()
}

// tableKeys returns the backticked names in the first column of the markdown
// table that follows heading.
func tableKeys(t *testing.T, doc, heading string) []string {
	t.Helper()
	i := strings.Index(doc, heading)
	if i < 0 {
		t.Fatalf("%s: heading %q not found", docPath, heading)
	}
	var keys []string
	inTable := false
	for _, line := range strings.Split(doc[i+len(heading):], "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		first := strings.Split(line, "|")[1]
		for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(first, -1) {
			keys = append(keys, m[1])
		}
	}
	if len(keys) == 0 {
		t.Fatalf("%s: no keys in the table under %q", docPath, heading)
	}
	return keys
}

func TestLoggingReference(t *testing.T) {
	entries, withValues := collect(t)
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	begin, end := strings.Index(doc, beginMark), strings.Index(doc, endMark)
	if begin < 0 || end < begin {
		t.Fatalf("%s: generated catalog markers missing", docPath)
	}
	want := catalog(entries, withValues)
	if got := doc[begin : end+len(endMark)]; got != want {
		if *update {
			if err := os.WriteFile(docPath, []byte(doc[:begin]+want+doc[end+len(endMark):]), 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
		t.Fatalf("%s is out of date with the logger call sites; run: go test ./hack/logref -update", docPath)
	}

	codeKeys := map[string]bool{}
	levels := map[string]bool{}
	for _, e := range entries {
		levels[e.level] = true
		for _, k := range e.keys {
			codeKeys[k] = true
		}
	}
	for _, keys := range withValues {
		for _, k := range keys {
			codeKeys[k] = true
		}
	}

	// Every level in the code is described in the level table.
	documented := tableKeys(t, doc, "## Levels")
	for l := range levels {
		if !slices.Contains(documented, l) {
			t.Errorf("level %s is used in code but not described under \"## Levels\"", l)
		}
	}

	// Every documented decision and PII field is a key the code logs.
	for _, heading := range []string{"### Authorization decision fields", "## Fields that can hold personal data"} {
		for _, k := range tableKeys(t, doc, heading) {
			if !codeKeys[k] {
				t.Errorf("%q under %q is not a key in any log call", k, heading)
			}
		}
	}

	// Nothing that names a credential is logged.
	secret := regexp.MustCompile(`(?i)token|password|passphrase|secret|credential|bearer|private`)
	for k := range codeKeys {
		if secret.MatchString(k) {
			t.Errorf("log key %q names a credential; see \"## Never logged\"", k)
		}
	}
}
