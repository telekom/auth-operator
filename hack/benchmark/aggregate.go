// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var cellResultName = regexp.MustCompile(`^cell-[a-z0-9-]+-\d+\.json$`)

func LoadResults(dir string) ([]Result, error) {
	paths, e := filepath.Glob(filepath.Join(dir, "*.json"))
	if e != nil {
		return nil, e
	}
	sort.Strings(paths)
	out := make([]Result, 0, len(paths))
	for _, p := range paths {
		if !cellResultName.MatchString(filepath.Base(p)) {
			continue
		}
		b, e := readBenchmarkFile(p)
		if e != nil {
			return nil, e
		}
		var r Result
		if e := json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		if e := r.Validate(); e != nil {
			return nil, fmt.Errorf("invalid cell result %s: %w", p, e)
		}
		key := string(canonical(r.Cell))
		for _, prior := range out {
			if string(canonical(prior.Cell)) == key {
				return nil, fmt.Errorf("duplicate cell result %s", p)
			}
		}
		out = append(out, r)
	}
	return sortedResults(out), nil
}

func plannedKey(c Cell) string {
	c.RunID = ""
	// Objects is runtime sizing metadata, not part of the executable cell key.
	c.Objects = 0
	return string(canonical(c))
}

func LoadPlannedResults(dir string) ([]Result, error) {
	planBytes, err := readBenchmarkFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}
	var plan struct {
		Cells []Cell `json:"cells"`
	}
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return nil, fmt.Errorf("decode plan: %w", err)
	}
	if len(plan.Cells) == 0 {
		return nil, fmt.Errorf("plan has no cells")
	}
	results, err := LoadResults(dir)
	if err != nil {
		return nil, err
	}
	expected := map[string]bool{}
	for _, c := range plan.Cells {
		k := plannedKey(c)
		if expected[k] {
			return nil, fmt.Errorf("duplicate planned cell %s", k)
		}
		expected[k] = true
	}
	seen := map[string]bool{}
	for _, r := range results {
		k := plannedKey(r.Cell)
		if !expected[k] {
			return nil, fmt.Errorf("unexpected result cell %s", k)
		}
		if seen[k] {
			return nil, fmt.Errorf("duplicate result cell %s", k)
		}
		seen[k] = true
	}
	for k := range expected {
		if !seen[k] {
			return nil, fmt.Errorf("missing planned cell %s", k)
		}
	}
	return results, nil
}
func WriteReports(dir string, rs []Result) error {
	// Reports can contain raw benchmark observations and environment details.
	// Keep the output directory private, matching the artifact permission policy.
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return e
	}
	reports := []struct {
		name string
		fn   func(*os.File) error
	}{
		{"results.csv", func(f *os.File) error { return WriteReportCSV(f, AggregateReport(rs, "")) }},
		{"results.md", func(f *os.File) error { return WriteReportMarkdown(f, AggregateReport(rs, "")) }},
		{"raw-results.csv", func(f *os.File) error { return WriteCSV(f, rs) }},
		{"results.json", func(f *os.File) error {
			rows := AggregateReport(rs, "")
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}},
	}
	for _, report := range reports {
		name, fn := report.name, report.fn
		p := filepath.Join(dir, name)
		t, e := os.CreateTemp(dir, ".report-*")
		if e != nil {
			return e
		}
		n := t.Name()
		if e := fn(t); e != nil {
			_ = t.Close()
			_ = os.Remove(n)
			return e
		}
		if e := t.Close(); e != nil {
			_ = os.Remove(n)
			return e
		}
		if e := os.Rename(n, p); e != nil {
			_ = os.Remove(n)
			return e
		}
	}
	return nil
}

func WritePartialReports(dir string, rs []Result) error {
	tmp, err := os.MkdirTemp(dir, ".partial-report-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := WriteReports(tmp, rs); err != nil {
		return err
	}
	pairs := []struct {
		from string
		to   string
	}{
		{from: "results.csv", to: "partial-results.csv"},
		{from: "results.md", to: "partial-results.md"},
		{from: "results.json", to: "partial-results.json"},
		{from: "raw-results.csv", to: "partial-raw-results.csv"},
	}
	for _, pair := range pairs {
		if err := os.Rename(filepath.Join(tmp, pair.from), filepath.Join(dir, pair.to)); err != nil {
			return err
		}
	}
	return nil
}
