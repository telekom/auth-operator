// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadResultsAndReports(t *testing.T) {
	d := t.TempDir()
	r := Result{
		Cell: Cell{
			Engine:      "map",
			Tier:        "t1",
			Mode:        "protect",
			Phase:       "create",
			Verb:        "create",
			Variant:     "enabled",
			Concurrency: 8,
		},
		Status:        "complete",
		Samples:       1,
		RunID:         "run-1",
		InputHash:     "hash",
		EnvironmentID: "env",
	}
	if e := writeResult(filepath.Join(d, "cell-run-1-map-t1-protect-enabled-create-8.json"), r); e != nil {
		t.Fatal(e)
	}
	rs, e := LoadResults(d)
	if e != nil || len(rs) != 1 {
		t.Fatalf("load: %v", e)
	}
	if e = WriteReports(d, rs); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(d, "results.csv")); e != nil {
		t.Fatal(e)
	}
}
