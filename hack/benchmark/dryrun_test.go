// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"testing"
)

func CoreCells() []Cell { return ProductionCoreCells() }
func TestCoreMatrixShape(t *testing.T) {
	if len(CoreCells()) != 48 {
		t.Fatal(len(CoreCells()))
	}
}
func TestBaselinesAndIsolationVariants(t *testing.T) {
	if len(CoreCells()) != 48 {
		t.Fatal("core")
	}
	if CoreCells()[0].Tier != "t1" || CoreCells()[0].Variant != "enabled" {
		t.Fatal("variant")
	}
}
func TestResumeSkipsOnlyMatchingComplete(t *testing.T) {
	d := t.TempDir()
	c := CoreCells()[0]
	m := []byte("m")
	p := resultPath(d, c)
	if e := writeResult(p, Result{Cell: c, InputHash: InputHash(c, m), Status: "pending"}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var r Result
	_ = json.Unmarshal(b, &r)
	if r.Status == "complete" {
		t.Fatal("incomplete resumed")
	}
}
