// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestResumeStartOffsetAlwaysReplaysIncompletePhase(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"always replay incomplete phase", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resumeStartOffset(); got != tc.want {
				t.Fatalf("resume offset = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestValidateCompletedResultRequiresExactIdentityAndHashes(t *testing.T) {
	expected := Cell{
		Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseCreate,
		Concurrency: 8, Kind: resourceRoleDefinition, Verb: "create",
		Variant: variantEnabled, RunID: "run-1", Objects: 2,
	}
	valid := Result{Cell: expected, RunID: "run-1", InputHash: "input", EnvironmentID: "environment", WorkloadHash: "workload", ConfigHash: "config", Status: "complete", Samples: 1}

	if err := validateCompletedResult(valid, expected, "input", "environment", "workload", "config"); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Result)
	}{
		{name: "cell", edit: func(r *Result) { r.Cell.Phase = "churn" }},
		{name: "run ID", edit: func(r *Result) { r.RunID = "other" }},
		{name: "input hash", edit: func(r *Result) { r.InputHash = "other" }},
		{name: "environment ID", edit: func(r *Result) { r.EnvironmentID = "other" }},
		{name: "workload hash", edit: func(r *Result) { r.WorkloadHash = "other" }},
		{name: "config hash", edit: func(r *Result) { r.ConfigHash = "other" }},
		{name: "status", edit: func(r *Result) { r.Status = "failed"; r.Error = "failed" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prior := valid
			tc.edit(&prior)
			if err := validateCompletedResult(prior, expected, "input", "environment", "workload", "config"); err == nil {
				t.Fatal("mismatched result was accepted")
			}
		})
	}
}

func TestValidateCompletedResultRejectsInvalidResult(t *testing.T) {
	expected := Cell{
		Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseCreate,
		Concurrency: 8, Kind: resourceRoleDefinition, Verb: "create",
		Variant: variantEnabled, RunID: "run-1",
	}
	invalid := Result{Cell: expected, RunID: "run-1", InputHash: "input", EnvironmentID: "environment", WorkloadHash: "workload", ConfigHash: "config", Status: "complete"}
	if err := validateCompletedResult(invalid, expected, "input", "environment", "workload", "config"); err == nil {
		t.Fatal("invalid completed result was accepted")
	}
}

func TestValidateResultIdentityAllowsExactFailedResultForRetry(t *testing.T) {
	expected := Cell{
		Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseChurn,
		Concurrency: 8, Kind: resourceRoleDefinition, Verb: verbMixed,
		Variant: variantEnabled, RunID: "run-1", Objects: 2,
	}
	failed := Result{
		Cell: expected, RunID: "run-1", InputHash: "input",
		EnvironmentID: "environment", WorkloadHash: "workload",
		ConfigHash: "config", Status: statusFailed, Error: "interrupted",
	}
	if err := validateResultIdentity(failed, expected, "input", "environment", "workload", "config"); err != nil {
		t.Fatalf("exact failed result cannot be retried: %v", err)
	}
	if err := validateCompletedResult(failed, expected, "input", "environment", "workload", "config"); err == nil {
		t.Fatal("failed result was accepted as a completed checkpoint")
	}

	failed.ConfigHash = "other"
	if err := validateResultIdentity(failed, expected, "input", "environment", "workload", "config"); err == nil {
		t.Fatal("mismatched failed result was accepted for retry")
	}
}
