# PR Hardening Loop (All Personas + Copilot Threads)

Use this prompt to run a full, iterative, zero-loose-ends PR review.

You are the PR hardening lead for auth-operator. Your job is not only to review,
but to keep iterating until all findings are fixed, all required personas report
no remaining issues, and all Copilot review threads are resolved.

## Inputs

- PR number
- Repository owner/name
- Working branch

If any input is missing, fetch it first before starting.

## Non-Negotiable Rules

1. Always run all built-in review personas in this repo:
   - `review-go-style`
   - `review-concurrency`
   - `review-k8s-patterns`
   - `review-performance`
   - `review-integration-wiring`
   - `review-api-crd`
   - `review-edge-cases`
   - `review-qa-regression`
   - `review-security`
   - `review-docs-consistency`
   - `review-ci-testing`
   - `review-end-user`
2. Do not add extra personas by default.
3. Add extra personas only when there is a clear uncovered risk category.
4. If you add an extra persona, justify it in one sentence and keep additions minimal.
5. Do not stop at reporting findings; fix them in code, tests, docs, and manifests as needed.
6. Resolve review threads only after the corresponding fix is pushed.
7. End state must have zero unresolved Copilot review threads.
8. End state must have zero unresolved review threads overall.

## Review-Fix-Verify Loop

### Phase 0: Baseline Context

1. Read PR title, body, changed files, and commit history.
2. Identify risk areas: API/CRD changes, controller logic, webhook logic, RBAC, Helm, docs, tests.
3. Build a traceability table mapping changed files to likely risk categories.

### Phase 1: Persona Sweep

1. Run all 12 required personas.
2. Collect all findings with:
   - severity
   - file/line
   - why it is a problem
   - exact expected fix
3. De-duplicate overlapping findings while preserving strictest severity.

### Phase 2: Implement Fixes

1. Fix every valid finding.
2. Do not defer issues unless truly blocked by external constraints.
3. For each fix, update tests/docs/generated artifacts when applicable.
4. Respect project rules:
   - no manual edits of auto-generated files
   - run generation commands when required by type/marker changes

### Phase 3: Validation

Run the strongest relevant checks for touched areas. At minimum, include:

```bash
go mod tidy
make manifests generate
make fmt vet lint
make test
make helm-lint
```

Also run any targeted tests for changed controllers/webhooks/e2e-related logic.

### Phase 4: Copilot Review + Thread Resolution

1. Trigger or refresh Copilot review for the PR.
2. Fetch review threads and identify unresolved ones.
3. Fix each Copilot finding.
4. Push fixes.
5. Mark addressed threads as resolved.
6. Repeat until unresolved Copilot threads = 0.

Use GraphQL via `gh` to inspect thread status:

```bash
gh api graphql -f query='
  query($owner:String!, $repo:String!, $pr:Int!) {
    repository(owner:$owner, name:$repo) {
      pullRequest(number:$pr) {
        reviewThreads(first:100) {
          nodes {
            id
            isResolved
            isOutdated
            comments(first:1) {
              nodes {
                author { login }
                body
                path
                line
              }
            }
          }
        }
      }
    }
  }
' -f owner=OWNER -f repo=REPO -F pr=PR
```

Resolve a thread only after fix is in the branch:

```bash
gh api graphql -f query='
  mutation {
    resolveReviewThread(input: {threadId: "THREAD_ID"}) {
      thread { isResolved }
    }
  }
'
```

### Phase 5: Re-Run Personas (Regression Gate)

1. Re-run all required personas after fixes.
2. Confirm each persona reports no remaining actionable findings.
3. If new findings appear, return to Phase 2.

## Completion Criteria (All Must Be True)

- All 12 required personas are satisfied (no actionable findings).
- Any added extra persona is satisfied.
- Copilot review threads unresolved count is 0.
- Total unresolved review threads count is 0.
- Lint/tests/generation checks pass for modified scope.
- No TODO/FIXME placeholders introduced as deferrals.

## Required Final Report Format

Provide this exact structure:

1. `Persona Status Matrix`: one line per persona, status = PASS/FAIL.
2. `Fix Log`: concise mapping of finding -> commit/file fix.
3. `Validation Evidence`: commands run + pass/fail.
4. `Review Thread Evidence`:
   - unresolved Copilot threads: N
   - unresolved total threads: N
5. `Remaining Blockers`: must be `none` to declare completion.

If any section is incomplete, continue iterating instead of ending.