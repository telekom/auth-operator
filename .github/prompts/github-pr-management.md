# GitHub PR Management

Use this prompt when managing pull requests: reviewing, resolving threads,
rebasing, squashing, and interacting with CI.

## Prerequisites

- GitHub CLI (`gh`) must be authenticated
- EMU (Enterprise Managed User) accounts cannot use GitHub MCP API for
  write operations — always use `gh` CLI instead

## Checking PR Review Threads

Use this GraphQL query to list all review threads and their resolution status:

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
                body
                author { login }
                path
                line
                createdAt
              }
            }
          }
        }
      }
    }
  }
' -f owner=telekom -f repo=REPO_NAME -F pr=PR_NUMBER
```

## Resolving Review Threads

After fixing an issue raised in a review thread, resolve it:

```bash
# Single thread
gh api graphql -f query='
  mutation {
    resolveReviewThread(input: {threadId: "THREAD_ID"}) {
      thread { isResolved }
    }
  }
'

# Multiple threads at once (use aliases)
gh api graphql -f query='
  mutation {
    t1: resolveReviewThread(input: {threadId: "ID_1"}) { thread { isResolved } }
    t2: resolveReviewThread(input: {threadId: "ID_2"}) { thread { isResolved } }
  }
'
```

## Rebasing on Main

```bash
git fetch origin main
git rebase origin/main

# If conflicts arise, resolve them and continue:
git add -A
GIT_EDITOR=true git -c commit.gpgsign=false rebase --continue
```

## Squashing Commits

```bash
# Count commits ahead of main
COMMITS=$(git rev-list --count origin/main..HEAD)

# Reset-based squash (simplest):
git reset --soft origin/main
git -c commit.gpgsign=false commit -m "feat: description (#PR)"
```

## Amending and Force-Pushing

```bash
git add -A
git -c commit.gpgsign=false commit --amend --no-edit
git push --force-with-lease
```

## Checking CI Status

```bash
gh pr checks PR_NUMBER
gh pr checks PR_NUMBER --watch
gh run view RUN_ID --log-failed
```

## Creating PRs

```bash
gh pr create \
  --title "feat: description" \
  --body "## Summary\n\n..." \
  --base main
```

## Workflow Tips

1. **Always check threads after push** — Copilot reviewer may add new
   threads on every push. Query threads after each force-push.
2. **Resolve threads only after fixing** — push the fix first.
3. **Batch GraphQL mutations** — use aliases (`t1:`, `t2:`) to resolve
   multiple threads in one API call.
4. **Force-push with lease** — always `--force-with-lease`.
5. **Verify 0 unresolved** before marking a PR ready.
