// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const report = require('./security-report.cjs');

function fixture() {
  const posted = [];
  const pr = {
    number: 1, state: 'open', head: { sha: 'abc', repo: { id: 2 } },
    base: { repo: { full_name: 'owner/repo' } },
  };
  const data = {
    pulls: [pr], comments: [],
    runs: [{ id: 3, name: 'Security Scan' }, { id: 1, name: 'Security Scan' }],
    jobs: [{ name: 'govulncheck', conclusion: 'success', html_url: 'https://github.com/logs', check_run_url: 'https://api.github.com/checks/4' }],
    annotations: [{ title: 'Security scan advisory', message: '<ScRiPt>@someone|finding</SCRIPT>', annotation_level: 'warning' }],
  };
  const endpoint = key => Object.assign(() => {}, { key });
  const github = {
    paginate: async (method, args) => {
      if (method.key === 'jobs') assert.equal(args.run_id, 3);
      return data[method.key];
    },
    rest: {
      repos: { listPullRequestsAssociatedWithCommit: endpoint('pulls') },
      pulls: { get: async () => ({ data: pr }) },
      actions: { listWorkflowRunsForRepo: endpoint('runs'), listJobsForWorkflowRun: endpoint('jobs') },
      checks: { listAnnotations: endpoint('annotations') },
      issues: {
        listComments: endpoint('comments'),
        createComment: async args => posted.push({ method: 'create', ...args }),
        updateComment: async args => posted.push({ method: 'update', ...args }),
      },
    },
  };
  const context = {
    repo: { owner: 'owner', repo: 'repo' },
    payload: { workflow_run: { event: 'pull_request', name: 'Security Scan', head_sha: 'abc', head_repository: { id: 2 } } },
  };
  return { github, context, core: { info() {} }, data, pr, posted };
}

test('creates one escaped advisory report using the newest run', async () => {
  const f = fixture();
  await report(f);
  assert.equal(f.posted.length, 1);
  assert.equal(f.posted[0].method, 'create');
  assert.match(f.posted[0].body, /success; findings or scanner error \(advisory\)/);
  assert.match(f.posted[0].body, /&lt;ScRiPt&gt;&#64;someone&#124;finding&lt;\/SCRIPT&gt;/);
  assert.doesNotMatch(f.posted[0].body, /<script>|@someone/i);
});

test('accepts both CI and Security Scan workflow runs', async () => {
  for (const name of ['CI', 'Security Scan']) {
    const f = fixture();
    f.context.payload.workflow_run.name = name;
    await report(f);
    assert.equal(f.posted.length, 1);
  }
});

test('updates only its own bot comment, preserving human comments', async () => {
  const f = fixture();
  f.data.comments = [
    { id: 8, user: { login: 'human' }, body: '<!-- security-scan-report -->' },
    { id: 9, user: { login: 'github-actions[bot]' }, body: '<!-- security-scan-report --> old' },
  ];
  await report(f);
  assert.equal(f.posted[0].method, 'update');
  assert.equal(f.posted[0].comment_id, 9);
});

test('ignores stale, closed, foreign and mismatched-head reports', async () => {
  for (const change of [
    f => { f.pr.head.sha = 'new'; },
    f => { f.pr.state = 'closed'; },
    f => { f.pr.base.repo.full_name = 'other/repo'; },
    f => { f.pr.head.repo.id = 99; },
    f => { f.pr.head.repo = null; },
    f => { f.context.payload.workflow_run.head_repository = null; },
    f => { f.context.payload.workflow_run.event = 'push'; },
    f => { f.context.payload.workflow_run.name = 'Other'; },
  ]) {
    const f = fixture();
    change(f);
    await report(f);
    assert.equal(f.posted.length, 0);
  }
});

test('does not claim a running scanner succeeded', async () => {
  const f = fixture();
  f.data.jobs[0].conclusion = null;
  f.data.jobs[0].status = 'in_progress';
  f.data.annotations = [];
  await report(f);
  assert.match(f.posted[0].body, /in_progress/);
});

test('retains blocking build or license failures alongside scan warnings', async () => {
  const f = fixture();
  f.data.jobs[0].conclusion = 'failure';
  await report(f);
  assert.match(f.posted[0].body, /failure; findings or scanner error \(advisory\)/);
});

test('does not post when the PR advances during report generation', async () => {
  const f = fixture();
  let calls = 0;
  f.github.rest.pulls.get = async () => ({ data: ++calls === 1 ? f.pr : { ...f.pr, head: { sha: 'new' } } });
  await report(f);
  assert.equal(f.posted.length, 0);
});

test('does not post if the source repository is deleted before reporting', async () => {
  const f = fixture();
  let calls = 0;
  f.github.rest.pulls.get = async () => ({
    data: ++calls === 1 ? f.pr : { ...f.pr, head: { ...f.pr.head, repo: null } },
  });
  await report(f);
  assert.equal(f.posted.length, 0);
});
