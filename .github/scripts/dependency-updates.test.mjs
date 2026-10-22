// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { after, test } from 'node:test';
import { pathToFileURL } from 'node:url';

assert.ok(process.env.RENOVATE_PACKAGE_DIR, 'Set RENOVATE_PACKAGE_DIR to the pinned Renovate installation');
const load = relative => import(pathToFileURL(path.join(process.env.RENOVATE_PACKAGE_DIR, 'dist', relative)));
const { init } = await load('logger/index.js');
await init();
const { GlobalConfig } = await load('config/global.js');
const { extractPackageFile } = await load('modules/manager/custom/regex/index.js');
const { doAutoReplace } = await load('workers/repository/update/branch/auto-replace.js');
const { applyPackageRules } = await load('util/package-rules/index.js');
const config = JSON.parse(await fs.readFile('.github/renovate.json', 'utf8'));
const manager = config.customManagers[0];
const sandbox = await fs.mkdtemp(path.join(process.cwd(), '.dependency-updates-'));
GlobalConfig.set({ localDir: sandbox, cacheDir: sandbox, platform: 'local' });
after(() => fs.rm(sandbox, { recursive: true, force: true }));

test('package rules leave normal modules to Dependabot and enable supported Go floor patches and OPA', async () => {
  for (const [depType, packageName, datasource, enabled] of [
    ['require', 'k8s.io/client-go', 'go', false],
    ['golang', 'go', 'golang-version', true],
    ['indirect', 'github.com/open-policy-agent/frameworks/constraint', 'go', true],
  ]) {
    const resolved = await applyPackageRules({
      packageRules: config.packageRules, manager: 'gomod', depType,
      packageName, depName: packageName, datasource,
    }, 'dependency ownership test');
    assert.equal(resolved.enabled, enabled, `${depType} ${packageName}`);
    if (depType === 'golang') {
      assert.equal(resolved.rangeStrategy, 'bump');
      assert.equal(resolved.allowedVersions, '<1.27.0');
    }
  }
});

test('the real updater changes every duplicated tool pin without changing unrelated content', async () => {
  const files = [
    'versions.env', 'Makefile', 'kind-with-registry.sh', 'Tiltfile',
    '.github/actions/setup-go-env/action.yml', '.github/actions/setup-kind-cluster/action.yml',
    '.github/workflows/ci.yml', '.github/workflows/e2e.yml',
    '.github/workflows/release.yml', '.github/workflows/security-scan.yml',
    'hack/ci/setup-kind-crds.sh', 'test/e2e/run-authorization-chain.sh',
  ];
  const counts = new Map();
  for (const packageFile of files) {
    const original = await fs.readFile(packageFile, 'utf8');
    const extracted = extractPackageFile(original, packageFile, manager);
    if (!extracted) continue;
    let updated = original;
    for (const [depIndex, dep] of extracted.deps.entries()) {
      counts.set(dep.depName, (counts.get(dep.depName) || 0) + 1);
      const parts = dep.currentValue.split('.');
      const newValue = `${parts.slice(0, -1).join('.')}.${Number(parts.at(-1)) + 1}`;
      const fixture = `fixture-${files.indexOf(packageFile)}.env`;
      updated = await doAutoReplace({
        ...manager, ...dep, manager: 'regex', depIndex, packageFile: fixture, newValue,
      }, updated, false);
      const current = extractPackageFile(updated, packageFile, manager).deps[depIndex];
      assert.equal(current.currentValue, newValue, `${packageFile}: ${dep.depName}`);
      assert.equal(current.currentDigest, dep.currentDigest);
    }
    assert.equal(await fs.readFile(packageFile, 'utf8'), original);
  }
  for (const [name, count] of [
    ['sigs.k8s.io/kind', 2], ['helm/helm', 2],
    ['github.com/golangci/golangci-lint/v2', 2],
    ['github.com/google/go-licenses/v2', 2], ['aquasecurity/trivy', 3],
    ['cert-manager/cert-manager', 3], ['kubernetes/kubernetes', 1], ['kindest/node', 6],
  ]) assert.equal(counts.get(name), count, name);
});

test('kind tag-only source formats stay tag-only and use published image versions', async () => {
  for (const packageFile of [
    'versions.env', 'Makefile', 'kind-with-registry.sh',
    '.github/actions/setup-kind-cluster/action.yml',
  ]) {
    const original = await fs.readFile(packageFile, 'utf8');
    const { deps } = extractPackageFile(original, packageFile, manager);
    const depIndex = deps.findIndex(dep => dep.depName === 'kindest/node' && !dep.currentDigest);
    const dep = deps[depIndex];
    assert.equal(dep.datasource, 'docker');
    assert.equal(dep.currentValue, 'v1.36.1');
    const resolved = await applyPackageRules({
      packageRules: config.packageRules, manager: 'regex', ...dep, packageName: dep.depName,
    }, 'kind image ownership');
    assert.equal(resolved.pinDigests, false);
    const updated = await doAutoReplace({
      ...manager, ...dep, manager: 'regex', depIndex,
      packageFile: `kind-${depIndex}-${path.basename(packageFile)}.env`, newValue: 'v1.36.2',
    }, original, false);
    const replacement = extractPackageFile(updated, packageFile, manager).deps[depIndex];
    assert.equal(replacement.currentValue, 'v1.36.2');
    assert.equal(replacement.currentDigest, undefined);
    assert.equal(updated, original.replace(dep.replaceString, dep.replaceString.replace('v1.36.1', 'v1.36.2')));
  }
});

test('the real updater changes an image tag and digest atomically', async () => {
  const original = '# renovate: datasource=docker depName=kindest/node\n' +
    `IMAGE=kindest/node:v1.36.1@sha256:${'a'.repeat(64)}\nUNRELATED_VERSION=v1.36.1\n`;
  const dep = extractPackageFile(original, 'image.env', manager).deps[0];
  const newDigest = `sha256:${'b'.repeat(64)}`;
  const updated = await doAutoReplace({
    ...manager, ...dep, manager: 'regex', depIndex: 0, packageFile: 'image.env',
    newValue: 'v1.36.2', newDigest,
  }, original, false);
  assert.equal(updated, original.replace(`v1.36.1@${dep.currentDigest}`, `v1.36.2@${newDigest}`));
  assert.equal(await fs.readFile(path.join(sandbox, 'image.env'), 'utf8'), updated);
});

test('the native Go datasource resolves the actual nested module from the Go proxy', { timeout: 90000 }, async () => {
  const module = 'github.com/open-policy-agent/frameworks/constraint';
  const response = await fetch(`https://proxy.golang.org/${module}/@latest`, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200);
  const latest = await response.json();
  const { getPkgReleases } = await load('modules/datasource/index.js');
  const result = await getPkgReleases({ datasource: 'go', packageName: module, versioning: 'semver' });
  assert.ok(result?.releases.some(release => release.version === latest.Version));
});
