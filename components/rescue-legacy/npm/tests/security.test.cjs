'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..');
const launcherPath = path.join(root, 'npm', 'codex-rescue', 'bin', 'codex-rescue.js');
const launcher = fs.readFileSync(launcherPath, 'utf8');
const top = JSON.parse(fs.readFileSync(path.join(root, 'npm', 'codex-rescue', 'package.json'), 'utf8'));
const { getTarget, missingBinaryPayload, missingPackageMessage, resolvePlatformPackage, targets } = require(launcherPath);

const platformDirs = ['linux-x64', 'win32-x64', 'darwin-arm64', 'darwin-x64'];

function syntheticResolver(installed) {
  return (request) => {
    const suffix = '/package.json';
    assert.ok(request.endsWith(suffix));
    const packageName = request.slice(0, -suffix.length);
    if (!installed.has(packageName)) {
      const error = new Error(`Cannot find module ${request}`);
      error.code = 'MODULE_NOT_FOUND';
      throw error;
    }
    return path.join('/synthetic/node_modules', packageName, 'package.json');
  };
}

test('launcher has no runtime downloader, Python bootstrap, npm mutation, or shell execution path', () => {
  assert.doesNotMatch(launcher, /https?:\/\//i);
  assert.doesNotMatch(launcher, /curl|wget|powershell|invoke-webrequest/i);
  assert.doesNotMatch(launcher, /\bpython(?:3)?\b|\bpip(?:x)?\b/i);
  assert.doesNotMatch(launcher, /execSync|execFileSync|\bexec\s*\(/);
  assert.doesNotMatch(launcher, /spawnSync/);
  assert.equal((launcher.match(/\bspawn\s*\(/g) || []).length, 1);
  assert.doesNotMatch(launcher, /shell\s*:\s*true/);
  assert.match(launcher, /spawn\(executable, process\.argv\.slice\(2\)/);
  assert.match(launcher, /shell:\s*false/);
});

test('top package uses an explicit content allowlist and no lifecycle scripts', () => {
  assert.deepEqual(top.files.sort(), ['README.md', 'bin/codex-rescue.js'].sort());
  assert.equal(top.scripts, undefined);
  assert.ok(top.version.startsWith('0.1.0-alpha.7'));
});

test('platform packages are restricted and script-free', () => {
  for (const directory of platformDirs) {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'npm', 'platforms', directory, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '0.1.0-alpha.7');
    assert.equal(pkg.scripts, undefined);
    assert.equal(pkg.os.length, 1);
    assert.equal(pkg.cpu.length, 1);
    assert.ok(Array.isArray(pkg.files) && pkg.files.length === 2);
  }
});

test('Windows x64 prefers the supported fallback package', () => {
  const target = getTarget('win32', 'x64');
  assert.deepEqual([...target.packages], ['codex-rescue-windows-x64', 'codex-rescue-win32-x64']);
  const resolved = resolvePlatformPackage(target, syntheticResolver(new Set(['codex-rescue-windows-x64'])));
  assert.equal(resolved.packageName, 'codex-rescue-windows-x64');
});

test('Windows x64 intentionally recognizes the historical package when it is the only installed candidate', () => {
  const target = getTarget('win32', 'x64');
  const resolved = resolvePlatformPackage(target, syntheticResolver(new Set(['codex-rescue-win32-x64'])));
  assert.equal(resolved.packageName, 'codex-rescue-win32-x64');
});

test('Windows x64 missing packages fail deterministically and report checked candidates', () => {
  const target = getTarget('win32', 'x64');
  const resolved = resolvePlatformPackage(target, syntheticResolver(new Set()));
  assert.equal(resolved, null);
  const message = missingPackageMessage('win32', 'x64', target, '0.1.0-alpha.7');
  assert.match(message, /win32\/x64/);
  assert.match(message, /codex-rescue-windows-x64, codex-rescue-win32-x64/);
  assert.match(message, /codex-rescue@0\.1\.0-alpha\.7/);
  assert.doesNotMatch(message, /Alpha5 prerelease/);
});

test('Linux x64 package selection remains unchanged', () => {
  const target = getTarget('linux', 'x64');
  assert.deepEqual([...target.packages], ['codex-rescue-linux-x64']);
  assert.equal(target.executable, 'codex-rescue');
});

test('Darwin arm64 package selection remains unchanged', () => {
  const target = getTarget('darwin', 'arm64');
  assert.deepEqual([...target.packages], ['codex-rescue-darwin-arm64']);
  assert.equal(target.executable, 'codex-rescue');
});

test('Darwin x64 package selection remains unchanged', () => {
  const target = getTarget('darwin', 'x64');
  assert.deepEqual([...target.packages], ['codex-rescue-darwin-x64']);
  assert.equal(target.executable, 'codex-rescue');
});

test('unsupported or malformed platform keys fail closed', () => {
  assert.equal(getTarget('win32', 'arm64'), null);
  assert.equal(getTarget('linux', 'mips64'), null);
  assert.equal(getTarget('../win32', 'x64'), null);
  assert.equal(getTarget('', ''), null);
});

test('manifest topology points only at publishable platform package families', () => {
  assert.equal(top.optionalDependencies['codex-rescue-windows-x64'], '0.1.0-alpha.7');
  assert.equal(top.optionalDependencies['codex-rescue-win32-x64'], undefined);
  assert.deepEqual(Object.keys(top.optionalDependencies).sort(), [
    'codex-rescue-darwin-arm64',
    'codex-rescue-darwin-x64',
    'codex-rescue-linux-x64',
    'codex-rescue-windows-x64',
  ]);
  assert.equal(targets['win32-x64'].packages[0], 'codex-rescue-windows-x64');
});

test('missingBinaryPayload generates valid fail-closed structured JSON payload', () => {
  const target = getTarget('win32', 'x64');
  const payload = missingBinaryPayload('win32', 'x64', target, '0.1.0-alpha.7');
  assert.equal(payload.error, 'NATIVE_BINARY_MISSING');
  assert.equal(payload.platform, 'win32');
  assert.equal(payload.arch, 'x64');
  assert.deepEqual(payload.checked_packages, ['codex-rescue-windows-x64', 'codex-rescue-win32-x64']);
  assert.match(payload.message, /codex-rescue-windows-x64/);
});

test('launcher execution without native binary exits 1 and emits structured JSON on stderr', (t) => {
  const { spawnSync } = require('node:child_process');
  const res = spawnSync(process.execPath, [launcherPath], {
    encoding: 'utf8',
    env: { ...process.env, NODE_PATH: '' },
  });
  assert.equal(res.status, 1);
  const errOutput = res.stderr.trim();
  assert.ok(errOutput.length > 0);
  const parsed = JSON.parse(errOutput);
  assert.equal(parsed.error, 'NATIVE_BINARY_MISSING');
  assert.ok(parsed.platform);
  assert.ok(parsed.arch);
  assert.doesNotMatch(res.stderr, /at Object\.<anonymous>|at Module\._compile/);
});
