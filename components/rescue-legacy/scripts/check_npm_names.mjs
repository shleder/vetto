import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const top = JSON.parse(readFileSync(new URL('../npm/codex-rescue/package.json', import.meta.url), 'utf8'));
const packages = [
  { name: top.name, version: top.version },
  ...Object.entries(top.optionalDependencies || {}).map(([name, version]) => ({ name, version })),
];

function npm(args) {
  const exe = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  return spawnSync(exe, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
    env: { ...process.env, npm_config_registry: 'https://registry.npmjs.org' },
  });
}

function text(result) {
  return `${result.stdout || ''}\n${result.stderr || ''}`.trim();
}

function is404(result) {
  return /E404|404 Not Found|is not in this registry|No match found for version/i.test(text(result));
}

const whoami = npm(['whoami', '--json']);
let identity = null;
if (whoami.status === 0) {
  try {
    identity = JSON.parse(whoami.stdout);
  } catch {
    identity = String(whoami.stdout || '').trim().replace(/^"|"$/g, '') || null;
  }
}

const rows = [];
let gate = 'PASS';

for (const pkg of packages) {
  const view = npm(['view', pkg.name, 'name', 'version', 'maintainers', '--json']);
  if (view.status !== 0 && is404(view)) {
    rows.push({
      PACKAGE: pkg.name,
      INTENDED_VERSION: pkg.version,
      REGISTRY_STATE: 'AVAILABLE',
      OWNER_MAINTAINER: null,
      WE_CAN_PUBLISH: identity ? 'YES_NAME_AVAILABLE' : 'AUTH_NOT_VERIFIED',
      EVIDENCE: 'npm view returned unambiguous registry E404',
      ACTION_REQUIRED: identity ? 'NONE' : 'authenticate npm identity before publication',
    });
    continue;
  }

  if (view.status !== 0) {
    gate = 'BLOCKED';
    rows.push({
      PACKAGE: pkg.name,
      INTENDED_VERSION: pkg.version,
      REGISTRY_STATE: 'UNKNOWN',
      OWNER_MAINTAINER: null,
      WE_CAN_PUBLISH: 'UNKNOWN',
      EVIDENCE: text(view).slice(0, 500),
      ACTION_REQUIRED: 'retry registry preflight; do not infer availability',
    });
    continue;
  }

  let data = {};
  try {
    data = JSON.parse(view.stdout || '{}');
  } catch {
    data = {};
  }
  const maintainers = Array.isArray(data.maintainers)
    ? data.maintainers.map((entry) => typeof entry === 'string' ? entry : entry?.name).filter(Boolean)
    : [];
  const owned = Boolean(identity && maintainers.includes(identity));
  const exact = npm(['view', `${pkg.name}@${pkg.version}`, 'version', '--json']);
  const exactExists = exact.status === 0;

  let state = 'UNKNOWN';
  let canPublish = 'UNKNOWN';
  let action = 'verify npm ownership with authenticated identity';
  if (identity) {
    state = owned ? 'OWNED_BY_US' : 'OWNED_BY_OTHER';
    canPublish = owned && !exactExists ? 'YES' : 'NO';
    action = owned
      ? (exactExists ? 'STOP: intended version already exists' : 'NONE')
      : 'rename package or use an owned scope; do not publish';
  }

  if (!owned || exactExists) gate = 'BLOCKED';
  rows.push({
    PACKAGE: pkg.name,
    INTENDED_VERSION: pkg.version,
    REGISTRY_STATE: state,
    OWNER_MAINTAINER: maintainers.length ? maintainers.join(',') : null,
    WE_CAN_PUBLISH: canPublish,
    EVIDENCE: exactExists
      ? `registered; intended version ${pkg.version} already exists`
      : 'registered package metadata returned by npm registry',
    ACTION_REQUIRED: action,
  });
}

console.log(JSON.stringify({ npm_identity: identity, NPM_NAMES_GATE: gate, packages: rows }, null, 2));
if (gate !== 'PASS') {
  console.error('NPM registry-name gate is BLOCKED. No publication was attempted.');
  process.exit(1);
}
