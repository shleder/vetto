#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');
const meta = require('../package.json');

const targets = Object.freeze({
  'linux-x64': Object.freeze({ packages: Object.freeze(['codex-rescue-linux-x64']), executable: 'codex-rescue' }),
  'win32-x64': Object.freeze({
    packages: Object.freeze(['codex-rescue-windows-x64', 'codex-rescue-win32-x64']),
    executable: 'codex-rescue.exe',
  }),
  'darwin-arm64': Object.freeze({ packages: Object.freeze(['codex-rescue-darwin-arm64']), executable: 'codex-rescue' }),
  'darwin-x64': Object.freeze({ packages: Object.freeze(['codex-rescue-darwin-x64']), executable: 'codex-rescue' }),
});

function getTarget(platform, arch) {
  return targets[`${platform}-${arch}`] || null;
}

function resolvePlatformPackage(target, resolver = require.resolve) {
  for (const packageName of target.packages) {
    try {
      return {
        packageName,
        packageJson: resolver(`${packageName}/package.json`),
      };
    } catch {}
  }
  return null;
}

function missingPackageMessage(platform, arch, target, version = meta.version) {
  return (
    `codex-rescue: platform binary package unavailable for ${platform}/${arch}. ` +
    `Checked: ${target.packages.join(', ')}. ` +
    `Reinstall codex-rescue@${version} with optional dependencies enabled ` +
    `(npm install --include=optional codex-rescue@${version}) and retry.`
  );
}

function missingBinaryPayload(platform, arch, target, version = meta.version) {
  return {
    error: 'NATIVE_BINARY_MISSING',
    platform,
    arch,
    checked_packages: target ? [...target.packages] : [],
    message: target ? missingPackageMessage(platform, arch, target, version) : `Unsupported platform ${platform}/${arch}`,
  };
}

function main() {
  const platform = process.platform;
  const arch = process.arch;
  const target = getTarget(platform, arch);
  if (!target) {
    console.error(JSON.stringify({
      error: 'NATIVE_BINARY_MISSING',
      platform,
      arch,
      message: `codex-rescue: unsupported platform ${platform}/${arch}; no platform package will be executed.`,
    }));
    process.exit(1);
  }

  const resolved = resolvePlatformPackage(target);
  if (!resolved) {
    console.error(JSON.stringify(missingBinaryPayload(platform, arch, target)));
    process.exit(1);
  }

  const fs = require('node:fs');
  const executable = path.join(path.dirname(resolved.packageJson), 'bin', target.executable);
  if (!fs.existsSync(executable)) {
    console.error(JSON.stringify({
      error: 'NATIVE_BINARY_MISSING',
      platform,
      arch,
      executable,
      message: `codex-rescue: native binary not found at ${executable}`,
    }));
    process.exit(1);
  }

  const child = spawn(executable, process.argv.slice(2), {
    stdio: 'inherit',
    shell: false,
    windowsHide: false,
  });

  child.once('error', (error) => {
    console.error(JSON.stringify({
      error: 'NATIVE_BINARY_MISSING',
      platform,
      arch,
      message: `codex-rescue: failed to start platform executable: ${error.message}`,
    }));
    process.exit(1);
  });

  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    if (process.platform === 'win32' && signal === 'SIGHUP') continue;
    process.on(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  }

  child.once('exit', (code, signal) => {
    if (signal && process.platform !== 'win32') {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  getTarget,
  missingBinaryPayload,
  missingPackageMessage,
  resolvePlatformPackage,
  targets,
};
