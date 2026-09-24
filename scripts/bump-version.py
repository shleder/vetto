#!/usr/bin/env python3
"""
Automated version bump script for Vetto.
Strictly adheres to +0.0.1 increment rule and updates all package manifests and VERSIONS.md.
Usage:
    python3 scripts/bump-version.py [optional_explicit_version]
"""

import sys
import re
import os
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CARGO_TOML = os.path.join(REPO_ROOT, "Cargo.toml")
CARGO_LOCK = os.path.join(REPO_ROOT, "Cargo.lock")
PACKAGE_JSON = os.path.join(REPO_ROOT, "npm", "package.json")
PKGBUILD = os.path.join(REPO_ROOT, "packaging", "aur", "vetto-git", "PKGBUILD")
NUSPEC = os.path.join(REPO_ROOT, "packaging", "chocolatey", "vetto.nuspec")
HOMEBREW_RB = os.path.join(REPO_ROOT, "packaging", "homebrew", "vetto.rb")
SPEC = os.path.join(REPO_ROOT, "packaging", "rpm", "vetto.spec")
VERSIONS_MD = "/home/shleder/prod/VERSIONS.md"

def get_current_version():
    with open(CARGO_TOML, "r") as f:
        content = f.read()
    m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not m:
        raise RuntimeError("Could not find version in Cargo.toml")
    return m.group(1)

def compute_next_version(current):
    parts = current.split(".")
    if len(parts) != 3:
        raise ValueError(f"Version must be semver X.Y.Z, got {current}")
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    return f"{major}.{minor}.{patch + 1}"

def update_file(filepath, pattern, replacement, count=1):
    if not os.path.exists(filepath):
        print(f"Skipping {filepath} (file not found)")
        return False
    with open(filepath, "r") as f:
        content = f.read()
    new_content, replaced = re.subn(pattern, replacement, content, count=count, flags=re.MULTILINE)
    if replaced == 0:
        print(f"Warning: pattern '{pattern}' not found in {filepath}")
        return False
    with open(filepath, "w") as f:
        f.write(new_content)
    print(f"Updated {os.path.relpath(filepath, REPO_ROOT)}")
    return True

def update_cargo_lock(old_ver, new_ver):
    if not os.path.exists(CARGO_LOCK):
        return
    with open(CARGO_LOCK, "r") as f:
        lines = f.readlines()
    in_vetto_block = False
    updated = False
    for i, line in enumerate(lines):
        if line.strip() == 'name = "vetto"':
            in_vetto_block = True
        elif in_vetto_block and line.startswith("version = "):
            lines[i] = f'version = "{new_ver}"\n'
            in_vetto_block = False
            updated = True
            break
        elif line.startswith("[[package]]"):
            in_vetto_block = False
    if updated:
        with open(CARGO_LOCK, "w") as f:
            f.writelines(lines)
        print("Updated Cargo.lock")

def update_versions_md(new_ver, next_ver, desc="Automated bump"):
    if not os.path.exists(VERSIONS_MD):
        return
    with open(VERSIONS_MD, "r") as f:
        content = f.read()
    
    today = time.strftime("%Y-%m-%d", time.gmtime())
    new_row = f"| **{new_ver}** | **{today}** | {desc} | GitHub release v{new_ver}, npm {new_ver}, crates.io {new_ver}, Homebrew tap {new_ver} |\n"
    
    # Insert before ## Следующая версия
    if "## Следующая версия:" in content:
        parts = content.split("## Следующая версия:")
        next_section = re.sub(r'\*\*[0-9\.]+\*\*', f'**{next_ver}**', parts[1], count=1)
        new_content = parts[0] + new_row + "\n## Следующая версия:" + next_section
        with open(VERSIONS_MD, "w") as f:
            f.write(new_content)
        print("Updated VERSIONS.md")

def update_debian_changelog(new_ver, desc="Bug fixes and improvements"):
    debian_changelog = os.path.join(REPO_ROOT, "debian", "changelog")
    if not os.path.exists(debian_changelog):
        return
    with open(debian_changelog, "r") as f:
        content = f.read()
    date_str = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    entry = f"""vetto ({new_ver}-1) unstable; urgency=medium

  * {desc}.

 -- vetto contributors <noreply@github.com>  {date_str}

"""
    with open(debian_changelog, "w") as f:
        f.write(entry + content)
    print("Updated debian/changelog")

def update_rpm_spec_changelog(new_ver, desc="Bug fixes and improvements"):
    if not os.path.exists(SPEC):
        return
    with open(SPEC, "r") as f:
        content = f.read()
    date_str = time.strftime("%a %b %d %Y", time.gmtime())
    entry = f"""* {date_str} vetto contributors - {new_ver}-1
- {desc}.

"""
    if "%changelog\n" in content:
        new_content = content.replace("%changelog\n", f"%changelog\n{entry}", 1)
        with open(SPEC, "w") as f:
            f.write(new_content)
        print("Updated packaging/rpm/vetto.spec changelog")

def main():
    current = get_current_version()
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = compute_next_version(current)
    
    next_after = compute_next_version(target)
    print(f"Bumping version: {current} -> {target} (next will be {next_after})")
    
    update_file(CARGO_TOML, r'^version\s*=\s*"[^"]+"', f'version = "{target}"')
    update_cargo_lock(current, target)
    update_file(PACKAGE_JSON, r'"version":\s*"[^"]+"', f'"version": "{target}"')
    update_file(PKGBUILD, r'^pkgver=.*', f'pkgver={target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto", "PKGBUILD"), r'^pkgver=.*', f'pkgver={target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto", ".SRCINFO"), r'^\s*pkgver\s*=\s*.*', f'\tpkgver = {target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto", ".SRCINFO"), rf'vetto-{re.escape(current)}\.tar\.gz', f'vetto-{target}.tar.gz')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto-git", ".SRCINFO"), r'^\s*pkgver\s*=\s*.*', f'\tpkgver = {target}')
    update_file(os.path.join(REPO_ROOT, "install.sh"), r'DEFAULT_FALLBACK_VERSION="[^"]+"', f'DEFAULT_FALLBACK_VERSION="{target}"')
    update_file(os.path.join(REPO_ROOT, "scripts", "install.sh"), r'DEFAULT_FALLBACK_VERSION="[^"]+"', f'DEFAULT_FALLBACK_VERSION="{target}"')
    update_file(NUSPEC, r'<version>[^<]+</version>', f'<version>{target}</version>')
    update_file(HOMEBREW_RB, r'version\s+"[^"]+"', f'version "{target}"')
    update_file(HOMEBREW_RB, rf'/v{re.escape(current)}/', f'/v{target}/', count=0)
    update_file(SPEC, r'^Version:\s*.*', f'Version: {target}')
    update_file(os.path.join(REPO_ROOT, "assets", "demo.svg"), rf'\[installed v{re.escape(current)}\]', f'[installed v{target}]')
    update_file(os.path.join(REPO_ROOT, "vscode", "package.json"), r'"version":\s*"[^"]+"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "plugins", "vscode", "package.json"), r'"version":\s*"[^"]+"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "editors", "vscode", "package.json"), r'"version":\s*"[^"]+"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "flake.nix"), r'version\s*=\s*"[^"]+"', f'version = "{target}"')
    update_file(os.path.join(REPO_ROOT, "scripts", "gen-sbom.sh"), rf'"version":\s*"{re.escape(current)}"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "npm", "README.md"), rf'Prebuilt targets in `{re.escape(current)}`:', f'Prebuilt targets in `{target}`:')
    update_file(os.path.join(REPO_ROOT, "deploy", "k8s", "daemonset.yaml"), rf'image:\s*ghcr\.io/shleder/vetto:{re.escape(current)}', f'image: ghcr.io/shleder/vetto:{target}')
    update_file(os.path.join(REPO_ROOT, "deploy", "helm", "vetto", "Chart.yaml"), rf'appVersion:\s*"[^"]+"', f'appVersion: "{target}"')
    update_file(os.path.join(REPO_ROOT, "README.md"), rf'/releases/tag/v{re.escape(current)}', f'/releases/tag/v{target}')
    update_file(os.path.join(REPO_ROOT, "README.md"), rf'badge/version-{re.escape(current)}-blue', f'badge/version-{target}-blue')
    update_file(os.path.join(REPO_ROOT, "docs", "README.ru.md"), rf'/releases/tag/v{re.escape(current)}', f'/releases/tag/v{target}')
    update_file(os.path.join(REPO_ROOT, "docs", "README.ru.md"), rf'badge/version-{re.escape(current)}-blue', f'badge/version-{target}-blue')
    
    # GitHub Actions
    update_file(os.path.join(REPO_ROOT, "action.yml"), r'\(e\.g\. "' + re.escape(current) + r'" or "latest"\)', f'(e.g. "{target}" or "latest")')
    update_file(os.path.join(REPO_ROOT, "action.yml"), rf'RESOLVED_TAG="v{re.escape(current)}"', f'RESOLVED_TAG="v{target}"')
    update_file(os.path.join(REPO_ROOT, "action", "action.yml"), r'\[ "\${ver}" = "latest" \] && ver="' + re.escape(current) + '"', f'[ "${{ver}}" = "latest" ] && ver="{target}"')
    update_file(os.path.join(REPO_ROOT, "action", "README.md"), rf'shleder/vetto/action@v{re.escape(current)}', f'shleder/vetto/action@v{target}', count=0)

    # Kubernetes manifests
    update_file(os.path.join(REPO_ROOT, "k8s", "daemonset.yaml"), rf'image:\s*ghcr\.io/shleder/vetto:{re.escape(current)}', f'image: ghcr.io/shleder/vetto:{target}')
    update_file(os.path.join(REPO_ROOT, "k8s", "vetto-sidecar.yaml"), rf'image:\s*ghcr\.io/shleder/vetto:{re.escape(current)}', f'image: ghcr.io/shleder/vetto:{target}')
    update_file(os.path.join(REPO_ROOT, "k8s", "deployment.yaml"), rf'image:\s*ghcr\.io/shleder/vetto-agent:{re.escape(current)}', f'image: ghcr.io/shleder/vetto-agent:{target}')

    # Packaging
    update_file(os.path.join(REPO_ROOT, "packaging", "macos", "build_pkg.sh"), r'VERSION="\${1:-' + re.escape(current) + r'}"', f'VERSION="${{1:-{target}}}"')
    update_file(os.path.join(REPO_ROOT, "packaging", "macos", "README.md"), rf'build_pkg\.sh {re.escape(current)}', f'build_pkg.sh {target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "macos", "README.md"), rf'vetto-{re.escape(current)}-', f'vetto-{target}-', count=0)
    update_file(os.path.join(REPO_ROOT, "packaging", "homebrew", "create-tap.sh"), rf'formula v{re.escape(current)}', f'formula v{target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "homebrew", "README.md"), rf'release v{re.escape(current)}', f'release v{target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto-git", "README.md"), rf'update vetto v{re.escape(current)}', f'update vetto v{target}')
    update_file(os.path.join(REPO_ROOT, "packaging", "aur", "vetto", ".SRCINFO"), rf'/v{re.escape(current)}\.tar\.gz', f'/v{target}.tar.gz')

    # VS Code
    update_file(os.path.join(REPO_ROOT, "plugins", "vscode", "package-lock.json"), rf'"version":\s*"{re.escape(current)}"', f'"version": "{target}"', count=0)
    update_file(os.path.join(REPO_ROOT, "vscode", "README.md"), rf'vetto-vscode-{re.escape(current)}\.vsix', f'vetto-vscode-{target}.vsix', count=0)

    # Documentation & Tutorials
    update_file(os.path.join(REPO_ROOT, "docs", "tutorials", "installing.md"), rf'@shledery/vetto@{re.escape(current)}', f'@shledery/vetto@{target}')
    update_file(os.path.join(REPO_ROOT, "docs", "SBOM.md"), rf'/tag/v{re.escape(current)}', f'/tag/v{target}')
    update_file(os.path.join(REPO_ROOT, "docs", "SBOM.md"), rf'release `v{re.escape(current)}`', f'release `v{target}`')
    update_file(os.path.join(REPO_ROOT, "docs", "security", "slsa-provenance.md"), rf'download v{re.escape(current)}', f'download v{target}')
    update_file(os.path.join(REPO_ROOT, "docs", "integrations", "opencode.md"), rf'"version":\s*"{re.escape(current)}"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "docs", "integrations", "claude-code.md"), rf'"version":\s*"{re.escape(current)}"', f'"version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "docs", "field-testing.md"), rf'current `{re.escape(current)}` package', f'current `{target}` package')
    update_file(os.path.join(REPO_ROOT, "docs", "architecture", "verify-ng.md"), r'Статус реализации \(' + re.escape(current) + r', факт\)', f'Статус реализации ({target}, факт)')
    update_file(os.path.join(REPO_ROOT, "docs", "threat-model.md"), r'Статус модели угроз \(' + re.escape(current) + r', факт\)', f'Статус модели угроз ({target}, факт)')
    update_file(os.path.join(REPO_ROOT, "docs", "telemetry.md"), rf'"vetto_version":\s*"{re.escape(current)}"', f'"vetto_version": "{target}"')
    update_file(os.path.join(REPO_ROOT, "docs", "telemetry.md"), r'\(e\.g\. `' + re.escape(current) + r'`\)', f'(e.g. `{target}`)')

    # Install scripts help
    update_file(os.path.join(REPO_ROOT, "install.sh"), r'\(e\.g\. ' + re.escape(current) + r'\)', f'(e.g. {target})')
    update_file(os.path.join(REPO_ROOT, "scripts", "install.sh"), r'\(e\.g\. ' + re.escape(current) + r'\)', f'(e.g. {target})')

    desc = sys.argv[2] if len(sys.argv) > 2 else "Maintenance and synchronization"
    update_debian_changelog(target, desc)
    update_rpm_spec_changelog(target, desc)
    update_versions_md(target, next_after, desc)
    print(f"\nVersion bump to {target} completed successfully across all manifests!")

if __name__ == "__main__":
    main()
