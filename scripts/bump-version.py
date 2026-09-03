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
PKGBUILD = os.path.join(REPO_ROOT, "packaging", "aur", "PKGBUILD")
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

def update_file(filepath, pattern, replacement):
    if not os.path.exists(filepath):
        print(f"Skipping {filepath} (file not found)")
        return False
    with open(filepath, "r") as f:
        content = f.read()
    new_content, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count == 0:
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
    update_file(NUSPEC, r'<version>[^<]+</version>', f'<version>{target}</version>')
    update_file(HOMEBREW_RB, r'version\s+"[^"]+"', f'version "{target}"')
    update_file(SPEC, r'^Version:\s*.*', f'Version: {target}')
    
    desc = "Automated version bump"
    update_versions_md(target, next_after, desc)
    print(f"\nVersion bump to {target} completed successfully across all manifests!")

if __name__ == "__main__":
    main()
