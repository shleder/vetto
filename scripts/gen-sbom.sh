#!/usr/bin/env bash
# Generate CycloneDX SBOM for Vetto dependencies from Cargo.lock
set -euo pipefail

OUTPUT_FILE="${1:-vetto-sbom.cyclonedx.json}"

echo "==> Generating Software Bill of Materials (SBOM) -> ${OUTPUT_FILE}..."

if command -v cargo-cyclonedx >/dev/null 2>&1; then
    cargo cyclonedx --format json --output-pattern "${OUTPUT_FILE}"
    echo "==> SBOM successfully generated using cargo-cyclonedx."
    exit 0
fi

# Fallback python generator parsing Cargo.lock
python3 - <<'PY' "$OUTPUT_FILE"
import sys
import json
import uuid
import datetime

output_path = sys.argv[1]

packages = []
current_pkg = {}

try:
    with open("Cargo.lock", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "[[package]]":
                if current_pkg and "name" in current_pkg:
                    packages.append(current_pkg)
                current_pkg = {}
            elif "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                if key in ("name", "version", "source", "checksum"):
                    current_pkg[key] = val
        if current_pkg and "name" in current_pkg:
            packages.append(current_pkg)
except FileNotFoundError:
    print("Error: Cargo.lock not found", file=sys.stderr)
    sys.exit(1)

components = []
for pkg in packages:
    comp = {
        "type": "library",
        "name": pkg["name"],
        "version": pkg.get("version", "unknown"),
        "purl": f"pkg:cargo/{pkg['name']}@{pkg.get('version', '')}",
    }
    if "checksum" in pkg:
        comp["hashes"] = [
            {
                "alg": "SHA-256",
                "content": pkg["checksum"]
            }
        ]
    components.append(comp)

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "component": {
            "type": "application",
            "name": "vetto",
            "version": "0.2.5",
            "description": "Daemon-less sandbox + security layer for AI coding agents",
        }
    },
    "components": components
}

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(sbom, f, indent=2)

print(f"==> Generated CycloneDX 1.5 SBOM with {len(components)} components.")
PY
