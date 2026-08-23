#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "${GITHUB_ACTION_PATH}/.." && pwd -P)"
manifest="${repo_root}/Cargo.toml"
binary="${repo_root}/target/release/vetto"
report_dir="${VETTO_ACTION_REPORT_DIR}"

if [[ ! -f "${manifest}" ]]; then
  echo "vetto action: Cargo.toml not found at ${manifest}" >&2
  exit 2
fi

if [[ -z "${VETTO_ACTION_COMMAND}" ]]; then
  echo "vetto action: input 'command' must not be empty" >&2
  exit 2
fi

mkdir -p -- "${report_dir}"
cargo build --locked --release --manifest-path "${manifest}"

args=(
  --ci
  --profile "${VETTO_ACTION_PROFILE}"
  --net "${VETTO_ACTION_NET}"
  --report "${VETTO_ACTION_REPORT}"
  --report-dir "${report_dir}"
)

case "${VETTO_ACTION_FAIL_ON_BLOCK,,}" in
  ""|false|0)
    ;;
  true)
    args+=(--fail-on-block=1)
    ;;
  *[!0-9]*)
    echo "vetto action: fail-on-block must be true, false, or a positive integer" >&2
    exit 2
    ;;
  *)
    args+=("--fail-on-block=${VETTO_ACTION_FAIL_ON_BLOCK}")
    ;;
esac

set +e
"${binary}" "${args[@]}" -- bash -lc "${VETTO_ACTION_COMMAND}"
vetto_status=$?
set -e

sarif_path=""
while IFS= read -r -d '' candidate; do
  sarif_path="${candidate}"
done < <(find "${report_dir}" -maxdepth 1 -type f -name '*.sarif' -print0 | sort -z)

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'exit-code=%s\n' "${vetto_status}" >> "${GITHUB_OUTPUT}"
  printf 'sarif-path=%s\n' "${sarif_path}" >> "${GITHUB_OUTPUT}"
fi

exit "${vetto_status}"
