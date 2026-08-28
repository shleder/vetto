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

version="${VETTO_ACTION_VERSION:-0.2.3}"
use_prebuilt="${VETTO_ACTION_USE_PREBUILT:-true}"
prebuilt_ok=false

if [[ "${use_prebuilt}" == "true" || "${use_prebuilt}" == "1" ]]; then
  kernel="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "${kernel}" in
    linux) os="linux" ;;
    darwin) os="macos" ;;
    msys*|mingw*|cygwin*) os="windows" ;;
    *) os="${kernel}" ;;
  esac

  case "${arch}" in
    x86_64|amd64) target_arch="x86_64" ;;
    aarch64|arm64) target_arch="aarch64" ;;
    *) target_arch="${arch}" ;;
  esac

  archive_name="vetto-${os}-${target_arch}.tar.gz"
  download_url="https://github.com/shleder/vetto/releases/download/v${version}/${archive_name}"
  temp_dir="${RUNNER_TEMP:-/tmp}/vetto-action-bin"
  mkdir -p "${temp_dir}"

  echo "vetto action: fetching precompiled binary from ${download_url}..."
  if curl -sSLf --retry 3 --connect-timeout 5 "${download_url}" | tar -xz -C "${temp_dir}" 2>/dev/null; then
    if [[ -x "${temp_dir}/vetto" ]]; then
      binary="${temp_dir}/vetto"
      prebuilt_ok=true
      echo "vetto action: successfully loaded native binary (${os}-${target_arch} v${version})"
    fi
  fi
fi

if [[ "${prebuilt_ok}" != "true" ]]; then
  echo "vetto action: precompiled binary unavailable, building from source via cargo..."
  cargo build --locked --release --manifest-path "${manifest}"
fi

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
