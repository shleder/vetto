#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${VETTO_ACTION_COMMAND:-}" ]]; then
  echo "vetto action: input 'command' must not be empty" >&2
  exit 2
fi

binary="vetto"
if ! command -v "${binary}" >/dev/null 2>&1; then
  if [[ -x "${HOME}/.local/bin/vetto" ]]; then
    binary="${HOME}/.local/bin/vetto"
  else
    echo "vetto action: vetto executable not found in PATH" >&2
    exit 127
  fi
fi

report_dir="${VETTO_ACTION_REPORT_DIR:-.vetto/reports}"
mkdir -p -- "${report_dir}"

args=(
  --ci
  --profile "${VETTO_ACTION_PROFILE:-strict}"
  --net "${VETTO_ACTION_NET:-off}"
  --report "${VETTO_ACTION_REPORT:-json,sarif}"
  --report-dir "${report_dir}"
)

if [[ -n "${VETTO_ACTION_POLICY:-}" ]]; then
  args+=(--policy "${VETTO_ACTION_POLICY}")
fi

case "${VETTO_ACTION_FAIL_ON_BLOCK:-false}" in
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

echo "vetto action: executing '${binary} ${args[*]} -- bash -lc \"${VETTO_ACTION_COMMAND}\"'"

set +e
"${binary}" "${args[@]}" -- bash -lc "${VETTO_ACTION_COMMAND}"
vetto_status=$?
set -e

sarif_path=""
if [[ -d "${report_dir}" ]]; then
  while IFS= read -r -d '' candidate; do
    sarif_path="${candidate}"
  done < <(find "${report_dir}" -maxdepth 1 -type f -name '*.sarif' -print0 2>/dev/null | sort -z)
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'exit-code=%s\n' "${vetto_status}" >> "${GITHUB_OUTPUT}"
  printf 'sarif-path=%s\n' "${sarif_path}" >> "${GITHUB_OUTPUT}"
fi

exit "${vetto_status}"
