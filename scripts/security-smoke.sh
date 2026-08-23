#!/usr/bin/env bash
set -u

binary=${1:-./target/release/vetto}
case "$binary" in
  /*) ;;
  *) binary="$(pwd -P)/${binary#./}" ;;
esac
if [[ ! -x "$binary" ]]; then
  echo "smoke: vetto binary is not executable: $binary" >&2
  exit 2
fi

smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/vetto-smoke.XXXXXXXX") || exit 2
case "$smoke_root" in
  "${TMPDIR:-/tmp}"/vetto-smoke.*) ;;
  *) echo "smoke: unsafe temporary path" >&2; exit 2 ;;
esac
cleanup() {
  rm -rf -- "$smoke_root"
}
trap cleanup EXIT

project="$smoke_root/project"
fake_home="$smoke_root/home"
mkdir -p "$project" "$fake_home/.ssh"
printf 'VETTO_FAKE_PRIVATE_KEY\n' > "$fake_home/.ssh/id_rsa"
printf 'VETTO_DOTENV_SECRET=1\n' > "$project/.env"
ln -s /etc/passwd "$project/x"

failures=0
run_capture() {
  local label=$1
  shift
  local output_file="$smoke_root/$label.out"
  local error_file="$smoke_root/$label.err"
  (cd "$project" && HOME="$fake_home" "$@") >"$output_file" 2>"$error_file"
  return $?
}
failed() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}

if ! HOME="$fake_home" "$binary" doctor >"$smoke_root/doctor.out" 2>"$smoke_root/doctor.err"; then
  failed doctor
fi

run_capture ssh "$binary" --tui=none -- sh -c 'cat "$HOME/.ssh/id_rsa"'
ssh_status=$?
if [[ $ssh_status -eq 0 ]] || grep -q 'VETTO_FAKE_PRIVATE_KEY' "$smoke_root/ssh.out"; then
  failed ssh-secret
fi

run_capture dotenv "$binary" --tui=none -- cat ./.env
dotenv_status=$?
if grep -q 'VETTO_DOTENV_SECRET' "$smoke_root/dotenv.out"; then
  failed project-dotenv
elif [[ $dotenv_status -eq 0 && -s "$smoke_root/dotenv.out" ]]; then
  failed project-dotenv-nonempty
fi

run_capture symlink "$binary" --tui=none -- cat ./x
symlink_status=$?
if [[ $symlink_status -eq 0 ]] || grep -q '^root:' "$smoke_root/symlink.out"; then
  failed symlink-escape
fi

if command -v curl >/dev/null 2>&1; then
  run_capture network "$binary" --tui=none -- curl -fsS --max-time 5 http://example.com
  network_status=$?
  if [[ $network_status -eq 0 ]]; then
    failed network-off
  fi
else
  echo "SKIP curl unavailable"
fi

GH_TOKEN=VETTO_GH_SECRET \
OPENAI_API_KEY=VETTO_OPENAI_SECRET \
AWS_SECRET_ACCESS_KEY=VETTO_AWS_SECRET \
ANTHROPIC_API_KEY=VETTO_ANTHROPIC_SECRET \
  run_capture environment "$binary" --tui=none -- env
environment_status=$?
if [[ $environment_status -ne 0 ]]; then
  failed environment-command
elif grep -qE 'VETTO_(GH|OPENAI|AWS|ANTHROPIC)_SECRET' "$smoke_root/environment.out"; then
  failed environment-leak
fi

if [[ $failures -ne 0 ]]; then
  echo "security smoke: $failures failure(s)" >&2
  exit 1
fi
echo "security smoke: PASS"
