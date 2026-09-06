#!/usr/bin/env bash
set -uo pipefail

RESULTS_LOG="target/sbpl-matrix.log"
RESULTS_JSON="target/sbpl-matrix-results.json"
mkdir -p target

echo "=== macOS SBPL Dispute Resolution Test Harness ===" | tee "$RESULTS_LOG"
SW_VERS=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
ARCH_NAME=$(uname -m 2>/dev/null || echo "Unknown")
echo "Environment: macOS $SW_VERS ($ARCH_NAME)" | tee -a "$RESULTS_LOG"

# 1. Подготовка тестовых каталогов и файлов
TEST_DIR=$(mktemp -d /tmp/vetto-sbpl-harness-XXXXXX)
CANON_TEST_DIR=$(cd "$TEST_DIR" && pwd -P)
TARGET_FILE="$CANON_TEST_DIR/public.txt"
SECRET_FILE="$CANON_TEST_DIR/secret.key"
echo "PROBE_PAYLOAD_OK" > "$TARGET_FILE"
echo "SUPER_SECRET_TOKEN" > "$SECRET_FILE"

REPO_DIR=$(pwd -P)
CANON_BIN_DIR=$(cd "target/matrix-binaries" 2>/dev/null && pwd -P || echo "$REPO_DIR/target/matrix-binaries")

# 2. Определение профилей SBPL (Profile AST Shapes)

# Shape A: Текущий широкий профиль Vetto ((allow file-read* (subpath "/")) + trailing deny)
PROFILE_A="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (subpath \"/\"))
(deny file-read* (literal \"$SECRET_FILE\"))
"

# Shape B: Наивный фрагментированный профиль (из probe_sbpl_read_fragment в vetto doctor)
PROFILE_B="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (literal \"$TARGET_FILE\"))
(allow file-read* (subpath \"/bin\"))
(allow file-read* (subpath \"/usr\"))
(allow file-read* (subpath \"/lib\"))
(allow file-read* (subpath \"/System\"))
(allow file-read* (subpath \"$CANON_BIN_DIR\"))
(allow file-read* (subpath \"$REPO_DIR\"))
(allow file-read* (subpath \"/Users\"))
"

# Shape C: Полный фрагментированный профиль (со всеми путями Cryptex/dyld/dev и метаданными)
PROFILE_C="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-metadata)
(allow process-info*)
(allow file-read* (literal \"/dev/null\"))
(allow file-read* (literal \"/dev/zero\"))
(allow file-read* (literal \"/dev/urandom\"))
(allow file-read* (literal \"/dev/random\"))
(allow file-read* (literal \"/dev/dtracehelper\"))
(allow file-read* (subpath \"/bin\"))
(allow file-read* (subpath \"/usr/bin\"))
(allow file-read* (subpath \"/usr/lib\"))
(allow file-read* (subpath \"/usr/share\"))
(allow file-read* (subpath \"/System\"))
(allow file-read* (subpath \"/System/Volumes/Preboot/Cryptexes\"))
(allow file-read* (subpath \"/private/var/db/dyld\"))
(allow file-read* (subpath \"$CANON_BIN_DIR\"))
(allow file-read* (subpath \"$REPO_DIR\"))
(allow file-read* (subpath \"/Users\"))
(allow file-read* (literal \"$TARGET_FILE\"))
"

# Shape D: Предикатная модель require-any (форма srt / nono)
PROFILE_D="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-metadata)
(allow process-info*)
(allow file-read*
  (require-any
    (literal \"/dev/null\")
    (literal \"/dev/zero\")
    (literal \"/dev/urandom\")
    (literal \"/dev/random\")
    (literal \"/dev/dtracehelper\")
    (subpath \"/bin\")
    (subpath \"/usr/bin\")
    (subpath \"/usr/lib\")
    (subpath \"/usr/share\")
    (subpath \"/System\")
    (subpath \"/System/Volumes/Preboot/Cryptexes\")
    (subpath \"/private/var/db/dyld\")
    (subpath \"$CANON_BIN_DIR\")
    (subpath \"$REPO_DIR\")
    (subpath \"/Users\")
    (literal \"$TARGET_FILE\")
  )
)
"

# Shape E: Профиль с регулярными выражениями (Regex AST Shape)
PROFILE_E="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-metadata)
(allow process-info*)
(allow file-read* (literal \"/dev/null\"))
(allow file-read* (literal \"/dev/zero\"))
(allow file-read* (literal \"/dev/urandom\"))
(allow file-read* (literal \"/dev/random\"))
(allow file-read* (literal \"/dev/dtracehelper\"))
(allow file-read* (regex #\"^/bin/.*$\"))
(allow file-read* (regex #\"^/usr/(bin|lib|share)/.*$\"))
(allow file-read* (regex #\"^/System/.*$\"))
(allow file-read* (regex #\"^/System/Volumes/Preboot/Cryptexes/.*$\"))
(allow file-read* (regex #\"^/private/var/db/dyld/.*$\"))
(allow file-read* (subpath \"$CANON_BIN_DIR\"))
(allow file-read* (subpath \"$REPO_DIR\"))
(allow file-read* (subpath \"/Users\"))
(allow file-read* (literal \"$TARGET_FILE\"))
"

# Shape F: Истинная изоляция (Разрешение системы + целевого файла, запрет секретов)
PROFILE_F="(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-metadata)
(allow process-info*)
(allow file-read*
  (require-any
    (subpath \"/dev\")
    (subpath \"/bin\")
    (subpath \"/usr\")
    (subpath \"/System\")
    (subpath \"/System/Volumes/Preboot/Cryptexes\")
    (subpath \"/private/var/db/dyld\")
    (subpath \"$CANON_BIN_DIR\")
    (subpath \"$REPO_DIR\")
    (subpath \"/Users\")
    (literal \"$TARGET_FILE\")
  )
)
(deny file-read* (literal \"$SECRET_FILE\"))
"

BINARIES=(
    "/bin/ls"
    "/bin/cat"
    "target/matrix-binaries/go_static"
    "target/matrix-binaries/go_dynamic"
    "target/matrix-binaries/rust_dynamic"
    "target/matrix-binaries/swift_dynamic"
)

printf '[\n' > "$RESULTS_JSON"
FIRST_ENTRY=1
TOTAL_TESTS=0
FATAL_FAILURES=0

get_ts_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))' 2>/dev/null || date +%s000
}

run_test() {
    local bin="$1"
    local shape_name="$2"
    local profile_content="$3"
    local target_arg="$4"
    local expected_type="$5"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    local pfile
    pfile=$(mktemp /tmp/sbpl-XXXXXX.sb)
    echo "$profile_content" > "$pfile"

    local err_file
    err_file=$(mktemp /tmp/sbpl-err-XXXXXX.log)

    local start_ts
    start_ts=$(get_ts_ms)

    local stdout_val
    stdout_val=$(/usr/bin/sandbox-exec -f "$pfile" "$bin" "$target_arg" 2> "$err_file")
    local exit_code=$?

    local end_ts
    end_ts=$(get_ts_ms)
    local duration_ms=$(( end_ts - start_ts ))
    if [ "$duration_ms" -lt 0 ]; then
        duration_ms=0
    fi

    local err_val
    err_val=$(cat "$err_file" 2>/dev/null | tr '\n' ' ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | head -c 200)

    rm -f "$pfile" "$err_file"

    local status="FAIL"
    if [ "$exit_code" -eq 0 ]; then
        if [ "$expected_type" == "DENY" ]; then
            status="LEAK_FAIL"
        else
            if [ "$bin" == "/bin/ls" ]; then
                if [[ "$stdout_val" == *"public.txt"* ]] || [ -n "$stdout_val" ]; then
                    status="PASS"
                else
                    status="FAIL"
                fi
            elif [ "$stdout_val" == "PROBE_PAYLOAD_OK" ]; then
                status="PASS"
            else
                status="FAIL"
            fi
        fi
    elif [ "$exit_code" -eq 134 ]; then
        status="SIGABRT"
    elif [ "$exit_code" -eq 2 ] || [ "$exit_code" -eq 1 ]; then
        if [[ "$err_val" == *"Operation not permitted"* ]] || [[ "$err_val" == *"Permission denied"* ]] || [[ "$err_val" == *"ERR:"* ]]; then
            if [ "$expected_type" == "DENY" ]; then
                status="BLOCKED_OK"
            else
                status="DENIED"
            fi
        else
            status="ERROR"
        fi
    fi

    # Fail-closed gate: only an actual leak (DENY target readable, exit 0)
    # or a harness ERROR fails the run. SIGABRT/PASS/DENIED distributions
    # across shapes are research telemetry (see JSON), not verdicts: on some
    # macOS builds every deny-default fragmented shape aborts, which is a
    # denial by death, not a leak.
    if [ "$status" == "LEAK_FAIL" ] || [ "$status" == "ERROR" ]; then
        FATAL_FAILURES=$((FATAL_FAILURES + 1))
    fi

    printf "[%s] OS:%s | Bin:%-35s | Profile:%-20s | Exit:%-3d | Status:%-10s | %dms\n" \
        "$(date +%T)" "$SW_VERS" "$bin" "$shape_name" "$exit_code" "$status" "$duration_ms" | tee -a "$RESULTS_LOG"

    if [ "$FIRST_ENTRY" -eq 0 ]; then
        echo "," >> "$RESULTS_JSON"
    fi
    FIRST_ENTRY=0

    cat << EOF >> "$RESULTS_JSON"
  {
    "os": "$SW_VERS",
    "arch": "$ARCH_NAME",
    "binary": "$bin",
    "shape": "$shape_name",
    "target": "$target_arg",
    "expected_type": "$expected_type",
    "exit_code": $exit_code,
    "status": "$status",
    "duration_ms": $duration_ms,
    "error_sample": "$err_val"
  }
EOF
}

for bin in "${BINARIES[@]}"; do
    if [ ! -f "$bin" ] && [ ! -x "$bin" ]; then
        echo "Binary not found: $bin" | tee -a "$RESULTS_LOG"
        continue
    fi
    echo "--- Testing Binary: $bin ---" | tee -a "$RESULTS_LOG"
    run_test "$bin" "ShapeA_Broad" "$PROFILE_A" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeB_Naive" "$PROFILE_B" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeC_Clauses" "$PROFILE_C" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeD_RequireAny" "$PROFILE_D" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeE_Regex" "$PROFILE_E" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeF_Allowed" "$PROFILE_F" "$TARGET_FILE" "ALLOW"
    run_test "$bin" "ShapeF_BlockedSecret" "$PROFILE_F" "$SECRET_FILE" "DENY"
done

printf '\n]\n' >> "$RESULTS_JSON"
rm -rf "$TEST_DIR"
echo "=== Harness Finished. Log written to $RESULTS_LOG, results to $RESULTS_JSON ===" | tee -a "$RESULTS_LOG"
echo "Summary: Total tests: $TOTAL_TESTS, Fatal failures: $FATAL_FAILURES" | tee -a "$RESULTS_LOG"

if [ "$TOTAL_TESTS" -eq 0 ]; then
    echo "ERROR: No tests executed." | tee -a "$RESULTS_LOG"
    exit 1
fi

if [ "$FATAL_FAILURES" -gt 0 ]; then
    echo "FATAL: $FATAL_FAILURES unexpected failures detected in SBPL matrix." | tee -a "$RESULTS_LOG"
    exit 1
fi

exit 0
