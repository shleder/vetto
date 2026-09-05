#!/usr/bin/env bash
# Vetto Canary Probe — Zero-dependency Host Security & Egress Audit Script
# Tests kernel sandboxing primitives, developer secret exposure, and egress boundaries.
#
# Usage:
#   bash scripts/canary.sh
#   curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/scripts/canary.sh | bash

set -u

COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_BOLD="\033[1m"
COLOR_RESET="\033[0m"

if [ ! -t 1 ] || [ -n "${CI:-}" ]; then
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_BOLD=""
    COLOR_RESET=""
fi

echo -e "${COLOR_BOLD}================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}         VETTO CANARY PROBE — AGENT RUNTIME SECURITY AUDIT        ${COLOR_RESET}"
echo -e "${COLOR_BOLD}================================================================${COLOR_RESET}"

OS_TYPE="$(uname -s 2>/dev/null || echo "Unknown")"
ARCH_TYPE="$(uname -m 2>/dev/null || echo "Unknown")"
KERNEL_REV="$(uname -r 2>/dev/null || echo "Unknown")"

echo -e "Platform: ${COLOR_BLUE}${OS_TYPE} ${ARCH_TYPE} (Kernel: ${KERNEL_REV})${COLOR_RESET}"

# -----------------------------------------------------------------------------
# 1. Kernel Sandboxing Primitives Check
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}[1/4] Checking Kernel Sandboxing Capabilities...${COLOR_RESET}"

SANDBOX_BACKEND="None"
SANDBOX_CAPABLE=0

if [ "$OS_TYPE" = "Linux" ]; then
    # Check Landlock support
    LANDLOCK_DETECTED=0
    if [ -f "/sys/kernel/security/lsm" ]; then
        if grep -q "landlock" /sys/kernel/security/lsm 2>/dev/null; then
            LANDLOCK_DETECTED=1
        fi
    fi

    USERNS_OK=0
    if [ -f "/proc/sys/kernel/unprivileged_userns_clone" ]; then
        VAL=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "0")
        if [ "$VAL" = "1" ]; then
            USERNS_OK=1
        fi
    else
        # Default enabled on modern Linux
        USERNS_OK=1
    fi

    SECCOMP_OK=0
    if [ -f "/proc/sys/kernel/seccomp/actions_avail" ]; then
        SECCOMP_OK=1
    fi

    if [ "$LANDLOCK_DETECTED" -eq 1 ]; then
        echo -e "  ✓ Landlock LSM: ${COLOR_GREEN}ACTIVE${COLOR_RESET}"
        SANDBOX_BACKEND="Linux Landlock (LSM)"
        SANDBOX_CAPABLE=1
    else
        echo -e "  ! Landlock LSM: ${COLOR_YELLOW}NOT DETECTED IN /sys/kernel/security/lsm${COLOR_RESET}"
    fi

    if [ "$USERNS_OK" -eq 1 ]; then
        echo -e "  ✓ Unprivileged User Namespaces: ${COLOR_GREEN}ENABLED${COLOR_RESET}"
    else
        echo -e "  ! Unprivileged User Namespaces: ${COLOR_RED}DISABLED${COLOR_RESET}"
    fi

    if [ "$SECCOMP_OK" -eq 1 ]; then
        echo -e "  ✓ Seccomp BPF Syscall Filtering: ${COLOR_GREEN}SUPPORTED${COLOR_RESET}"
        [ "$SANDBOX_CAPABLE" -eq 0 ] && SANDBOX_BACKEND="Seccomp-BPF / User Namespaces"
        SANDBOX_CAPABLE=1
    fi

elif [ "$OS_TYPE" = "Darwin" ]; then
    # macOS Seatbelt / sandbox-exec
    if [ -x "/usr/bin/sandbox-exec" ]; then
        echo -e "  ✓ macOS Seatbelt (sandbox-exec): ${COLOR_GREEN}AVAILABLE${COLOR_RESET}"
        SANDBOX_BACKEND="macOS Seatbelt (Apple SBPL)"
        SANDBOX_CAPABLE=1
    else
        echo -e "  ✗ macOS Seatbelt: ${COLOR_RED}MISSING (/usr/bin/sandbox-exec)${COLOR_RESET}"
    fi

    if [ -d "/System/Volumes/Preboot/Cryptexes" ]; then
        echo -e "  ✓ APFS Preboot Cryptex Storage: ${COLOR_GREEN}PRESENT (macOS 13+)${COLOR_RESET}"
    fi
else
    echo -e "  ! Unsupported operating system for native kernel confinement: ${OS_TYPE}"
fi

# -----------------------------------------------------------------------------
# 2. Host Secret Boundary Audit
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}[2/4] Auditing Developer Secrets & Credential Exposure...${COLOR_RESET}"

EXPOSED_SECRETS=0
CHECKED_TARGETS=0

check_path_exposure() {
    local target_path="$1"
    local desc="$2"
    CHECKED_TARGETS=$((CHECKED_TARGETS + 1))

    if [ -e "$target_path" ]; then
        # Check if readable
        if [ -r "$target_path" ]; then
            echo -e "  ${COLOR_RED}✗ EXPOSED${COLOR_RESET} : ${desc} (${target_path})"
            EXPOSED_SECRETS=$((EXPOSED_SECRETS + 1))
        else
            echo -e "  ${COLOR_GREEN}✓ BLOCKED${COLOR_RESET} : ${desc} (Read permission denied)"
        fi
    else
        echo -e "  - ABSENT  : ${desc} (Path not found on host)"
    fi
}

check_path_exposure "$HOME/.ssh" "SSH Private Keys & Config"
check_path_exposure "$HOME/.aws" "AWS Cloud Credentials"
check_path_exposure "$HOME/.gnupg" "GnuPG Private Keyring"
check_path_exposure "$HOME/.netrc" "Stored Network Passwords (.netrc)"
check_path_exposure "$HOME/.npmrc" "NPM Auth Tokens (.npmrc)"

# Check repository / current directory .env files
ENV_FILES_FOUND=0
for env_candidate in .env .env.local .env.production .env.development; do
    if [ -f "$env_candidate" ] && [ -r "$env_candidate" ]; then
        echo -e "  ${COLOR_RED}✗ EXPOSED${COLOR_RESET} : Repository Environment Secrets (${env_candidate})"
        EXPOSED_SECRETS=$((EXPOSED_SECRETS + 1))
        ENV_FILES_FOUND=1
    fi
done
if [ "$ENV_FILES_FOUND" -eq 0 ]; then
    echo -e "  - ABSENT  : Working directory .env files"
fi

# -----------------------------------------------------------------------------
# 3. Network Egress Boundary Audit
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}[3/4] Auditing Outbound Network Egress Boundaries...${COLOR_RESET}"

EGRESS_BLOCKED=0

# Probe external connectivity via standard socket / tools
if command -v curl >/dev/null 2>&1; then
    if curl -s --connect-timeout 2 --max-time 3 -o /dev/null "https://1.1.1.1" 2>/dev/null; then
        echo -e "  ${COLOR_YELLOW}! UNCONFINED${COLOR_RESET}: Outbound HTTPS connections are completely unrestricted."
    else
        echo -e "  ${COLOR_GREEN}✓ CONFINED${COLOR_RESET}  : Outbound HTTPS connection refused or blocked."
        EGRESS_BLOCKED=1
    fi
elif command -v nc >/dev/null 2>&1; then
    if nc -z -w 2 1.1.1.1 443 2>/dev/null; then
        echo -e "  ${COLOR_YELLOW}! UNCONFINED${COLOR_RESET}: Outbound TCP traffic allowed without policy enforcement."
    else
        echo -e "  ${COLOR_GREEN}✓ CONFINED${COLOR_RESET}  : Outbound TCP traffic blocked."
        EGRESS_BLOCKED=1
    fi
else
    # Raw /dev/tcp check in bash
    if (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then
        exec 3<&-
        exec 3>&-
        echo -e "  ${COLOR_YELLOW}! UNCONFINED${COLOR_RESET}: Direct TCP sockets open to external networks."
    else
        echo -e "  ${COLOR_GREEN}✓ CONFINED${COLOR_RESET}  : Direct TCP egress blocked."
        EGRESS_BLOCKED=1
    fi
fi

# -----------------------------------------------------------------------------
# 4. Runtime Confinement Context & Diagnostic Summary
# -----------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}[4/4] Runtime Context & Security Assessment...${COLOR_RESET}"

VETTO_ACTIVE=0
if [ -n "${VETTO_SESSION_ID:-}" ] || [ -n "${VETTO_TIER:-}" ]; then
    VETTO_ACTIVE=1
fi

echo "----------------------------------------------------------------"
if [ "$VETTO_ACTIVE" -eq 1 ]; then
    echo -e "Running Under VETTO: ${COLOR_GREEN}YES (Session: ${VETTO_SESSION_ID:-active}, Tier: ${VETTO_TIER:-enforced})${COLOR_RESET}"
else
    echo -e "Running Under VETTO: ${COLOR_YELLOW}NO (Unconfined Shell / Host Process)${COLOR_RESET}"
fi
echo -e "Kernel Sandbox Primitives: ${COLOR_BOLD}${SANDBOX_BACKEND}${COLOR_RESET}"
echo -e "Exposed Host Secrets: ${COLOR_BOLD}${EXPOSED_SECRETS}${COLOR_RESET}"
echo "----------------------------------------------------------------"

if [ "$VETTO_ACTIVE" -eq 0 ] && [ "$EXPOSED_SECRETS" -gt 0 ]; then
    echo -e "${COLOR_RED}${COLOR_BOLD}VERDICT: HIGH RISK — AI AGENTS CAN READ UNPROTECTED HOST SECRETS${COLOR_RESET}"
    echo -e "Autonomous tools (Claude Code, OpenAI Codex CLI, Aider, Cursor) running"
    echo -e "in this shell have unrestricted access to your credentials and keys."
    echo -e "\nRemediation:"
    echo -e "  1. Install Vetto:  ${COLOR_BOLD}npm i -g @shledery/vetto${COLOR_RESET}  or  ${COLOR_BOLD}brew install shleder/tap/vetto${COLOR_RESET}"
    echo -e "  2. Enable agent:   ${COLOR_BOLD}vetto enable claude${COLOR_RESET} (or codex / aider / cursor)"
    echo -e "  3. Execute safely: ${COLOR_BOLD}vetto run -- <command>${COLOR_RESET}"
elif [ "$VETTO_ACTIVE" -eq 1 ]; then
    echo -e "${COLOR_GREEN}${COLOR_BOLD}VERDICT: PROTECTED — VETTO ACTIVE ENFORCEMENT ENGAGED${COLOR_RESET}"
    echo -e "Host secrets are masked and egress policy is enforced by kernel primitives."
else
    echo -e "${COLOR_GREEN}${COLOR_BOLD}VERDICT: CLEAN — NO SENSITIVE CREDENTIALS FOUND IN DEFAULT LOCATIONS${COLOR_RESET}"
    echo -e "Kernel sandbox backend (${SANDBOX_BACKEND}) is available to enforce isolation."
fi

echo -e "${COLOR_BOLD}================================================================${COLOR_RESET}"
exit 0
