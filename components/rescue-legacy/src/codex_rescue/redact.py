from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

SECRET_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{16,})"), "[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,})"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)(gh[opusr]_[a-zA-Z0-9]{20,})"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?i)(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"), "[REDACTED_JWT]"),
    (re.compile(r"""(?i)(api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"])"""), "[REDACTED_API_KEY]"),
    (re.compile(r"""(?i)(password\s*[:=]\s*['"][^\s'"]{6,}['"])"""), "[REDACTED_PASSWORD]"),
    (re.compile(r"(?i)(cookie\s*:\s*[^\r\n]+)"), "[REDACTED_COOKIE]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[REDACTED_EMAIL]"),
]

PATH_PATTERNS = [
    (re.compile(r"/Users/[a-zA-Z0-9_\-\.]+"), "~"),
    (re.compile(r"/home/[a-zA-Z0-9_\-\.]+"), "~"),
    (re.compile(r"(?i)[a-z]:\\users\\[a-zA-Z0-9_\-\.]+"), "~"),
]


def redact_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    result = text
    for pattern, repl in SECRET_PATTERNS:
        result = pattern.sub(repl, result)
    for pattern, repl in PATH_PATTERNS:
        result = pattern.sub(repl, result)
    return result


def sanitize_path(path_str: str | Path) -> str:
    if not path_str:
        return ""
    p = str(path_str).replace("\\", "/")
    user = os.environ.get("USER") or os.environ.get("USERNAME")
    if user and user in p:
        p = p.replace(f"/home/{user}", "~").replace(f"/Users/{user}", "~")
    for pattern, repl in PATH_PATTERNS:
        p = pattern.sub(repl, p)
    return p


def audit_privacy(data: Any, path_prefix: str = "") -> list[str]:
    violations: list[str] = []
    if isinstance(data, str):
        for pattern, repl in SECRET_PATTERNS:
            if pattern.search(data):
                violations.append(f"Secret detected at {path_prefix or 'root'}: matches {repl}")
        for pattern, _ in PATH_PATTERNS:
            if pattern.search(data):
                violations.append(f"Unsanitized user home path at {path_prefix or 'root'}")
    elif isinstance(data, dict):
        for k, v in data.items():
            key_str = str(k).lower()
            if any(forbidden in key_str for forbidden in ("prompt_raw", "raw_assistant_message", "tool_input_raw", "tool_output_raw", "secret_key")):
                violations.append(f"Forbidden raw payload key '{k}' found at {path_prefix}")
            violations.extend(audit_privacy(v, f"{path_prefix}.{k}" if path_prefix else str(k)))
    elif isinstance(data, (list, tuple, set)):
        for idx, item in enumerate(data):
            violations.extend(audit_privacy(item, f"{path_prefix}[{idx}]"))
    return violations
