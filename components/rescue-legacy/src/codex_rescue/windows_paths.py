from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable


_DRIVE_ABS_RE = re.compile(r"(?i)^([a-z]):[\\/](.*)$")
_EXT_DRIVE_RE = re.compile(r"(?i)^(?:\\\\\?\\|//\?/)([a-z]):[\\/](.*)$")
_EXT_UNC_RE = re.compile(r"(?i)^(?:\\\\\?\\|//\?/)UNC[\\/]+([^\\/]+)[\\/]+([^\\/]+)(?:[\\/](.*))?$")
_UNC_RE = re.compile(r"^(?:\\\\|//)([^\\/?][^\\/]*)[\\/]+([^\\/]+)(?:[\\/](.*))?$")
_WSL_RE = re.compile(r"(?i)^/mnt/([a-z])/(.*)$")
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


@dataclass(frozen=True)
class PathIdentityResult:
    relation: str
    namespace_divergence: bool = False
    left_identity: str | None = None
    right_identity: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_components(tail: str, *, extended: bool) -> list[str] | None:
    raw_parts = re.split(r"[\\/]+", tail)
    parts: list[str] = []
    for part in raw_parts:
        if part == "":
            continue
        if part in {".", ".."}:
            return None
        if extended and (part.endswith(" ") or part.endswith(".")):
            return None
        stem = part.split(".", 1)[0].casefold()
        if extended and stem in _RESERVED:
            return None
        parts.append(part.casefold())
    return parts


def _windows_key(value: str | os.PathLike[str]) -> tuple[str, bool] | None:
    text = os.fspath(value).strip()
    if not text or "\x00" in text:
        return None

    match = _EXT_UNC_RE.match(text)
    if match:
        server, share, tail = match.group(1), match.group(2), match.group(3) or ""
        parts = _safe_components(tail, extended=True)
        if parts is None:
            return None
        suffix = "/".join(parts)
        key = f"win-unc:{server.casefold()}/{share.casefold()}"
        return (f"{key}/{suffix}" if suffix else key, True)

    match = _EXT_DRIVE_RE.match(text)
    if match:
        parts = _safe_components(match.group(2), extended=True)
        if parts is None:
            return None
        suffix = "/".join(parts)
        key = f"win-drive:{match.group(1).casefold()}"
        return (f"{key}/{suffix}" if suffix else key, True)

    if text.startswith(("\\\\.\\", "//./", "\\\\?\\", "//?/")):
        return None

    match = _UNC_RE.match(text)
    if match:
        server, share, tail = match.group(1), match.group(2), match.group(3) or ""
        parts = _safe_components(tail, extended=False)
        if parts is None:
            return None
        suffix = "/".join(parts)
        key = f"win-unc:{server.casefold()}/{share.casefold()}"
        return (f"{key}/{suffix}" if suffix else key, False)

    match = _DRIVE_ABS_RE.match(text)
    if match:
        parts = _safe_components(match.group(2), extended=False)
        if parts is None:
            return None
        suffix = "/".join(parts)
        key = f"win-drive:{match.group(1).casefold()}"
        return (f"{key}/{suffix}" if suffix else key, False)
    return None


def path_identity(value: str | os.PathLike[str]) -> str:
    """Stable lexical identity used for inventory correlation."""

    raw = os.fspath(value).strip()
    win = _windows_key(raw)
    if win is not None:
        return "win:" + win[0]
    wsl = _WSL_RE.match(raw.replace("\\", "/"))
    if wsl:
        tail = _safe_components(wsl.group(2), extended=False)
        if tail is not None:
            suffix = "/".join(tail)
            key = f"win-drive:{wsl.group(1).casefold()}"
            return "win:" + (f"{key}/{suffix}" if suffix else key)
    text = raw.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return "posix:" + text.rstrip("/")


def compare_windows_paths(
    left: str | os.PathLike[str],
    right: str | os.PathLike[str],
    *,
    allow_filesystem_identity: bool = False,
    samefile: Callable[[str, str], bool] = os.path.samefile,
) -> PathIdentityResult:
    """Compare recognized Windows absolute paths without rewriting either path."""

    left_text = os.fspath(left).strip()
    right_text = os.fspath(right).strip()
    left_key = _windows_key(left_text)
    right_key = _windows_key(right_text)
    if left_key is not None and right_key is not None:
        if left_key[0] == right_key[0]:
            return PathIdentityResult(
                relation="EQUIVALENT",
                namespace_divergence=left_key[1] != right_key[1],
                left_identity=left_key[0],
                right_identity=right_key[0],
                reason="recognized Windows absolute paths have the same logical identity",
            )
        return PathIdentityResult(
            relation="DIFFERENT",
            left_identity=left_key[0],
            right_identity=right_key[0],
            reason="recognized Windows absolute paths identify different logical locations",
        )

    if allow_filesystem_identity and os.name == "nt":
        try:
            if samefile(left_text, right_text):
                return PathIdentityResult(
                    relation="EQUIVALENT",
                    namespace_divergence=False,
                    reason="Windows filesystem identity probe reports the same file; namespace-boundary cause is unproven",
                )
        except (OSError, ValueError):
            pass

    return PathIdentityResult(
        relation="UNKNOWN",
        reason="path spelling is not safely comparable as a recognized Windows absolute path",
    )


import posixpath


def normalize_windows_extended_path(path: str | os.PathLike[str]) -> str:
    """Normalize Windows extended-length, UNC, and POSIX path representations.

    - Strips \\?\\ and //?/ prefixes.
    - Normalizes \\?\\UNC\\server\\share to //server/share.
    - Normalizes drive letters to uppercase (e.g., c:/ -> C:/).
    - Normalizes backslashes to forward slashes.
    - Normalizes relative components (. and ..).
    - Preserves standard POSIX paths (e.g. /home/user or /tmp/...) cleanly in Linux/Codespaces environments.
    """
    raw = os.fspath(path).strip()
    if not raw:
        return ""

    # 1. Check extended UNC: \\?\UNC\server\share\tail or //?/UNC/server/share/tail
    match_ext_unc = _EXT_UNC_RE.match(raw)
    if match_ext_unc:
        server = match_ext_unc.group(1)
        share = match_ext_unc.group(2)
        tail = match_ext_unc.group(3) or ""
        tail_norm = posixpath.normpath(tail.replace("\\", "/")).strip("/")
        return f"//{server}/{share}/{tail_norm}" if tail_norm and tail_norm != "." else f"//{server}/{share}"

    # 2. Check extended drive: \\?\C:\tail or //?/C:/tail
    match_ext_drive = _EXT_DRIVE_RE.match(raw)
    if match_ext_drive:
        drive = match_ext_drive.group(1).upper()
        tail = match_ext_drive.group(2).replace("\\", "/")
        norm_tail = posixpath.normpath(tail).lstrip("/")
        return f"{drive}:/{norm_tail}" if norm_tail and norm_tail != "." else f"{drive}:/"

    # 3. Check standard UNC: \\server\share\tail or //server/share/tail
    match_unc = _UNC_RE.match(raw)
    if match_unc:
        server = match_unc.group(1)
        share = match_unc.group(2)
        tail = match_unc.group(3) or ""
        tail_norm = posixpath.normpath(tail.replace("\\", "/")).strip("/")
        return f"//{server}/{share}/{tail_norm}" if tail_norm and tail_norm != "." else f"//{server}/{share}"

    # 4. Check standard drive: C:\tail or c:/tail
    match_drive = _DRIVE_ABS_RE.match(raw)
    if match_drive:
        drive = match_drive.group(1).upper()
        tail = match_drive.group(2).replace("\\", "/")
        norm_tail = posixpath.normpath(tail).lstrip("/")
        return f"{drive}:/{norm_tail}" if norm_tail and norm_tail != "." else f"{drive}:/"

    # 5. Check WSL mount: /mnt/c/tail
    match_wsl = _WSL_RE.match(raw.replace("\\", "/"))
    if match_wsl:
        drive = match_wsl.group(1).upper()
        tail = match_wsl.group(2)
        norm_tail = posixpath.normpath(tail).lstrip("/")
        return f"{drive}:/{norm_tail}" if norm_tail and norm_tail != "." else f"{drive}:/"

    # 6. Pure POSIX / other path
    normalized = posixpath.normpath(raw.replace("\\", "/"))
    return normalized


def has_windows_namespace_divergence(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    result = compare_windows_paths(left, right)
    return result.relation == "EQUIVALENT" and result.namespace_divergence


__all__ = [
    "PathIdentityResult",
    "compare_windows_paths",
    "has_windows_namespace_divergence",
    "normalize_windows_extended_path",
    "path_identity",
]
