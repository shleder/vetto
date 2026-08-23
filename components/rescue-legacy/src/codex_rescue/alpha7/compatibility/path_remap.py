from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.graph import PathNamespace, detect_path_namespace


@dataclass
class PathMappingResult:
    source_path: str
    target_path: str
    source_namespace: PathNamespace
    target_namespace: PathNamespace
    confidence: str  # HIGH, MEDIUM, LOW, UNRESOLVED
    is_equivalent: bool
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "target_path": self.target_path,
            "source_namespace": self.source_namespace.value,
            "target_namespace": self.target_namespace.value,
            "confidence": self.confidence,
            "is_equivalent": self.is_equivalent,
            "notes": self.notes,
        }


class PathRemappingEngine:
    """Explicit cross-platform, WSL, and namespace path remapping engine."""

    @staticmethod
    def translate_path(
        raw_path: str,
        target_platform: str = "windows",  # "windows", "linux", "wsl", "darwin"
        explicit_mappings: Optional[Dict[str, str]] = None,
    ) -> PathMappingResult:
        src_ns = detect_path_namespace(raw_path)
        clean_src = raw_path.strip()

        # Check explicit overrides first
        if explicit_mappings and clean_src in explicit_mappings:
            target = explicit_mappings[clean_src]
            target_ns = detect_path_namespace(target)
            return PathMappingResult(
                source_path=clean_src,
                target_path=target,
                source_namespace=src_ns,
                target_namespace=target_ns,
                confidence="HIGH",
                is_equivalent=True,
                notes="Explicit user mapping applied",
            )

        # Windows to WSL: C:\src\foo -> /mnt/c/src/foo
        if src_ns in (PathNamespace.WINDOWS_STANDARD, PathNamespace.WINDOWS_EXTENDED) and target_platform.lower() in ("wsl", "linux"):
            drive_match = re.match(r"^(?:\\\\\?\\)?([a-zA-Z]):[\\/](.*)", clean_src)
            if drive_match:
                drive = drive_match.group(1).lower()
                rest = drive_match.group(2).replace("\\", "/")
                target = f"/mnt/{drive}/{rest}"
                return PathMappingResult(
                    source_path=clean_src,
                    target_path=target,
                    source_namespace=src_ns,
                    target_namespace=PathNamespace.WSL_MNT,
                    confidence="HIGH",
                    is_equivalent=True,
                )

        # WSL to Windows: /mnt/c/src/foo -> C:\src\foo
        if src_ns == PathNamespace.WSL_MNT and target_platform.lower() == "windows":
            wsl_match = re.match(r"^/mnt/([a-zA-Z])/(.*)", clean_src)
            if wsl_match:
                drive = wsl_match.group(1).upper()
                rest = wsl_match.group(2).replace("/", "\\")
                target = f"{drive}:\\{rest}"
                return PathMappingResult(
                    source_path=clean_src,
                    target_path=target,
                    source_namespace=src_ns,
                    target_namespace=PathNamespace.WINDOWS_STANDARD,
                    confidence="HIGH",
                    is_equivalent=True,
                )

        # Long path prefix stripping: \\?\C:\foo -> C:\foo
        if src_ns == PathNamespace.WINDOWS_EXTENDED and target_platform.lower() == "windows":
            target = clean_src[4:]
            return PathMappingResult(
                source_path=clean_src,
                target_path=target,
                source_namespace=src_ns,
                target_namespace=PathNamespace.WINDOWS_STANDARD,
                confidence="HIGH",
                is_equivalent=True,
            )

        # Default fallback
        return PathMappingResult(
            source_path=clean_src,
            target_path=clean_src,
            source_namespace=src_ns,
            target_namespace=src_ns,
            confidence="MEDIUM",
            is_equivalent=True,
            notes="No platform translation rule applied",
        )
