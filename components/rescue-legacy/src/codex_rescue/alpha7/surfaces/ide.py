from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.graph import SurfaceObservation, SurfaceVisibility


@dataclass
class IDEInspectionReport:
    available: bool = False
    detected_editors: List[str] = field(default_factory=list)
    extension_paths: List[str] = field(default_factory=list)
    storage_paths: List[str] = field(default_factory=list)
    visible_thread_ids: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "detected_editors": self.detected_editors,
            "extension_paths": self.extension_paths,
            "storage_paths": self.storage_paths,
            "visible_thread_ids": self.visible_thread_ids,
            "notes": self.notes,
        }


class IDEAdapter:
    """Inspects IDE extension surfaces when technically available and inspectable."""

    def __init__(self, codex_home: Optional[Path] = None):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))

    def inspect(self) -> IDEInspectionReport:
        report = IDEInspectionReport()
        home = Path.home()

        # Check VS Code
        vscode_ext = home / ".vscode" / "extensions"
        if vscode_ext.exists():
            report.detected_editors.append("vscode")
            for ext in vscode_ext.glob("*codex*"):
                report.extension_paths.append(str(ext))
                report.available = True

        # Check Cursor
        cursor_ext = home / ".cursor" / "extensions"
        if cursor_ext.exists():
            report.detected_editors.append("cursor")
            for ext in cursor_ext.glob("*codex*"):
                report.extension_paths.append(str(ext))
                report.available = True

        return report

    def observe_thread(self, session_id: str) -> SurfaceObservation:
        info = self.inspect()
        if not info.available:
            return SurfaceObservation(
                surface="ide",
                visibility=SurfaceVisibility.UNSUPPORTED,
                notes="No supported IDE Codex extension detected",
            )

        # In Alpha7 lab: IDE storage inspection
        return SurfaceObservation(
            surface="ide",
            visibility=SurfaceVisibility.UNKNOWN,
            notes="IDE extension present; deep state binding requires active IDE LSP connection",
        )
