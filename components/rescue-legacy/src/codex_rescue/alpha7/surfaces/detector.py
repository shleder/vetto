from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


import enum

class SurfaceStatus(str, enum.Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class DetectedSurface:
    name: str  # "cli", "desktop", "ide", "app_server"
    available: bool
    status: str = SurfaceStatus.UNAVAILABLE.value
    version: Optional[str] = None
    path: Optional[str] = None
    process_running: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "status": self.status,
            "version": self.version,
            "path": self.path,
            "process_running": self.process_running,
            "details": self.details,
        }


@dataclass
class EnvironmentTopology:
    os_name: str
    os_version: str
    is_wsl: bool
    wsl_distro: Optional[str]
    codex_home: Path
    surfaces: Dict[str, DetectedSurface] = field(default_factory=dict)

    @property
    def detected_surface_count(self) -> int:
        return sum(1 for s in self.surfaces.values() if s.available)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "os_name": self.os_name,
            "os_version": self.os_version,
            "is_wsl": self.is_wsl,
            "wsl_distro": self.wsl_distro,
            "codex_home": str(self.codex_home),
            "detected_surface_count": self.detected_surface_count,
            "surfaces": {k: v.to_dict() for k, v in self.surfaces.items()},
        }


class SurfaceDetector:
    """Detects available Codex surfaces, local/remote topology, processes, and storage."""

    @staticmethod
    def detect_topology(codex_home: Optional[Path] = None) -> EnvironmentTopology:
        home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        system = platform.system()
        is_wsl = "microsoft" in platform.uname().release.lower() or "wsl" in platform.uname().release.lower()
        wsl_distro = os.environ.get("WSL_DISTRO_NAME") if is_wsl else None

        topo = EnvironmentTopology(
            os_name=system,
            os_version=platform.version(),
            is_wsl=is_wsl,
            wsl_distro=wsl_distro,
            codex_home=home,
        )

        topo.surfaces["cli"] = SurfaceDetector._detect_cli(home)
        topo.surfaces["desktop"] = SurfaceDetector._detect_desktop(home)
        topo.surfaces["ide"] = SurfaceDetector._detect_ide(home)
        topo.surfaces["app_server"] = SurfaceDetector._detect_app_server(home)

        return topo

    detect_all_surfaces = detect_topology

    @staticmethod
    def _detect_cli(home: Path) -> DetectedSurface:
        # CLI presence: ~/.codex/sessions or ~/.codex/history.jsonl or cli binary
        sessions_dir = home / "sessions"
        history_file = home / "history.jsonl"
        has_sessions = sessions_dir.exists()
        has_history = history_file.exists()
        available = has_sessions or has_history
        status = SurfaceStatus.AVAILABLE.value if (has_sessions and has_history) else (
            SurfaceStatus.PARTIAL.value if available else SurfaceStatus.UNAVAILABLE.value
        )
        return DetectedSurface(
            name="cli",
            available=available,
            status=status,
            path=str(home) if available else None,
            details={
                "has_sessions_dir": has_sessions,
                "has_history": has_history,
            },
        )

    @staticmethod
    def _detect_desktop(home: Path) -> DetectedSurface:
        # Desktop presence: state_5.sqlite / state.sqlite / state.db or Electron desktop data dir
        system = platform.system()
        sqlite_candidates = [home / "state_5.sqlite", home / "state.sqlite", home / "state.db"]
        existing_dbs = [str(p) for p in sqlite_candidates if p.exists()]
        desktop_data_dir = None
        if system == "Windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                desktop_data_dir = Path(appdata) / "Codex"
        elif system == "Darwin":
            desktop_data_dir = Path.home() / "Library" / "Application Support" / "Codex"
        else:
            desktop_data_dir = Path.home() / ".config" / "Codex"

        has_state_db = len(existing_dbs) > 0
        has_data_dir = desktop_data_dir is not None and desktop_data_dir.exists()
        available = has_state_db or has_data_dir
        status = SurfaceStatus.AVAILABLE.value if (has_state_db and has_data_dir) else (
            SurfaceStatus.PARTIAL.value if available else SurfaceStatus.UNAVAILABLE.value
        )

        return DetectedSurface(
            name="desktop",
            available=available,
            status=status,
            path=str(desktop_data_dir) if has_data_dir else (existing_dbs[0] if existing_dbs else None),
            details={
                "has_state_db": has_state_db,
                "existing_dbs": existing_dbs,
                "has_desktop_data_dir": has_data_dir,
                "desktop_data_path": str(desktop_data_dir) if desktop_data_dir else None,
            },
        )

    @staticmethod
    def _detect_ide(home: Path) -> DetectedSurface:
        # VS Code / Cursor / Compatible Codex extensions
        vscode_ext_dir = Path.home() / ".vscode" / "extensions"
        cursor_ext_dir = Path.home() / ".cursor" / "extensions"

        found_ext = False
        ext_path = None
        for base in [vscode_ext_dir, cursor_ext_dir]:
            if base.exists():
                for item in base.glob("*codex*"):
                    found_ext = True
                    ext_path = str(item)
                    break

        status = SurfaceStatus.AVAILABLE.value if found_ext else SurfaceStatus.UNAVAILABLE.value
        return DetectedSurface(
            name="ide",
            available=found_ext,
            status=status,
            path=ext_path,
            details={"has_extension": found_ext},
        )

    @staticmethod
    def _detect_app_server(home: Path) -> DetectedSurface:
        # App server socket / port / lockfile check
        server_info_file = home / "app_server.json"
        socket_file = home / "app_server.sock"
        has_info = server_info_file.exists()
        has_sock = socket_file.exists()
        available = has_info or has_sock
        status = SurfaceStatus.AVAILABLE.value if (has_info and has_sock) else (
            SurfaceStatus.PARTIAL.value if available else SurfaceStatus.UNAVAILABLE.value
        )

        return DetectedSurface(
            name="app_server",
            available=available,
            status=status,
            path=str(server_info_file) if server_info_file.exists() else None,
            details={
                "has_server_info": has_info,
                "has_socket": has_sock,
            },
        )
