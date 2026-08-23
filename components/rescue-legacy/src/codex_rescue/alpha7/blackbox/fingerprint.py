from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FailureFingerprint:
    fingerprint_id: str
    pattern_family: str  # e.g. "projection/wedged/source-healthy/desktop-hidden"
    canonical_hash: str
    known_match: Optional[str] = None
    confidence: str = "HIGH"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "pattern_family": self.pattern_family,
            "canonical_hash": self.canonical_hash,
            "known_match": self.known_match,
            "confidence": self.confidence,
            "details": self.details,
        }


KNOWN_PATTERNS = {
    "projection_wedged_after_migration": "WEDGED_PROJECTION_AFTER_MIGRATION",
    "orphaned_archived_rollout": "ORPHANED_ARCHIVED_ROLLOUT",
    "active_writer_disappeared": "WRITER_PROCESS_DISAPPEARED",
    "inline_image_amplification": "STORAGE_INLINE_IMAGE_AMPLIFICATION",
    "unindexed_desktop_thread": "UNINDEXED_DESKTOP_THREAD",
}


class FingerprintEngine:
    """Generates stable, privacy-safe failure fingerprints and matches known failure patterns."""

    @staticmethod
    def generate_fingerprint(
        findings: List[str],
        surface_states: Dict[str, str],
        storage_risk: Optional[str] = None,
    ) -> FailureFingerprint:
        sorted_findings = sorted(findings)
        sorted_surfaces = sorted(f"{k}:{v}" for k, v in surface_states.items())

        raw_family = "/".join(sorted_findings + sorted_surfaces)
        if storage_risk:
            raw_family += f"/{storage_risk}"

        h = hashlib.sha256(raw_family.encode("utf-8")).hexdigest()[:16]
        fid = f"CR7-{h}"

        # Match against known patterns
        known_match = None
        if "UNINDEXED_IN_SQLITE" in findings:
            known_match = KNOWN_PATTERNS["unindexed_desktop_thread"]
        elif "WEDGED_PROJECTION" in findings:
            known_match = KNOWN_PATTERNS["projection_wedged_after_migration"]
        elif "WRITER_PROCESS_DEAD" in findings:
            known_match = KNOWN_PATTERNS["active_writer_disappeared"]

        return FailureFingerprint(
            fingerprint_id=fid,
            pattern_family=raw_family,
            canonical_hash=h,
            known_match=known_match,
            confidence="HIGH" if known_match else "MEDIUM",
            details={
                "findings": sorted_findings,
                "surfaces": surface_states,
            },
        )
