from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.blackbox.recorder import StructuralEvent


@dataclass
class CausalStep:
    category: str  # "OBSERVED", "INFERRED", "UNKNOWN"
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class IncidentReport:
    incident_id: str
    start_time: float
    end_time: float
    duration_sec: float
    last_known_good_time: Optional[float] = None
    first_known_bad_time: Optional[float] = None
    first_anomaly: Optional[str] = None
    events_count: int = 0
    anomalies_count: int = 0
    causal_chain: List[CausalStep] = field(default_factory=list)
    canonical_rollout_status: str = "HEALTHY"
    is_safe_shareable: bool = False
    affected_logical_thread_ids: List[str] = field(default_factory=list)
    surfaces: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    evidence_provenance: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "HIGH"
    unknown_fields: List[str] = field(default_factory=list)
    sanitized_reproduction_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "duration_sec": self.duration_sec,
            "last_known_good_time": self.last_known_good_time,
            "first_known_bad_time": self.first_known_bad_time,
            "first_anomaly": self.first_anomaly,
            "events_count": self.events_count,
            "anomalies_count": self.anomalies_count,
            "causal_chain": [c.to_dict() for c in self.causal_chain],
            "canonical_rollout_status": self.canonical_rollout_status,
            "is_safe_shareable": self.is_safe_shareable,
            "affected_logical_thread_ids": self.affected_logical_thread_ids,
            "surfaces": self.surfaces,
            "finding_ids": self.finding_ids,
            "evidence_provenance": self.evidence_provenance,
            "confidence": self.confidence,
            "unknown_fields": self.unknown_fields,
            "sanitized_reproduction_summary": self.sanitized_reproduction_summary,
        }


from codex_rescue.alpha7.privacy.redaction import PrivacyRedactionEngine


class IncidentEngine:
    """Reconstructs evidence-backed causal chains and identifies first bad state."""

    def __init__(self):
        self._active_sessions: Dict[str, float] = {}

    def start_incident(self, session_id: str) -> str:
        self._active_sessions[session_id] = time.time()
        return f"inc_{session_id}_{int(time.time())}"

    def analyze_events(
        self,
        incident_id: str,
        events: List[StructuralEvent],
        start_time: Optional[float] = None,
        rollout_status: Optional[str] = None,
        validate_privacy: bool = False,
    ) -> IncidentReport:
        now = time.time()
        st = start_time or (events[0].timestamp if events else now)
        duration = max(0.0, round(now - st, 2))

        last_good = None
        first_bad = None
        first_anomaly = None
        anomalies = []
        causal = []

        for e in events:
            if "error" in e.details or e.event_type.value.endswith("STOPPED") or e.event_type.value.endswith("REGRESSED"):
                if first_bad is None:
                    first_bad = e.timestamp
                    first_anomaly = e.details.get("error") or e.event_type.value
                anomalies.append(e)
            else:
                last_good = e.timestamp

        # Construct causal chain
        for e in events:
            causal.append(
                CausalStep(
                    category="OBSERVED",
                    description=f"{e.event_type.value} on {e.path or e.session_id or 'system'}",
                    evidence=e.details,
                )
            )

        if first_bad:
            causal.append(
                CausalStep(
                    category="INFERRED",
                    description=f"State divergence started at timestamp {first_bad}: {first_anomaly}",
                )
            )
            causal.append(
                CausalStep(
                    category="UNKNOWN",
                    description="Exact internal Desktop UI rendering failure reason (requires debug hooks)",
                )
            )

        # Extract thread IDs, surfaces, finding IDs
        thread_ids = sorted(list({e.session_id for e in events if e.session_id}))
        surfaces = sorted(list({e.details.get("surface") for e in events if e.details.get("surface")}))
        findings = sorted(list({e.details.get("finding") for e in events if e.details.get("finding")}))

        unknown_fields = []
        if first_bad:
            unknown_fields.append("exact_desktop_internal_renderer_state")

        rep_summary = (
            f"Incident {incident_id} affected {len(thread_ids)} threads across surfaces {surfaces or ['local']}. "
            f"First anomaly observed at {first_bad}: {first_anomaly}."
            if first_bad else "All observed operations healthy."
        )

        # Canonical rollout status must be derived from actual integrity evidence
        canonical_status = rollout_status or ("UNKNOWN" if anomalies else "UNKNOWN")

        # Confidence is evidence-derived, never blindly HIGH
        if not events:
            confidence = "UNKNOWN"
        elif len(anomalies) > 0 and rollout_status is None:
            confidence = "LOW"
            unknown_fields.append("unverified_rollout_disk_status")
        elif len(events) >= 2 and all(e.details.get("source") == "OBSERVED" for e in events):
            confidence = "HIGH"
        else:
            confidence = "MEDIUM"

        # Shareability: Default FALSE. Only TRUE if explicit privacy validation passes
        is_shareable = False
        if validate_privacy:
            sanitized_summary, audit = PrivacyRedactionEngine.sanitize_text(rep_summary)
            if audit.passed_validation and audit.secrets_found_and_redacted == 0:
                is_shareable = True
                rep_summary = sanitized_summary

        return IncidentReport(
            incident_id=incident_id,
            start_time=st,
            end_time=now,
            duration_sec=duration,
            last_known_good_time=last_good,
            first_known_bad_time=first_bad,
            first_anomaly=first_anomaly,
            events_count=len(events),
            anomalies_count=len(anomalies),
            causal_chain=causal,
            canonical_rollout_status=canonical_status,
            is_safe_shareable=is_shareable,
            affected_logical_thread_ids=thread_ids,
            surfaces=surfaces,
            finding_ids=findings,
            evidence_provenance={"events_recorded": len(events), "anomalies": len(anomalies)},
            confidence=confidence,
            unknown_fields=unknown_fields,
            sanitized_reproduction_summary=rep_summary,
        )
