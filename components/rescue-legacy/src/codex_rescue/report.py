from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .diff import diff_session
from .evidence import collect_session_evidence
from .explanations import get_explanation
from .graph import build_session_graph
from .plan import generate_recovery_plan
from .redact import audit_privacy, sanitize_path
from .schema_inspector import inspect_schemas
from .timeline import build_timeline


def generate_html_report(
    session_path: Path | str,
    output_html_path: Path | str | None = None,
    codex_home: Path | str | None = None,
) -> str:
    path = Path(session_path).resolve()
    ev = collect_session_evidence(path, codex_home=codex_home)
    diff = diff_session(path, codex_home=codex_home)
    tl = build_timeline(path, max_events=100)
    graph = build_session_graph(path, codex_home=codex_home)
    plan = generate_recovery_plan(path, codex_home=codex_home)
    schema = inspect_schemas(codex_home=codex_home, session_files=[path])

    violations = audit_privacy({
        "session_id": ev.session_id,
        "findings": ev.findings,
        "diff": diff.to_dict(),
        "plan": plan.to_dict(),
    })

    display_session_id = ev.session_id or "UNKNOWN"
    h_session = html.escape(display_session_id)
    h_status = html.escape(ev.status or "UNKNOWN")
    h_confidence = html.escape(ev.confidence or "UNKNOWN")

    findings_html = ""
    for f in (ev.findings or ["HEALTHY"]):
        exp = get_explanation(f)
        findings_html += f'''
        <div class="card">
            <h3>Finding: {html.escape(f)}</h3>
            <p><strong>What Happened:</strong> {html.escape(exp.what_happened)}</p>
            <p><strong>Evidence Used:</strong> {html.escape(exp.evidence_used)}</p>
            <p><strong>What Is Still Healthy:</strong> {html.escape(exp.what_is_still_healthy)}</p>
            <p><strong>Risk:</strong> {html.escape(exp.risk)}</p>
            <p><strong>Safe Action:</strong> {html.escape(exp.safe_next_action)}</p>
        </div>
        '''

    diff_html = ""
    if diff.divergences:
        diff_html = "<ul>"
        for d in diff.divergences:
            diff_html += f"<li><strong>{html.escape(d.dimension)}</strong> ({html.escape(d.divergence_type)}): {html.escape(d.note)}</li>"
        diff_html += "</ul>"
    else:
        diff_html = "<p class='healthy'>All persisted layers are in alignment.</p>"

    events_html = ""
    for evt in tl.events[:30]:
        events_html += f"<tr><td>{evt.index}</td><td>{html.escape(evt.event_type)}</td><td>{html.escape(str(evt.ordinal))}</td><td>{html.escape(str(evt.timestamp or ''))}</td><td>{evt.record_size}B</td></tr>"

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Codex Rescue Report — {h_session}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #24292f; background: #f6f8fa; margin: 0; padding: 24px; }}
.container {{ max-width: 960px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
h1, h2, h3 {{ color: #0969da; }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 14px; }}
.badge-healthy {{ background: #dafbe1; color: #1a7f37; }}
.badge-warning {{ background: #fff8c5; color: #9a6700; }}
.badge-error {{ background: #ffebe9; color: #cf222e; }}
.card {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #d0d7de; font-size: 13px; }}
th {{ background: #f6f8fa; }}
.healthy {{ color: #1a7f37; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
    <h1>Codex Rescue Diagnostic Report</h1>
    <p>Session ID: <code>{h_session}</code> | Status: <span class="badge badge-{'healthy' if ev.status == 'HEALTHY' else 'warning'}">{h_status}</span> | Confidence: <strong>{h_confidence}</strong></p>

    <h2>1. Diagnostic Findings</h2>
    {findings_html}

    <h2>2. Persisted State Layer Diff</h2>
    {diff_html}

    <h2>3. Forensic Event Timeline (First 30 Events)</h2>
    <table>
        <thead><tr><th>#</th><th>Event Kind</th><th>Ordinal</th><th>Timestamp</th><th>Size</th></tr></thead>
        <tbody>{events_html}</tbody>
    </table>

    <h2>4. Session Family Hierarchy</h2>
    <pre>{html.escape(graph.render_text())}</pre>

    <h2>5. Recovery Plan</h2>
    <div class="card">
        <p><strong>Applicable:</strong> {'YES' if plan.is_applicable else 'NO'}</p>
        <p><strong>Canonical Source:</strong> {html.escape(plan.canonical_source)}</p>
        <p><strong>Source Mutated:</strong> {'YES' if plan.source_files_modified else 'NO (SOURCE UNTOUCHED)'}</p>
        {f"<p><strong>Refusal Reason:</strong> {html.escape(plan.refusal_reason)}</p>" if plan.refusal_reason else ""}
    </div>

    <h2>6. Privacy & Redaction Audit</h2>
    <p>{'✅ Clean: No secrets, credentials, or private payload leakage detected.' if not violations else f'⚠️ Redaction Violations: {html.escape(str(violations))}'}</p>
</div>
</body>
</html>'''

    target_file = Path(output_html_path) if output_html_path else Path(f"rescue_report_{ev.session_id or 'unknown'}.html")
    target_file.write_text(html_content, encoding="utf-8")
    return str(target_file)
