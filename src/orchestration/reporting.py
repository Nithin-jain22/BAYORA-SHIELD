"""End-of-run security report generation.

Reports consolidate the attack journal, sanitised findings, remediation history,
condition analytics, sandbox health and audit-chain status into one artefact.

Formats: Markdown, JSON, printable HTML and PDF (ReportLab).
"""

from __future__ import annotations

import json
import re
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape

from ..config import MODEL, REPORTS_DIR
from ..core import updater
from ..core.conditions import CONDITION_LABELS
from ..core.timeutil import display_local, parse_timestamp, to_iso, to_local_iso
from ..infrastructure.security_plane import EventType, get_events, verify_chain
from . import journal
from .control_plane import get_control_plane
from .evidence import mask_prompt

REPORT_VERSION = 1


def _report_id() -> str:
    return f"BS-{time.strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 1000:03d}"


def _safe_json(value) -> str:
    return json.dumps(value, indent=2, default=str)


def _masked(entry: dict) -> str:
    prompt = entry.get("prompt") or ""
    return mask_prompt(prompt) if prompt else "(payload not retained in journal for retests)"


def _layer_label(layer: str) -> str:
    return {
        "layer_1_rules": "L1 · Rule filter",
        "layer_2_ml": "L2 · ML classifier",
        "layer_3_hardened_prompt": "L3 · Hardened system prompt",
        "layer_4_output_filter": "L4 · Output filter",
    }.get(layer, layer)


def build_report(
    *,
    scope: str = "all",
    session_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    generated_by: str = "system",
) -> dict:
    """Build the report data structure (no files written)."""
    entries = journal.load_entries()
    evidence = get_control_plane().get_all_evidence()

    if scope == "session" and session_id:
        entries = [entry for entry in entries if entry.get("session_id") == session_id]
        evidence = [item for item in evidence if item.session_id == session_id]
    if scope == "finding" and evidence_id:
        entries = [entry for entry in entries if entry.get("evidence_id") == evidence_id]
        evidence = [item for item in evidence if item.id == evidence_id]

    attacks = [entry for entry in entries if entry.get("phase", "attack") == "attack"]
    retests = [entry for entry in entries if entry.get("phase") == "retest"]
    summary = journal.summary(entries)

    outcomes = Counter(entry.get("outcome", "unknown") for entry in attacks)
    total = len(attacks)
    confirmed = [entry for entry in attacks if entry.get("outcome") in ("complied", "bypassed")]
    defended = [
        entry
        for entry in attacks
        if entry.get("outcome") in ("blocked", "filtered", "refused")
    ]
    inconclusive = [
        entry
        for entry in attacks
        if entry.get("outcome") in ("uncertain", "empty", "safe_completion")
    ]

    condition_rows = []
    condition_counts = (summary.get("conditions") or {}).get("counts", {})
    condition_bypass = (summary.get("conditions") or {}).get("bypass_counts", {})
    for flag, count in sorted(condition_counts.items(), key=lambda item: item[1], reverse=True):
        bypass_count = condition_bypass.get(flag, 0)
        condition_rows.append(
            {
                "flag": flag,
                "label": CONDITION_LABELS.get(flag, flag),
                "attacks": count,
                "bypasses": bypass_count,
                "bypass_rate": round(bypass_count / count, 3) if count else 0.0,
            }
        )

    layer_rows = []
    for layer, count in sorted(
        (summary.get("layer_breaches") or {}).items(), key=lambda item: item[1], reverse=True
    ):
        layer_rows.append(
            {
                "layer": layer,
                "label": _layer_label(layer),
                "breaches": count,
                "share": round(count / len(confirmed), 3) if confirmed else 0.0,
            }
        )

    chain_ok, chain_broken = verify_chain()
    defence = updater.defense_summary()

    report = {
        "report_id": _report_id(),
        "report_version": REPORT_VERSION,
        "generated_at": time.time(),
        "generated_at_iso": to_iso(time.time()),
        "generated_at_local": to_local_iso(time.time()),
        "generated_by": generated_by,
        "scope": scope,
        "session_id": session_id,
        "evidence_id": evidence_id,
        "model": MODEL,
        "summary": {
            "total_attacks": total,
            "confirmed_bypasses": len(confirmed),
            "defended": len(defended),
            "inconclusive": len(inconclusive),
            "bypass_rate": round(len(confirmed) / total, 3) if total else 0.0,
            "defence_rate": round(len(defended) / total, 3) if total else 0.0,
            "retests": len(retests),
            "findings_released": len(evidence),
            "findings_fixed": sum(1 for item in evidence if item.status == "retested_fixed"),
            "findings_still_vulnerable": sum(
                1 for item in evidence if item.status == "retested_vulnerable"
            ),
        },
        "outcomes": dict(outcomes),
        "by_type": summary.get("by_type", {}),
        "layer_breaches": layer_rows,
        "conditions": condition_rows,
        "timeline": summary.get("timeline", []),
        "confirmed_bypasses": [_attack_row(entry) for entry in confirmed],
        "defended_attacks": [_attack_row(entry) for entry in defended],
        "inconclusive_attacks": [_attack_row(entry) for entry in inconclusive],
        "sandbox": _sandbox_section(),
        "remediation": [_evidence_row(item) for item in evidence],
        "defense_posture": defence,
        "audit_chain": {"valid": chain_ok, "broken_at": chain_broken},
        "recommendations": _recommendations(condition_rows, layer_rows, confirmed, evidence),
    }
    return report


def _attack_row(entry: dict) -> dict:
    assessment = entry.get("assessment") or {}
    conditions = entry.get("conditions") or {}
    return {
        "journal_id": entry.get("id"),
        "timestamp": entry.get("timestamp"),
        "timestamp_iso": entry.get("timestamp_iso") or to_iso(entry.get("timestamp")),
        "timestamp_local": entry.get("timestamp_local") or to_local_iso(entry.get("timestamp")),
        "attack_name": entry.get("attack_name"),
        "attack_type": entry.get("attack_type"),
        "outcome": entry.get("outcome"),
        "prompt_hash": entry.get("prompt_hash"),
        "prompt_redacted": _masked(entry),
        "prompt_length": entry.get("prompt_length"),
        "word_count": entry.get("word_count"),
        "conditions": conditions,
        "condition_labels": conditions.get("labels", []),
        "risk_level": conditions.get("risk_level"),
        "risk_score": conditions.get("risk_score"),
        "layer_trace": entry.get("layer_trace", []),
        "layers_broken": entry.get("layers_broken", []),
        "layers_cleared": entry.get("layers_cleared", []),
        "breach_path": entry.get("breach_path"),
        "first_failed_layer": entry.get("first_failed_layer"),
        "containment_layer": entry.get("containment_layer"),
        "defended_by": entry.get("defended_by"),
        "ml_confidence": entry.get("ml_confidence"),
        "assessment": {
            "outcome": assessment.get("outcome"),
            "reason": assessment.get("reason"),
            "refusal_score": assessment.get("refusal_score"),
            "compliance_score": assessment.get("compliance_score"),
            "leaked_prompt": assessment.get("leaked_prompt"),
            "harmful_compliance": assessment.get("harmful_compliance"),
            "persona_adopted": assessment.get("persona_adopted"),
            "signals": assessment.get("signals", []),
            "excerpt": assessment.get("excerpt"),
        },
        "response_excerpt": entry.get("response_excerpt") or assessment.get("excerpt") or "",
        "raw_response_excerpt": entry.get("raw_response_excerpt") or "",
        "isolation_breaches": entry.get("isolation_breaches", []),
    }


def _evidence_row(item) -> dict:
    return {
        "evidence_id": item.id,
        "attack_name": item.attack_name,
        "attack_type": item.attack_type,
        "status": item.status,
        "severity": item.severity,
        "created_at": item.timestamp,
        "created_at_iso": to_iso(item.timestamp),
        "root_cause": item.root_cause,
        "recommended_fix": item.recommended_fix,
        "defense_update": item.defense_update,
        "layers_bypassed": item.layers_bypassed,
        "response_excerpt": (item.llm_response or "").strip()[:800],
        "retest_result": item.retest_result,
        "journal_id": item.journal_id,
    }


def _sandbox_section() -> dict:
    try:
        from ..infrastructure.sandbox_health import check_health

        return check_health(audit=False)
    except Exception as exc:  # pragma: no cover
        return {"status": "unknown", "error": str(exc), "layers": []}


def _recommendations(
    condition_rows: list[dict],
    layer_rows: list[dict],
    confirmed: list[dict],
    evidence: list,
) -> list[str]:
    items: list[str] = []
    if not confirmed:
        items.append(
            "No confirmed bypasses in this scope. Continue scheduled adversarial testing; "
            "refusals are being counted as defence wins rather than false findings."
        )
    top_conditions = [row for row in condition_rows if row["bypasses"] > 0][:4]
    for row in top_conditions:
        items.append(
            f"Prioritise '{row['label']}': {row['bypasses']} confirmed bypass(es) across "
            f"{row['attacks']} attack(s) ({row['bypass_rate']:.0%} bypass rate)."
        )
    if layer_rows:
        worst = layer_rows[0]
        items.append(
            f"The most-cleared defence layer is {worst['label']} ({worst['breaches']} bypass path(s)). "
            "Add layer-specific tests before the next evaluation run."
        )
    still = [item for item in evidence if item.status == "retested_vulnerable"]
    if still:
        items.append(
            f"{len(still)} finding(s) remain vulnerable after retest. Escalate to manual "
            "sandbox repair and add a regression test for each payload family."
        )
    if not items:
        items.append("Maintain the current defence stack and rerun the evasive attack set.")
    return items


# ── Markdown ────────────────────────────────────────────────────────────────

def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"# Bayora-Shield Security Report · {report['report_id']}",
        "",
        f"**Generated:** {report['generated_at_local']}  ",
        f"**Scope:** {report['scope']}  ",
        f"**Model:** {report['model']}  ",
        f"**Generated by:** {report['generated_by']}",
        "",
        "## Executive summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Attacks recorded | {summary['total_attacks']} |",
        f"| Confirmed bypasses | {summary['confirmed_bypasses']} |",
        f"| Defended (layer / model refusal) | {summary['defended']} |",
        f"| Inconclusive | {summary['inconclusive']} |",
        f"| Bypass rate | {summary['bypass_rate']:.1%} |",
        f"| Defence rate | {summary['defence_rate']:.1%} |",
        f"| Findings released | {summary['findings_released']} |",
        f"| Findings fixed after retest | {summary['findings_fixed']} |",
        "",
        "> A refused response is a defence win, not a bypass. Only confirmed "
        "compliance is released as a finding.",
        "",
        "## Outcome breakdown",
        "",
        "| Outcome | Count |",
        "| --- | --- |",
    ]
    for outcome, count in sorted(report["outcomes"].items()):
        lines.append(f"| {outcome} | {count} |")

    lines += ["", "## Layer breach analysis", ""]
    if report["layer_breaches"]:
        lines += ["| Layer | Confirmed breaches | Share of bypasses |", "| --- | --- | --- |"]
        for row in report["layer_breaches"]:
            lines.append(f"| {row['label']} | {row['breaches']} | {row['share']:.0%} |")
    else:
        lines.append("No defence layers were cleared by a confirmed bypass.")

    lines += ["", "## Attack conditions correlated with bypasses", ""]
    if report["conditions"]:
        lines += ["| Condition | Attacks | Bypasses | Bypass rate |", "| --- | --- | --- | --- |"]
        for row in report["conditions"]:
            lines.append(
                f"| {row['label']} | {row['attacks']} | {row['bypasses']} | {row['bypass_rate']:.0%} |"
            )
    else:
        lines.append("No structural conditions were recorded.")

    lines += ["", "## Confirmed bypasses", ""]
    if not report["confirmed_bypasses"]:
        lines.append("No confirmed bypasses in this scope.")
    for row in report["confirmed_bypasses"]:
        lines += [
            f"### {row['attack_name']} · {row['attack_type']}",
            "",
            f"- **When:** {row['timestamp_local']} ({row['timestamp_iso']})",
            f"- **Fingerprint:** `{row['prompt_hash']}`",
            f"- **Risk:** {row['risk_level']} ({row['risk_score']})",
            f"- **Breach path:** {row['breach_path'] or '—'}",
            f"- **Response assessment:** {row['assessment']['reason']}",
            f"- **Refusal score:** {row['assessment']['refusal_score']} · "
            f"**Compliance score:** {row['assessment']['compliance_score']}",
            f"- **Conditions:** {', '.join(row['condition_labels']) or '—'}",
            f"- **Masked payload:** `{row['prompt_redacted'][:220]}`",
            f"- **Model response (bypass evidence):** {row['response_excerpt'] or '—'}",
            "",
        ]

    lines += ["## Sandbox integrity", ""]
    sandbox = report.get("sandbox") or {}
    lines.append(
        f"Status: **{sandbox.get('status', 'unknown')}** · health score "
        f"{sandbox.get('score', '—')}/100"
    )
    for layer in sandbox.get("layers", []):
        lines.append(
            f"- **{layer['name']}** — {layer['status']}: {layer['detail']}"
        )
        if layer.get("recommendation"):
            lines.append(f"  - _Recommended:_ {layer['recommendation']}")

    lines += ["", "## Remediation history", ""]
    if report["remediation"]:
        lines += [
            "| Finding | Status | Severity | Root cause | Fix | Retest |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in report["remediation"]:
            retest = (row.get("retest_result") or {}).get("outcome") or "—"
            lines.append(
                f"| {row['evidence_id']} | {row['status']} | {row['severity'] or '—'} | "
                f"{(row['root_cause'] or '—').replace('|', '/')[:80]} | "
                f"{(row['recommended_fix'] or '—').replace('|', '/')[:80]} | {retest} |"
            )
    else:
        lines.append("No findings released in this scope.")

    lines += [
        "",
        "## Defence posture",
        "",
        f"- Layer 1 rules: {report['defense_posture']['rules']}",
        f"- Layer 4 patterns: {report['defense_posture']['output_patterns']}",
        f"- Learned rules: {report['defense_posture']['learned_rules']}",
        f"- Learned ML examples: {report['defense_posture']['learned_ml_examples']}",
        "",
        "## Audit chain",
        "",
        f"Valid: **{report['audit_chain']['valid']}**"
        + (
            f" · broken at line {report['audit_chain']['broken_at']}"
            if report["audit_chain"]["broken_at"]
            else ""
        ),
        "",
        "## Recommendations",
        "",
    ]
    lines += [f"- {item}" for item in report["recommendations"]]
    lines += [
        "",
        "---",
        "",
        "_Generated by Bayora-Shield. Payload text is masked to preserve red/blue "
        "team isolation; fingerprints and conditions are exact._",
        "",
    ]
    return "\n".join(lines)


# ── HTML ────────────────────────────────────────────────────────────────────

def render_html(report: dict) -> str:
    summary = report["summary"]
    sandbox = report.get("sandbox") or {}
    outcome_rows = "".join(
        f"<tr><td>{escape(str(key))}</td><td>{value}</td></tr>"
        for key, value in sorted(report["outcomes"].items())
    )
    type_rows = "".join(
        f"<tr><td>{escape(str(key))}</td><td>{row['total']}</td>"
        f"<td>{row['bypassed']}</td><td>{row['defended']}</td>"
        f"<td>{row['inconclusive']}</td></tr>"
        for key, row in sorted(report["by_type"].items())
    )
    layer_rows = "".join(
        f"<tr><td>{escape(row['label'])}</td><td>{row['breaches']}</td>"
        f"<td>{row['share']:.0%}</td></tr>"
        for row in report["layer_breaches"]
    ) or "<tr><td colspan=3>No confirmed layer breaches</td></tr>"
    condition_rows = "".join(
        f"<tr><td>{escape(row['label'])}</td><td>{row['attacks']}</td>"
        f"<td>{row['bypasses']}</td><td>{row['bypass_rate']:.0%}</td></tr>"
        for row in report["conditions"]
    ) or "<tr><td colspan=4>No conditions recorded</td></tr>"

    bypass_cards = []
    for row in report["confirmed_bypasses"]:
        assessment = row["assessment"]
        bypass_cards.append(
            f"""
            <article class="finding">
              <header>
                <div><strong>{escape(row['attack_name'] or '')}</strong>
                <span class="muted"> · {escape(row['attack_type'] or '')}</span></div>
                <span class="badge bad">{escape(row['outcome'] or '')}</span>
              </header>
              <div class="grid">
                <div><span class="label">When</span>{escape(row['timestamp_local'] or '')}</div>
                <div><span class="label">Fingerprint</span><code>{escape(row['prompt_hash'] or '')}</code></div>
                <div><span class="label">Risk</span>{escape(str(row['risk_level']))} ({row['risk_score']})</div>
                <div><span class="label">Breach path</span>{escape(row['breach_path'] or '—')}</div>
              </div>
              <p><span class="label">Conditions</span> {escape(', '.join(row['condition_labels']) or '—')}</p>
              <p><span class="label">Assessment</span> {escape(assessment['reason'] or '')}
              (refusal {assessment['refusal_score']}, compliance {assessment['compliance_score']})</p>
              <p><span class="label">Masked payload</span><code class="payload">{escape(row['prompt_redacted'][:280])}</code></p>
              <p><span class="label">Model response — bypass evidence</span> {escape(row['response_excerpt'] or assessment['excerpt'] or '—')}</p>
            </article>
            """
        )
    if not bypass_cards:
        bypass_cards.append("<p class='muted'>No confirmed bypasses in this scope.</p>")

    sandbox_rows = "".join(
        f"<tr><td>{escape(layer['name'])}</td><td class='{escape(layer['status'])}'>"
        f"{escape(layer['status'])}</td><td>{escape(layer['detail'])}</td></tr>"
        for layer in sandbox.get("layers", [])
    ) or "<tr><td colspan=3>Health check unavailable</td></tr>"

    remediation_rows = "".join(
        f"<tr><td>{escape(row['evidence_id'])}</td><td>{escape(row['status'])}</td>"
        f"<td>{escape(str(row['severity'] or '—'))}</td>"
        f"<td>{escape((row['root_cause'] or '—')[:160])}</td>"
        f"<td>{escape(((row.get('retest_result') or {}).get('outcome')) or '—')}</td></tr>"
        for row in report["remediation"]
    ) or "<tr><td colspan=5>No findings released</td></tr>"

    recommendations = "".join(
        f"<li>{escape(item)}</li>" for item in report["recommendations"]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Bayora-Shield Security Report {escape(report['report_id'])}</title>
<style>
  :root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --emerald:#059669; --red:#dc2626; --amber:#d97706; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:44px; color:var(--ink); font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif; }}
  h1 {{ font-size:30px; margin:0 0 6px; letter-spacing:-.02em; }}
  h2 {{ font-size:19px; margin:34px 0 12px; padding-bottom:8px; border-bottom:1px solid var(--line); }}
  h3 {{ font-size:15px; margin:20px 0 8px; }}
  .meta {{ color:var(--muted); margin-bottom:26px; }}
  .hero {{ background:linear-gradient(135deg,#0f172a,#134e4a); color:white; border-radius:16px; padding:26px 30px; }}
  .hero h1 {{ color:white; }}
  .hero .meta {{ color:#99f6e4; margin:0; }}
  .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:18px 0; }}
  .card {{ border:1px solid var(--line); border-radius:12px; padding:14px; }}
  .card b {{ display:block; font-size:25px; letter-spacing:-.03em; }}
  .card span {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
  table {{ width:100%; border-collapse:collapse; margin:10px 0 18px; font-size:13px; }}
  th {{ text-align:left; background:#f8fafc; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; }}
  th,td {{ padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  code {{ font-family:ui-monospace,Menlo,monospace; font-size:12px; }}
  .payload {{ display:block; background:#f8fafc; padding:8px; border-radius:6px; color:#475569; white-space:pre-wrap; }}
  .finding {{ border:1px solid var(--line); border-left:4px solid var(--red); border-radius:10px; padding:16px 18px; margin:14px 0; }}
  .finding header {{ display:flex; justify-content:space-between; gap:12px; align-items:center; }}
  .grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:10px 18px; margin:12px 0; }}
  .label {{ display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; margin-bottom:2px; }}
  .badge {{ border-radius:999px; padding:2px 10px; font-size:11px; font-weight:700; }}
  .bad {{ color:var(--red); background:#fef2f2; border:1px solid #fecaca; }}
  .healthy {{ color:var(--emerald); font-weight:700; }}
  .degraded {{ color:var(--amber); font-weight:700; }}
  .breached {{ color:var(--red); font-weight:700; }}
  .unknown {{ color:var(--muted); font-weight:700; }}
  .muted {{ color:var(--muted); }}
  ul {{ padding-left:20px; }}
  @media print {{ body {{ padding:22px; }} .hero {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }} .finding {{ break-inside:avoid; }} h2 {{ break-after:avoid; }} }}
</style>
</head>
<body>
<section class="hero">
  <h1>Bayora-Shield Security Report</h1>
  <p class="meta">{escape(report['report_id'])} · {escape(report['generated_at_local'])} · {escape(report['model'])}</p>
</section>

<div class="cards">
  <div class="card"><span>Attacks</span><b>{summary['total_attacks']}</b></div>
  <div class="card"><span>Confirmed bypasses</span><b>{summary['confirmed_bypasses']}</b></div>
  <div class="card"><span>Defended</span><b>{summary['defended']}</b></div>
  <div class="card"><span>Bypass rate</span><b>{summary['bypass_rate']:.0%}</b></div>
</div>
<p class="muted">Scope: {escape(report['scope'])} · Generated by {escape(report['generated_by'])}.
A refused response is counted as a defence win; only confirmed compliance becomes a finding.</p>

<h2>Outcome breakdown</h2>
<table><thead><tr><th>Outcome</th><th>Count</th></tr></thead><tbody>{outcome_rows}</tbody></table>

<h2>Attack types</h2>
<table><thead><tr><th>Type</th><th>Total</th><th>Bypassed</th><th>Defended</th><th>Inconclusive</th></tr></thead><tbody>{type_rows}</tbody></table>

<h2>Layer breach analysis</h2>
<table><thead><tr><th>Layer</th><th>Confirmed breaches</th><th>Share</th></tr></thead><tbody>{layer_rows}</tbody></table>

<h2>Attack conditions</h2>
<table><thead><tr><th>Condition</th><th>Attacks</th><th>Bypasses</th><th>Bypass rate</th></tr></thead><tbody>{condition_rows}</tbody></table>

<h2>Confirmed bypasses</h2>
{''.join(bypass_cards)}

<h2>Sandbox integrity</h2>
<p>Status: <strong class="{escape(sandbox.get('status', 'unknown'))}">{escape(sandbox.get('status', 'unknown'))}</strong>
· health score {sandbox.get('score', '—')}/100</p>
<table><thead><tr><th>Layer</th><th>Status</th><th>Detail</th></tr></thead><tbody>{sandbox_rows}</tbody></table>

<h2>Remediation history</h2>
<table><thead><tr><th>Finding</th><th>Status</th><th>Severity</th><th>Root cause</th><th>Retest</th></tr></thead><tbody>{remediation_rows}</tbody></table>

<h2>Audit chain</h2>
<p>Valid: <strong>{report['audit_chain']['valid']}</strong>
{(' · broken at line ' + str(report['audit_chain']['broken_at'])) if report['audit_chain']['broken_at'] else ''}</p>

<h2>Recommendations</h2>
<ul>{recommendations}</ul>

<hr />
<p class="muted">Generated by Bayora-Shield. Payload text is masked to preserve red/blue team
isolation; fingerprints and structural conditions are exact.</p>
</body>
</html>"""


# ── PDF ─────────────────────────────────────────────────────────────────────

def render_pdf(report: dict, path: Path) -> Path:
    """Render a compact, print-ready PDF using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="BSBody",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            alignment=TA_LEFT,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BSH1",
            parent=styles["Heading1"],
            fontSize=21,
            leading=25,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BSH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0f766e"),
            spaceBefore=14,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BSMono",
            parent=styles["Code"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#475569"),
        )
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Bayora-Shield Security Report {report['report_id']}",
    )
    story = []
    summary = report["summary"]
    story.append(Paragraph("Bayora-Shield Security Report", styles["BSH1"]))
    story.append(
        Paragraph(
            f"{escape(report['report_id'])} · {escape(report['generated_at_local'])} · "
            f"model {escape(report['model'])}",
            styles["BSBody"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "A refused response is counted as a defence win. Only confirmed model "
            "compliance is released as a finding.",
            styles["BSBody"],
        )
    )
    story.append(Spacer(1, 10))

    metrics = [
        ["Attacks", "Confirmed bypasses", "Defended", "Inconclusive", "Bypass rate"],
        [
            str(summary["total_attacks"]),
            str(summary["confirmed_bypasses"]),
            str(summary["defended"]),
            str(summary["inconclusive"]),
            f"{summary['bypass_rate']:.0%}",
        ],
    ]
    table = Table(metrics, colWidths=[30 * mm] * 5)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#475569")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)

    def heading(text: str) -> None:
        story.append(Paragraph(escape(text), styles["BSH2"]))

    def table(rows: list[list[str]], widths: list[float]) -> None:
        data = [[Paragraph(escape(str(cell)), styles["BSBody"]) for cell in row] for row in rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(t)

    heading("Outcome breakdown")
    table([["Outcome", "Count"]] + [[k, str(v)] for k, v in sorted(report["outcomes"].items())], [80 * mm, 30 * mm])

    heading("Layer breach analysis")
    table(
        [["Layer", "Breaches", "Share"]]
        + [[r["label"], str(r["breaches"]), f"{r['share']:.0%}"] for r in report["layer_breaches"]],
        [100 * mm, 30 * mm, 30 * mm],
    )

    heading("Attack conditions correlated with bypasses")
    table(
        [["Condition", "Attacks", "Bypasses", "Rate"]]
        + [
            [r["label"], str(r["attacks"]), str(r["bypasses"]), f"{r['bypass_rate']:.0%}"]
            for r in report["conditions"]
        ],
        [100 * mm, 22 * mm, 22 * mm, 22 * mm],
    )

    story.append(PageBreak())
    heading("Confirmed bypasses")
    if not report["confirmed_bypasses"]:
        story.append(Paragraph("No confirmed bypasses in this scope.", styles["BSBody"]))
    for row in report["confirmed_bypasses"]:
        story.append(
            Paragraph(
                f"<b>{escape(row['attack_name'] or '')}</b> · {escape(row['attack_type'] or '')} "
                f"· <font color='#dc2626'>{escape(row['outcome'] or '')}</font>",
                styles["BSBody"],
            )
        )
        story.append(
            Paragraph(
                f"When: {escape(row['timestamp_local'] or '')}<br/>"
                f"Fingerprint: {escape(row['prompt_hash'] or '')}<br/>"
                f"Risk: {escape(str(row['risk_level']))} ({row['risk_score']}) · "
                f"Breach path: {escape(row['breach_path'] or '—')}<br/>"
                f"Conditions: {escape(', '.join(row['condition_labels']) or '—')}<br/>"
                f"Assessment: {escape(row['assessment']['reason'] or '')} "
                f"(refusal {row['assessment']['refusal_score']}, "
                f"compliance {row['assessment']['compliance_score']})",
                styles["BSBody"],
            )
        )
        story.append(
            Paragraph(
                "Masked payload: " + escape(row["prompt_redacted"][:260]),
                styles["BSMono"],
            )
        )
        story.append(
            Paragraph(
                "Model response (bypass evidence): "
                + escape((row["response_excerpt"] or row["assessment"]["excerpt"] or "—")[:600]),
                styles["BSBody"],
            )
        )
        story.append(Spacer(1, 6))

    heading("Sandbox integrity")
    sandbox = report.get("sandbox") or {}
    story.append(
        Paragraph(
            f"Status: <b>{escape(sandbox.get('status', 'unknown'))}</b> · health score "
            f"{sandbox.get('score', '—')}/100",
            styles["BSBody"],
        )
    )
    table(
        [["Layer", "Status", "Detail"]]
        + [
            [layer["name"], layer["status"], layer["detail"][:160]]
            for layer in sandbox.get("layers", [])
        ],
        [45 * mm, 25 * mm, 90 * mm],
    )

    heading("Remediation history")
    table(
        [["Finding", "Status", "Severity", "Retest"]]
        + [
            [
                row["evidence_id"],
                row["status"],
                str(row["severity"] or "—"),
                str((row.get("retest_result") or {}).get("outcome") or "—"),
            ]
            for row in report["remediation"]
        ],
        [40 * mm, 45 * mm, 30 * mm, 45 * mm],
    )

    heading("Audit chain")
    story.append(
        Paragraph(
            f"Valid: <b>{report['audit_chain']['valid']}</b>"
            + (
                f" · broken at line {report['audit_chain']['broken_at']}"
                if report["audit_chain"]["broken_at"]
                else ""
            ),
            styles["BSBody"],
        )
    )

    heading("Recommendations")
    for item in report["recommendations"]:
        story.append(Paragraph("• " + escape(item), styles["BSBody"]))

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Payload text is masked to preserve red/blue team isolation; fingerprints "
            "and structural conditions are exact.",
            styles["BSBody"],
        )
    )
    doc.build(story)
    return path


# ── Persistence / listing ───────────────────────────────────────────────────

def generate_report(
    *,
    scope: str = "all",
    session_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    generated_by: str = "system",
) -> dict:
    report = build_report(
        scope=scope,
        session_id=session_id,
        evidence_id=evidence_id,
        generated_by=generated_by,
    )
    directory = REPORTS_DIR / report["report_id"]
    directory.mkdir(parents=True, exist_ok=True)

    with open(directory / "report.json", "w") as handle:
        json.dump(report, handle, indent=2, default=str)
    with open(directory / "report.md", "w") as handle:
        handle.write(render_markdown(report))
    with open(directory / "report.html", "w") as handle:
        handle.write(render_html(report))

    pdf_error = None
    try:
        render_pdf(report, directory / "report.pdf")
    except Exception as exc:  # PDF generation is optional; HTML remains printable
        pdf_error = str(exc)

    meta = {
        "report_id": report["report_id"],
        "generated_at": report["generated_at"],
        "generated_at_iso": report["generated_at_iso"],
        "generated_at_local": report["generated_at_local"],
        "scope": report["scope"],
        "session_id": report["session_id"],
        "evidence_id": report["evidence_id"],
        "generated_by": report["generated_by"],
        "summary": report["summary"],
        "pdf_error": pdf_error,
        "formats": ["json", "md", "html", "pdf"] if not pdf_error else ["json", "md", "html"],
    }
    with open(directory / "meta.json", "w") as handle:
        json.dump(meta, handle, indent=2)

    from ..infrastructure.security_plane import log_event

    log_event(
        EventType.REPORT_GENERATED,
        generated_by,
        {
            "report_id": report["report_id"],
            "scope": scope,
            "session_id": session_id,
            "evidence_id": evidence_id,
            "bypasses": report["summary"]["confirmed_bypasses"],
            "pdf_error": pdf_error,
        },
    )
    meta["report"] = report
    return meta


def list_reports() -> list[dict]:
    items = []
    for directory in REPORTS_DIR.iterdir() if REPORTS_DIR.exists() else []:
        meta_path = directory / "meta.json"
        if not directory.is_dir() or not meta_path.exists():
            continue
        try:
            with open(meta_path) as handle:
                items.append(json.load(handle))
        except (json.JSONDecodeError, OSError):
            continue
    return sorted(items, key=lambda item: item.get("generated_at", 0), reverse=True)


def get_report_meta(report_id: str) -> Optional[dict]:
    path = REPORTS_DIR / report_id / "meta.json"
    if not path.exists():
        return None
    try:
        with open(path) as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None


def report_file(report_id: str, fmt: str) -> Optional[Path]:
    allowed = {"json", "md", "html", "pdf"}
    if fmt not in allowed:
        return None
    path = REPORTS_DIR / report_id / f"report.{fmt}"
    return path if path.exists() else None


def delete_report(report_id: str) -> bool:
    directory = REPORTS_DIR / report_id
    if not directory.exists() or not report_id.startswith("BS-"):
        return False
    shutil.rmtree(directory)
    return True
