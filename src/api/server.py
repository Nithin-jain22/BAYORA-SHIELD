"""Bayora-Shield FastAPI control surface.

The React frontend talks to this API; the Streamlit app remains available as a
legacy interface.  All model traffic still flows through the same shared
pipeline, so a React attack and a Streamlit attack produce identical evidence,
journal entries and audit events.
"""

from __future__ import annotations

import threading
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import BASE_DIR, MODEL
from ..core import updater
from ..core.attacks import ATTACKS, ATTACK_TYPES, EVASIVE_ATTACKS
from ..infrastructure.sandbox import SandboxError, get_sandbox
from ..infrastructure.sandbox_health import (
    REPAIR_ACTIONS,
    check_health,
    run_repair,
)
from ..infrastructure.security_plane import EventType, get_events, verify_chain
from ..orchestration import journal, reporting
from ..orchestration.blue_team import BlueTeamSession
from ..orchestration.control_plane import get_control_plane
from ..orchestration.evaluation_plane import get_evaluation_plane
from ..orchestration.red_team import RedTeamSession

app = FastAPI(title="Bayora-Shield API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RED_SESSIONS: dict[str, RedTeamSession] = {}
BLUE_SESSIONS: dict[str, BlueTeamSession] = {}
PIPELINE_LOCK = threading.Lock()

FRONTEND_DIST = BASE_DIR / "frontend" / "dist"


# ── Models ──────────────────────────────────────────────────────────────────

class SessionRequest(BaseModel):
    operator: str = Field(min_length=1, max_length=80)


class AttackRequest(BaseModel):
    session_id: str
    prompt: str = Field(min_length=1, max_length=8192)
    attack_name: str = "Custom Attack"
    attack_type: str = "custom"


class ClearRequest(BaseModel):
    session_id: str


class AnalyzeRequest(BaseModel):
    session_id: str
    evidence_id: str
    root_cause: str = Field(min_length=1)
    severity: str = "medium"
    recommended_fix: str = Field(min_length=1)


class FixRequest(BaseModel):
    session_id: str
    evidence_id: str
    update_type: str
    description: str = Field(min_length=1)


class RetestRequest(BaseModel):
    session_id: str
    evidence_id: str


class SnapshotRequest(BaseModel):
    session_id: Optional[str] = None
    defense_version: str = "live"


class RepairRequest(BaseModel):
    action: str
    confirm: bool = False
    note: str = ""
    operator: str = "blue_team"


class ReportRequest(BaseModel):
    scope: str = "all"
    session_id: Optional[str] = None
    evidence_id: Optional[str] = None
    generated_by: str = "system"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _red(session_id: str) -> RedTeamSession:
    session = RED_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Red team session not found")
    return session


def _blue(session_id: str) -> BlueTeamSession:
    session = BLUE_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Blue team session not found")
    return session


def _sandbox_status() -> dict:
    return get_sandbox().status()


# ── Meta / health ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict:
    sandbox = get_sandbox().quick_status()
    return {
        "status": "ok",
        "app": "Bayora-Shield",
        "version": "2.0.0",
        "model": MODEL,
        "sandbox": sandbox,
        "frontend_built": FRONTEND_DIST.exists(),
        "red_sessions": len(RED_SESSIONS),
        "blue_sessions": len(BLUE_SESSIONS),
    }


@app.get("/api/overview")
def overview() -> dict:
    entries = journal.load_entries()
    summary = journal.summary(entries)
    evidence = [asdict(item) for item in get_control_plane().get_all_evidence()]
    chain_ok, chain_broken = verify_chain()
    return {
        "summary": summary,
        "journal_total": len(entries),
        "recent_attacks": [
            entry
            for entry in journal.recent(limit=20)
            if entry.get("phase", "attack") == "attack"
        ][:8],
        "evidence": {
            "total": len(evidence),
            "pending": sum(
                1 for item in evidence if item["status"] in ("new", "analyzed", "fix_applied")
            ),
            "fixed": sum(1 for item in evidence if item["status"] == "retested_fixed"),
            "vulnerable": sum(
                1 for item in evidence if item["status"] == "retested_vulnerable"
            ),
        },
        "sandbox": get_sandbox().quick_status(),
        "defense": updater.defense_summary(),
        "audit": {"valid": chain_ok, "broken_at": chain_broken},
        "evaluation": get_evaluation_plane().get_trend(),
    }


# ── Sandbox ─────────────────────────────────────────────────────────────────

@app.get("/api/sandbox/status")
def sandbox_status() -> dict:
    return _sandbox_status()


@app.post("/api/sandbox/start")
def sandbox_start() -> dict:
    sandbox = get_sandbox()
    try:
        sandbox.start()
    except SandboxError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return sandbox.status()


@app.post("/api/sandbox/stop")
def sandbox_stop() -> dict:
    sandbox = get_sandbox()
    sandbox.stop()
    return sandbox.status()


@app.get("/api/sandbox/health")
def sandbox_health(audit: bool = Query(default=False)) -> dict:
    return check_health(audit=audit)


@app.get("/api/sandbox/actions")
def sandbox_actions() -> dict:
    return {
        "actions": [
            {
                "id": key,
                "description": value,
                "destructive": key
                in {"recreate_sandbox", "quarantine_evidence", "reset_runtime"},
            }
            for key, value in REPAIR_ACTIONS.items()
        ]
    }


@app.post("/api/sandbox/repair")
def sandbox_repair(request: RepairRequest) -> dict:
    result = run_repair(request.action, confirm=request.confirm, note=request.note)
    if not result.get("ok") and result.get("requires_confirmation"):
        status = 409
    elif not result.get("ok"):
        status = 400
    else:
        status = 200
    return JSONResponse(status_code=status, content=result)


# ── Red team ────────────────────────────────────────────────────────────────

@app.post("/api/red/session")
def create_red_session(request: SessionRequest) -> dict:
    session = RedTeamSession(request.operator.strip())
    RED_SESSIONS[session.session_id] = session
    return {"session_id": session.session_id, "operator": session.operator_name}


@app.get("/api/red/examples")
def red_examples() -> dict:
    return {
        "obvious": ATTACKS,
        "evasive": EVASIVE_ATTACKS,
        "attack_types": ATTACK_TYPES,
    }


@app.get("/api/red/history")
def red_history(session_id: str) -> dict:
    session = _red(session_id)
    return {
        "session_id": session_id,
        "operator": session.operator_name,
        "stats": session.get_stats(),
        "attacks": [attack.to_dict() for attack in session.get_history()],
    }


@app.post("/api/red/attack")
def red_attack(request: AttackRequest) -> dict:
    session = _red(request.session_id)
    with PIPELINE_LOCK:
        result = session.submit_attack(
            request.prompt.strip(),
            request.attack_name.strip() or "Custom Attack",
            request.attack_type,
        )
    return {
        "attack": result.to_dict(),
        "stats": session.get_stats(),
    }


@app.post("/api/red/clear")
def red_clear(request: ClearRequest) -> dict:
    session = _red(request.session_id)
    session.clear_history()
    return {"ok": True, "stats": session.get_stats()}


# ── Blue team ───────────────────────────────────────────────────────────────

@app.post("/api/blue/session")
def create_blue_session(request: SessionRequest) -> dict:
    session = BlueTeamSession(request.operator.strip())
    BLUE_SESSIONS[session.session_id] = session
    return {"session_id": session.session_id, "operator": session.operator_name}


@app.get("/api/blue/evidence")
def blue_evidence(session_id: str, status: Optional[str] = None) -> dict:
    session = _blue(session_id)
    evidence = session.get_evidence(status=status)
    evidence = sorted(evidence, key=lambda item: item["timestamp"], reverse=True)
    return {"evidence": evidence, "stats": session.get_stats()}


@app.post("/api/blue/analyze")
def blue_analyze(request: AnalyzeRequest) -> dict:
    session = _blue(request.session_id)
    ok = session.analyze_evidence(
        request.evidence_id,
        request.root_cause.strip(),
        request.severity,
        request.recommended_fix.strip(),
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"ok": True, "stats": session.get_stats()}


@app.post("/api/blue/fix")
def blue_fix(request: FixRequest) -> dict:
    session = _blue(request.session_id)
    update_id, error = session.apply_defense_update(
        request.evidence_id, request.update_type, request.description
    )
    if error:
        raise HTTPException(status_code=400, detail=error)
    return {"ok": True, "update_id": update_id, "stats": session.get_stats()}


@app.post("/api/blue/retest")
def blue_retest(request: RetestRequest) -> dict:
    session = _blue(request.session_id)
    with PIPELINE_LOCK:
        verdict = session.retest(request.evidence_id)
    if verdict.get("error") == "Evidence not found":
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"ok": True, "result": verdict, "stats": session.get_stats()}


@app.get("/api/blue/defense")
def blue_defense() -> dict:
    return updater.defense_summary()


# ── Evaluation ──────────────────────────────────────────────────────────────

@app.get("/api/evaluation")
def evaluation() -> dict:
    plane = get_evaluation_plane()
    runs = [
        {
            **asdict(run),
            "outcome_breakdown": run.outcome_breakdown,
        }
        for run in sorted(plane.runs, key=lambda item: item.timestamp)
    ]
    latest = runs[-1] if runs else None
    return {
        "runs": list(reversed(runs)),
        "trend": plane.get_trend(),
        "latest": latest,
    }


@app.post("/api/evaluation/snapshot")
def evaluation_snapshot(request: SnapshotRequest) -> dict:
    plane = get_evaluation_plane()
    results: list[dict] = []
    if request.session_id:
        session = _red(request.session_id)
        results = [
            {
                "attack_type": attack.attack_type,
                "blocked": attack.blocked,
                "outcome": attack.outcome,
            }
            for attack in session.get_history()
        ]
    else:
        for entry in journal.load_entries():
            if entry.get("phase", "attack") != "attack":
                continue
            results.append(
                {
                    "attack_type": entry.get("attack_type", "unknown"),
                    "blocked": entry.get("outcome") in ("blocked", "filtered", "refused"),
                    "outcome": entry.get("outcome", "unknown"),
                }
            )
    if not results:
        raise HTTPException(status_code=400, detail="No attacks to snapshot")
    run = plane.create_run(
        model=MODEL,
        results=results,
        defense_version=request.defense_version,
        session_id=request.session_id,
    )
    return {"ok": True, "run": asdict(run)}


# ── Audit ───────────────────────────────────────────────────────────────────

@app.get("/api/audit/events")
def audit_events(
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = Query(default=250, ge=1, le=2000),
) -> dict:
    parsed_type = None
    if event_type and event_type != "all":
        try:
            parsed_type = EventType(event_type)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Unknown event type") from exc
    events = get_events(event_type=parsed_type, actor=actor if actor not in (None, "all") else None)
    chain_ok, chain_broken = verify_chain()
    sliced = list(reversed(events[-limit:]))
    return {
        "total": len(events),
        "events": sliced,
        "audit": {"valid": chain_ok, "broken_at": chain_broken},
        "event_types": [event.value for event in EventType],
    }


# ── Journal / conditions ────────────────────────────────────────────────────

@app.get("/api/journal")
def journal_entries(limit: int = Query(default=100, ge=1, le=2000)) -> dict:
    return {"entries": journal.recent(limit=limit)}


@app.get("/api/journal/summary")
def journal_summary() -> dict:
    return journal.summary()


@app.get("/api/journal/conditions")
def journal_conditions() -> dict:
    summary = journal.summary()
    conditions = []
    for flag, count in sorted(
        (summary.get("conditions", {}).get("counts") or {}).items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        bypasses = summary["conditions"]["bypass_counts"].get(flag, 0)
        conditions.append(
            {
                "flag": flag,
                "attacks": count,
                "bypasses": bypasses,
                "bypass_rate": round(bypasses / count, 3) if count else 0.0,
            }
        )
    return {"conditions": conditions, "summary": summary}


# ── Reports ─────────────────────────────────────────────────────────────────

@app.get("/api/reports")
def reports() -> dict:
    return {"reports": reporting.list_reports()}


@app.post("/api/reports/generate")
def generate_report(request: ReportRequest) -> dict:
    meta = reporting.generate_report(
        scope=request.scope,
        session_id=request.session_id,
        evidence_id=request.evidence_id,
        generated_by=request.generated_by,
    )
    # Return the meta without the full nested report to keep the response small.
    meta = {key: value for key, value in meta.items() if key != "report"}
    return {"ok": True, "report": meta}


@app.get("/api/reports/{report_id}")
def report_meta(report_id: str) -> dict:
    meta = reporting.get_report_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Report not found")
    return meta


@app.get("/api/reports/{report_id}/download/{fmt}")
def download_report(report_id: str, fmt: str):
    path = reporting.report_file(report_id, fmt)
    if not path:
        raise HTTPException(status_code=404, detail="Report format not found")
    media = {
        "json": "application/json",
        "md": "text/markdown",
        "html": "text/html",
        "pdf": "application/pdf",
    }.get(fmt, "application/octet-stream")
    return FileResponse(path, media_type=media, filename=f"{report_id}.{fmt}")


# ── Static frontend ─────────────────────────────────────────────────────────

if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
else:
    @app.get("/")
    def missing_frontend() -> dict:
        return {
            "message": "Bayora-Shield API is running, but the React frontend is not built.",
            "build": "cd frontend && npm install && npm run build",
            "api_docs": "/docs",
        }
