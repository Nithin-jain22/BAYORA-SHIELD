"""Append-only attack journal.

Every prompt that reaches the pipeline is recorded with:

* the exact input conditions (role-play, extraction, obfuscation, …),
* the per-layer outcome and where the first layer failed,
* the response assessment (refused / complied / uncertain),
* the isolation-layer snapshot so a later report can state whether the
  sandbox itself was affected.

The journal is the evidence source for the end-of-run report.  It is separate
from the tamper-evident audit log: the audit log proves *that* events happened,
the journal explains *why* an attack succeeded or failed.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ..config import ATTACK_JOURNAL_PATH, MODEL
from ..core.timeutil import to_iso, to_local_iso
from ..infrastructure.security_plane import EventType, log_event


def _file() -> Path:
    ATTACK_JOURNAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    return ATTACK_JOURNAL_PATH


def append_entry(entry: dict) -> dict:
    entry = dict(entry)
    entry.setdefault("timestamp", time.time())
    entry.setdefault("timestamp_iso", to_iso(entry["timestamp"]))
    entry.setdefault("timestamp_local", to_local_iso(entry["timestamp"]))
    entry.setdefault("model", MODEL)
    with open(_file(), "a") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")
    return entry


def _normalise_entry(entry: dict) -> dict:
    """Repair derived fields on historic journal entries.

    Older builds wrote the cleared-layer path onto refused / inconclusive runs.
    Those layers were *cleared*, not broken, so the breach fields must stay
    empty unless the response assessment confirmed compliance.
    """
    outcome = entry.get("outcome", "unknown")
    is_bypass = outcome in ("complied", "bypassed")
    if not is_bypass:
        entry["layers_broken"] = []
        entry["first_failed_layer"] = None
        entry["breach_path"] = ""
        return entry

    layers = entry.get("layers_broken") or entry.get("layers_cleared") or []
    entry["layers_broken"] = list(layers)
    if entry.get("first_failed_layer") is None and layers:
        entry["first_failed_layer"] = 1
    if not entry.get("breach_path"):
        entry["breach_path"] = " → ".join(_layer_short(name) for name in layers)
    return entry


def load_entries(limit: Optional[int] = None) -> list[dict]:
    path = _file()
    if not path.exists():
        return []
    entries: list[dict] = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(_normalise_entry(json.loads(line)))
            except json.JSONDecodeError:
                continue
    if limit:
        entries = entries[-limit:]
    return entries


def get_entry(entry_id: str) -> Optional[dict]:
    return next((item for item in load_entries() if item.get("id") == entry_id), None)


def record_pipeline_run(
    *,
    result,
    session_id: str,
    phase: str,
    attack_name: str = "Custom Attack",
    attack_type: str = "custom",
    operator: Optional[str] = None,
    evidence_id: Optional[str] = None,
    sandbox_snapshot: Optional[dict] = None,
) -> dict:
    """Persist one pipeline run to the journal."""
    assessment = result.assessment or {}
    conditions = result.conditions or {}
    layer_trace = [asdict(layer) for layer in result.layer_trace]
    bypassed = list(result.layers_bypassed or [])
    outcome = result.outcome or ("bypassed" if not result.blocked else "blocked")
    is_bypass = outcome in ("complied", "bypassed")
    response_excerpt = _clip(result.llm_response)
    raw_response_excerpt = _clip(result.raw_response)

    entry = {
        "id": hashlib.sha256(
            f"{session_id}:{time.time()}:{result.prompt[:16]}".encode()
        ).hexdigest()[:16],
        "timestamp": time.time(),
        "session_id": session_id,
        "operator": operator,
        "phase": phase,
        "evidence_id": evidence_id,
        "attack_name": attack_name,
        "attack_type": attack_type,
        "prompt_hash": hashlib.sha256(result.prompt.encode()).hexdigest()[:16],
        "prompt": result.prompt if phase == "attack" else None,
        "prompt_length": len(result.prompt),
        "word_count": len(result.prompt.split()),
        "conditions": conditions,
        "outcome": outcome,
        "defended": outcome in ("blocked", "filtered", "refused"),
        "bypassed": is_bypass,
        "inconclusive": outcome in ("uncertain", "empty", "safe_completion"),
        "defended_by": result.blocked_by,
        "containment_layer": _containment_layer(result),
        "first_failed_layer": (
            1 if is_bypass and result.layer_trace and result.layer_trace[0].outcome == "allowed" else None
        ),
        "layers_broken": bypassed if is_bypass else [],
        "layers_cleared": bypassed,
        "breach_path": " → ".join(_layer_short(name) for name in bypassed) if is_bypass else "",
        "ml_confidence": result.ml_confidence,
        "assessment": assessment,
        "response_excerpt": response_excerpt,
        "raw_response_excerpt": raw_response_excerpt,
        "layer_trace": layer_trace,
        "gateway_error": result.gateway_error,
        "sandbox": sandbox_snapshot or {},
        "isolation_breaches": [
            layer
            for layer in (sandbox_snapshot or {}).get("breached_layers", [])
            if layer
        ],
    }

    try:
        append_entry(entry)
    except OSError:
        # A reporting failure must never turn a defended attack into a crash.
        pass

    log_event(
        EventType.CONDITION_SNAPSHOT,
        "system",
        {
            "journal_id": entry["id"],
            "phase": phase,
            "outcome": outcome,
            "risk_score": conditions.get("risk_score"),
            "flags": conditions.get("flags", []),
            "attack_type": attack_type,
        },
        session_id,
    )
    return entry


def _clip(text: Optional[str], limit: int = 1200) -> str:
    """Keep a bounded copy of the model output for the report."""
    if not text:
        return ""
    compact = " ".join(str(text).split())
    if len(compact) <= limit:
        return compact
    return compact[:limit].rstrip() + " …"


def _containment_layer(result) -> Optional[str]:
    if result.outcome in ("complied", "bypassed"):
        return None
    if result.outcome == "refused":
        return "L5 · Model alignment"
    for layer in result.layer_trace:
        if layer.outcome in ("blocked", "filtered"):
            return f"L{layer.layer} · {layer.name}"
    return None


def _layer_short(name: str) -> str:
    mapping = {
        "layer_1_rules": "L1 Rules",
        "layer_2_ml": "L2 ML",
        "layer_3_hardened_prompt": "L3 Prompt",
        "layer_4_output_filter": "L4 Output",
    }
    return mapping.get(name, name)


def summary(entries: Optional[list[dict]] = None) -> dict:
    """Aggregate outcomes, layer breaches and conditions."""
    entries = load_entries() if entries is None else entries
    # Retests are validation runs, not new attacks.  Keep them in the journal
    # but out of attack totals, outcome mixes and bypass rates.
    entries = [entry for entry in entries if entry.get("phase", "attack") == "attack"]
    total = len(entries)
    outcomes = Counter(entry.get("outcome", "unknown") for entry in entries)
    attack_types = Counter(entry.get("attack_type", "unknown") for entry in entries)
    breaches: Counter = Counter()
    condition_hits: Counter = Counter()
    condition_totals: Counter = Counter()
    condition_bypass: Counter = Counter()
    by_type = defaultdict(lambda: {"total": 0, "bypassed": 0, "defended": 0, "inconclusive": 0})
    timeline: dict[str, dict] = {}

    for entry in entries:
        outcome = entry.get("outcome", "unknown")
        attack_type = entry.get("attack_type", "unknown")
        by_type[attack_type]["total"] += 1
        if outcome in ("complied", "bypassed"):
            by_type[attack_type]["bypassed"] += 1
        elif outcome in ("blocked", "filtered", "refused"):
            by_type[attack_type]["defended"] += 1
        else:
            by_type[attack_type]["inconclusive"] += 1

        for layer in entry.get("layers_broken", []) or []:
            breaches[layer] += 1

        flags = (entry.get("conditions") or {}).get("flags", [])
        for flag in flags:
            condition_hits[flag] += 1
        if flags:
            condition_totals[entry.get("attack_type", "unknown")] += 1
            if outcome in ("complied", "bypassed"):
                for flag in flags:
                    condition_bypass[flag] += 1

        day = (entry.get("timestamp_iso") or "")[:10]
        bucket = timeline.setdefault(
            day, {"date": day, "total": 0, "bypassed": 0, "defended": 0, "inconclusive": 0}
        )
        bucket["total"] += 1
        if outcome in ("complied", "bypassed"):
            bucket["bypassed"] += 1
        elif outcome in ("blocked", "filtered", "refused"):
            bucket["defended"] += 1
        else:
            bucket["inconclusive"] += 1

    return {
        "total": total,
        "outcomes": dict(outcomes),
        "attack_types": dict(attack_types),
        "layer_breaches": dict(breaches),
        "by_type": dict(by_type),
        "conditions": {
            "counts": dict(condition_hits),
            "bypass_counts": dict(condition_bypass),
        },
        "timeline": sorted(timeline.values(), key=lambda row: row["date"]),
        "bypass_rate": round(
            (outcomes.get("complied", 0) + outcomes.get("bypassed", 0)) / total, 3
        )
        if total
        else 0.0,
    }


def recent(limit: int = 50) -> list[dict]:
    entries = load_entries(limit=limit)
    return list(reversed(entries))


def clear() -> int:
    path = _file()
    if not path.exists():
        return 0
    count = len(load_entries())
    path.write_text("")
    return count
