"""
security_plane.py — Tamper-Evident Audit Log

Records all security-relevant events in an append-only log with hash chaining.
Each entry includes the hash of the previous entry, making it impossible to
modify or delete a record without breaking the chain.

Events logged:
  - Red team attack submissions
  - Defense layer blocks/allows
  - LLM queries and responses
  - Blue team defense updates
  - Sandbox lifecycle events
  - Authentication events

The log file is append-only (permissions 0444 after each write batch).
"""

import json
import hashlib
import time
import os
import fcntl
from typing import Any, Optional
from enum import Enum

from ..config import AUDIT_LOG_PATH
from ..core.timeutil import to_iso, to_local_iso

GENESIS_HASH = "0" * 64


class EventType(str, Enum):
    ATTACK_SUBMITTED = "attack_submitted"
    DEFENSE_BLOCKED = "defense_blocked"
    DEFENSE_PASSED = "defense_passed"
    LLM_QUERY = "llm_query"
    LLM_RESPONSE = "llm_response"
    OUTPUT_FILTERED = "output_filtered"
    RESPONSE_ASSESSED = "response_assessed"
    LAYER_BREACH = "layer_breach"
    CONDITION_SNAPSHOT = "condition_snapshot"
    BLUE_TEAM_UPDATE = "blue_team_update"
    SANDBOX_START = "sandbox_start"
    SANDBOX_STOP = "sandbox_stop"
    SANDBOX_INTEGRITY = "sandbox_integrity"
    SANDBOX_REPAIR = "sandbox_repair"
    REPORT_GENERATED = "report_generated"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    EVIDENCE_RELEASED = "evidence_released"
    EVIDENCE_RETIRED = "evidence_retired"
    VIOLATION_DETECTED = "violation_detected"


def _compute_hash(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _get_last_hash() -> str:
    if not AUDIT_LOG_PATH.exists():
        return GENESIS_HASH
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            lines = f.readlines()
            if not lines:
                return GENESIS_HASH
            last_entry = json.loads(lines[-1])
            return last_entry.get("hash", GENESIS_HASH)
    except (json.JSONDecodeError, KeyError):
        return GENESIS_HASH


def log_event(
    event_type: EventType,
    actor: str,
    details: dict[str, Any],
    session_id: Optional[str] = None,
) -> dict:
    """
    Appends a tamper-evident entry to the audit log.

    Args:
        event_type: Type of security event
        actor: Who triggered the event (red_team, blue_team, system)
        details: Event-specific data
        session_id: Optional session identifier

    Returns:
        The logged entry (including its hash)
    """
    previous_hash = _get_last_hash()

    now = time.time()
    entry = {
        "timestamp": now,
        "timestamp_iso": to_iso(now),
        "timestamp_local": to_local_iso(now),
        "event_type": event_type.value,
        "actor": actor,
        "session_id": session_id,
        "details": details,
        "previous_hash": previous_hash,
    }

    entry["hash"] = _compute_hash(entry)

    # A cross-process lock covers both hash selection and append.  Without it,
    # two writers (React API + Streamlit) can read the same tail hash and fork
    # the chain.
    lock_path = AUDIT_LOG_PATH.with_suffix(".lock")
    with open(lock_path, "a+") as lock_handle:
        fcntl.flock(lock_handle, fcntl.LOCK_EX)
        try:
            previous_hash = _get_last_hash()
            entry["previous_hash"] = previous_hash
            entry.pop("hash", None)
            entry["hash"] = _compute_hash(entry)
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            fcntl.flock(lock_handle, fcntl.LOCK_UN)

    return entry


def verify_chain() -> tuple[bool, Optional[int]]:
    """
    Verifies the integrity of the entire audit log.

    Returns:
        (is_valid, broken_at_line)
        is_valid = True if the chain is intact
        broken_at_line = line number where the chain breaks (None if valid)
    """
    if not AUDIT_LOG_PATH.exists():
        return True, None

    previous_hash = GENESIS_HASH
    with open(AUDIT_LOG_PATH, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, line_num
            if entry.get("previous_hash") != previous_hash:
                return False, line_num
            computed = _compute_hash({k: v for k, v in entry.items() if k != "hash"})
            if computed != entry.get("hash"):
                return False, line_num
            previous_hash = entry["hash"]

    return True, None


def get_events(
    event_type: Optional[EventType] = None,
    actor: Optional[str] = None,
    session_id: Optional[str] = None,
    since: Optional[float] = None,
) -> list[dict]:
    """Query audit log events with optional filters."""
    if not AUDIT_LOG_PATH.exists():
        return []

    results = []
    with open(AUDIT_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event_type and entry["event_type"] != event_type.value:
                continue
            if actor and entry["actor"] != actor:
                continue
            if session_id and entry.get("session_id") != session_id:
                continue
            if since and entry["timestamp"] < since:
                continue
            results.append(entry)
    return results


def get_violations(since: Optional[float] = None) -> list[dict]:
    """Get all security violations."""
    return get_events(event_type=EventType.VIOLATION_DETECTED, since=since)


if __name__ == "__main__":
    log_event(EventType.SANDBOX_START, "system", {"backend": "docker", "model": "llama3.2:1b"})
    log_event(EventType.ATTACK_SUBMITTED, "red_team", {"attack_name": "test", "prompt_hash": "abc123"})
    log_event(EventType.DEFENSE_BLOCKED, "system", {"layer": 1, "reason": "keyword match"})

    valid, broken = verify_chain()
    print(f"Chain valid: {valid}")
    if broken:
        print(f"Broken at line: {broken}")

    events = get_events()
    print(f"Total events: {len(events)}")
    for e in events:
        print(f"  [{e['event_type']}] by {e['actor']} at {e['timestamp_iso']}")
