"""Sandbox integrity checks and manual repair actions.

The red-team / blue-team loop protects the *model*, but the environment around
the model can still be damaged: a runaway ollama process, a container that lost
its isolation flags, a poisoned defence store, a tripped rate limiter, or a
broken audit chain.

This module exposes:

* :func:`check_health` — a per-layer health report with a damage score,
* :func:`run_repair` — explicit, audited manual repairs for the blue team.

Nothing here is automatic.  Destructive repairs require ``confirm=True`` from
the caller, are backed up first, and are written to the tamper-evident audit
log.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..config import (
    ATTACK_JOURNAL_PATH,
    AUDIT_LOG_PATH,
    DEFENSE_STORE_PATH,
    EVIDENCE_QUEUE_PATH,
    QUARANTINE_DIR,
    SANDBOX_PORT,
    SANDBOX_STATE_PATH,
)
from ..core.timeutil import to_iso, to_local_iso
from ..infrastructure.gateway import get_gateway
from ..infrastructure.sandbox import docker_available, docker_cli, get_sandbox
from ..infrastructure.security_plane import EventType, log_event, verify_chain

DOCKER_CONTAINER_NAME = "bayora-shield-llm"


def _now() -> dict:
    now = time.time()
    return {"timestamp": now, "timestamp_iso": to_iso(now), "timestamp_local": to_local_iso(now)}


def _layer(
    layer_id: str,
    name: str,
    status: str,
    detail: str,
    recommendation: str = "",
    *,
    critical: bool = False,
) -> dict:
    return {
        "id": layer_id,
        "name": name,
        "status": status,  # healthy | degraded | breached | unknown
        "detail": detail,
        "recommendation": recommendation,
        "critical": critical,
    }


def _port_owner() -> dict:
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{SANDBOX_PORT}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {"listening": False, "detail": "lsof unavailable", "addresses": []}
    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    addresses = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 9:
            addresses.append(parts[8])
    return {
        "listening": bool(lines[1:]),
        "detail": "listening" if lines[1:] else "no listener",
        "addresses": addresses,
    }


def _docker_isolation() -> dict:
    try:
        result = subprocess.run(
            [docker_cli(), "inspect", DOCKER_CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "detail": str(exc), "breaches": []}
    if result.returncode != 0:
        return {
            "available": False,
            "detail": "container not found (process sandbox or stopped)",
            "breaches": [],
        }
    try:
        data = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        return {"available": False, "detail": "unreadable docker inspect", "breaches": []}

    host = data.get("HostConfig", {})
    breaches = []
    if not host.get("ReadonlyRootfs"):
        breaches.append("read-only root filesystem disabled")
    if not host.get("CapDrop") or "ALL" not in host.get("CapDrop", []):
        breaches.append("capabilities not fully dropped")
    if not host.get("PidsLimit"):
        breaches.append("PID limit missing")
    if not host.get("Memory"):
        breaches.append("memory limit missing")
    if host.get("Privileged"):
        breaches.append("container is privileged")
    if host.get("NetworkMode") not in ("none", "bridge"):
        breaches.append(f"unexpected network mode: {host.get('NetworkMode')}")
    security_opt = host.get("SecurityOpt") or []
    if not any("no-new-privileges" in item for item in security_opt):
        breaches.append("no-new-privileges missing")

    return {
        "available": True,
        "detail": "Docker isolation flags inspected",
        "breaches": breaches,
        "host_config": {
            "readonly": host.get("ReadonlyRootfs"),
            "cap_drop": host.get("CapDrop"),
            "pids_limit": host.get("PidsLimit"),
            "memory": host.get("Memory"),
            "network_mode": host.get("NetworkMode"),
            "security_opt": security_opt,
        },
    }


def _defense_store_health() -> dict:
    if not DEFENSE_STORE_PATH.exists():
        return {"valid": True, "detail": "no learned defence state", "invalid": []}
    try:
        with open(DEFENSE_STORE_PATH) as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        return {"valid": False, "detail": f"unreadable: {exc}", "invalid": ["store"]}
    invalid = []
    for key in ("rules", "output_patterns"):
        for pattern in data.get(key, []):
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error:
                invalid.append(f"{key}: {pattern[:60]}")
    return {
        "valid": not invalid,
        "detail": "all learned patterns compile" if not invalid else f"{len(invalid)} invalid pattern(s)",
        "invalid": invalid,
    }


def _json_file_health(path: Path) -> dict:
    if not path.exists():
        return {"valid": True, "detail": "not present"}
    try:
        with open(path) as handle:
            json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        return {"valid": False, "detail": str(exc)}
    return {"valid": True, "detail": "valid JSON"}


def check_health(audit: bool = True) -> dict:
    """Return a per-layer sandbox health report."""
    sandbox = get_sandbox()
    status = sandbox.status()
    owner = _port_owner()
    docker = _docker_isolation()
    chain_ok, chain_broken = verify_chain()
    store = _defense_store_health()
    evidence = _json_file_health(EVIDENCE_QUEUE_PATH)
    gateway = get_gateway()

    layers = []
    running = bool(status.get("running")) or owner["listening"]
    layers.append(
        _layer(
            "sandbox_runtime",
            "Sandbox runtime",
            "healthy" if running else "breached",
            f"{status.get('backend') or 'unknown'} backend · port {SANDBOX_PORT} {owner['detail']}",
            "Start or recreate the sandbox from the repair workspace.",
            critical=True,
        )
    )

    if status.get("backend") == "docker" and docker.get("available"):
        breaches = docker.get("breaches", [])
        layers.append(
            _layer(
                "container_isolation",
                "Container isolation",
                "healthy" if not breaches else "degraded",
                "; ".join(breaches) if breaches else "read-only root, caps dropped, limits active",
                "Recreate the container to re-apply the isolation policy.",
                critical=True,
            )
        )
    else:
        layers.append(
            _layer(
                "container_isolation",
                "Container isolation",
                "degraded" if status.get("docker_available") else "unknown",
                "process sandbox active — no container isolation"
                if not status.get("docker_available")
                else "Docker available but the container backend is not active",
                "Start Docker and recreate the sandbox for the strongest isolation.",
            )
        )

    loopback = bool(owner["addresses"]) and all(
        address.startswith("127.0.0.1") or address.startswith("[::1]")
        for address in owner["addresses"]
    )
    layers.append(
        _layer(
            "network_scope",
            "Network scope",
            "healthy" if loopback else "degraded" if owner["listening"] else "unknown",
            f"listeners: {', '.join(owner['addresses']) or 'none'}",
            "Bind the model only to loopback and deny egress at the host firewall.",
            critical=True,
        )
    )

    layers.append(
        _layer(
            "gateway_policy",
            "Model gateway policy",
            "healthy" if not gateway.circuit_breaker.is_open else "degraded",
            (
                f"rate limit {len(gateway.rate_limiter.requests)} session bucket(s) · "
                f"circuit {'OPEN' if gateway.circuit_breaker.is_open else 'closed'}"
            ),
            "Reset gateway state if a stale breaker or rate bucket is blocking tests.",
        )
    )

    layers.append(
        _layer(
            "audit_chain",
            "Audit chain",
            "healthy" if chain_ok else "breached",
            "SHA-256 chain intact" if chain_ok else f"chain broken at line {chain_broken}",
            "Do not edit the log in place. Preserve it for forensics and rotate it.",
            critical=True,
        )
    )

    layers.append(
        _layer(
            "defence_state",
            "Defence state",
            "healthy" if store["valid"] else "breached",
            store["detail"],
            "Remove invalid learned patterns or restore the defence store from backup.",
            critical=True,
        )
    )

    layers.append(
        _layer(
            "runtime_artifacts",
            "Runtime artifacts",
            "healthy" if evidence["valid"] else "breached",
            f"evidence queue: {evidence['detail']}",
            "Quarantine the corrupted queue and reset it.",
        )
    )

    weight = {"healthy": 0, "unknown": 1, "degraded": 2, "breached": 3}
    damage = sum(weight.get(layer["status"], 1) for layer in layers)
    max_damage = len(layers) * 3
    breached = [layer["id"] for layer in layers if layer["status"] == "breached"]
    degraded = [layer["id"] for layer in layers if layer["status"] == "degraded"]

    report = {
        **_now(),
        "score": round(100 * (1 - damage / max_damage)) if max_damage else 100,
        "damage_score": damage,
        "max_damage": max_damage,
        "status": "critical" if breached else "warning" if degraded else "healthy",
        "breached_layers": breached,
        "degraded_layers": degraded,
        "layers": layers,
        "sandbox": status,
        "port": owner,
        "docker": docker,
        "audit_chain": {"valid": chain_ok, "broken_at": chain_broken},
        "defence_store": store,
    }
    _save_state({"last_health": report})
    if audit:
        log_event(
            EventType.SANDBOX_INTEGRITY,
            "system",
            {
                "status": report["status"],
                "score": report["score"],
                "breached_layers": breached,
                "degraded_layers": degraded,
            },
        )
    return report


def _save_state(update: dict) -> None:
    state = {}
    if SANDBOX_STATE_PATH.exists():
        try:
            with open(SANDBOX_STATE_PATH) as handle:
                state = json.load(handle)
        except (json.JSONDecodeError, OSError):
            state = {}
    state.update(update)
    state["updated_at"] = to_iso(time.time())
    with open(SANDBOX_STATE_PATH, "w") as handle:
        json.dump(state, handle, indent=2)


def _backup(paths: list[Path], label: str) -> Optional[Path]:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    target = QUARANTINE_DIR / f"{label}_{time.strftime('%Y%m%d_%H%M%S')}"
    target.mkdir(parents=True, exist_ok=True)
    copied = []
    for path in paths:
        if path.exists():
            try:
                shutil.copy2(path, target / path.name)
                copied.append(path.name)
            except OSError:
                pass
    if not copied:
        try:
            target.rmdir()
        except OSError:
            pass
        return None
    (target / "README.txt").write_text(
        "Bayora-Shield quarantine backup\n"
        f"label: {label}\ncreated: {to_iso(time.time())}\nfiles: {', '.join(copied)}\n"
    )
    return target


REPAIR_ACTIONS = {
    "restart_sandbox": "Stop and start the sandbox (keeps the same backend).",
    "recreate_sandbox": "Recreate the sandbox from scratch and re-apply isolation.",
    "reset_gateway": "Clear rate-limit buckets and reset the circuit breaker.",
    "repair_defense_store": "Validate learned patterns, quarantine then remove invalid ones.",
    "quarantine_evidence": "Back up the evidence queue and reset it to empty.",
    "repair_permissions": "Restrict runtime file permissions to the operator.",
    "verify_audit_chain": "Re-verify the SHA-256 audit chain.",
    "reset_runtime": "Quarantine and clear the attack journal + evidence queue.",
    "run_safe_repairs": "Run the non-destructive repairs (gateway, defence store, permissions).",
}

DESTRUCTIVE_ACTIONS = {"recreate_sandbox", "quarantine_evidence", "reset_runtime"}


def run_repair(action: str, *, confirm: bool = False, note: str = "") -> dict:
    """Execute one manual repair action and audit it."""
    if action not in REPAIR_ACTIONS:
        return {"ok": False, "action": action, "message": "Unknown repair action"}
    if action in DESTRUCTIVE_ACTIONS and not confirm:
        return {
            "ok": False,
            "action": action,
            "message": "This repair is destructive; pass confirm=true after reviewing the impact.",
            "requires_confirmation": True,
        }

    started = time.time()
    details: dict = {}
    ok = True
    message = ""

    try:
        if action in ("restart_sandbox", "recreate_sandbox"):
            sandbox = get_sandbox()
            sandbox.stop()
            if action == "recreate_sandbox":
                subprocess.run(
                    [docker_cli(), "rm", "-f", DOCKER_CONTAINER_NAME],
                    capture_output=True,
                    timeout=15,
                )
            sandbox.start()
            message = "Sandbox restarted and isolation re-applied"
            details["status"] = sandbox.status()

        elif action == "reset_gateway":
            gateway = get_gateway()
            gateway.rate_limiter.requests.clear()
            gateway.circuit_breaker.failures = 0
            gateway.circuit_breaker.is_open = False
            message = "Gateway rate limits and circuit breaker reset"
            details["circuit_open"] = gateway.circuit_breaker.is_open

        elif action == "repair_defense_store":
            backup = _backup([DEFENSE_STORE_PATH], "defense_store")
            invalid = []
            if DEFENSE_STORE_PATH.exists():
                with open(DEFENSE_STORE_PATH) as handle:
                    data = json.load(handle)
                for key in ("rules", "output_patterns"):
                    valid = []
                    for pattern in data.get(key, []):
                        try:
                            re.compile(pattern, re.IGNORECASE)
                            valid.append(pattern)
                        except re.error:
                            invalid.append(pattern)
                    data[key] = valid
                with open(DEFENSE_STORE_PATH, "w") as handle:
                    json.dump(data, handle, indent=2)
            message = f"Defence store validated ({len(invalid)} invalid pattern(s) removed)"
            details.update({"removed": invalid, "backup": str(backup) if backup else None})

        elif action == "quarantine_evidence":
            backup = _backup([EVIDENCE_QUEUE_PATH], "evidence_queue")
            with open(EVIDENCE_QUEUE_PATH, "w") as handle:
                json.dump([], handle)
            message = "Evidence queue quarantined and reset"
            details["backup"] = str(backup) if backup else None

        elif action == "repair_permissions":
            changed = []
            for path in (AUDIT_LOG_PATH, EVIDENCE_QUEUE_PATH, DEFENSE_STORE_PATH, ATTACK_JOURNAL_PATH):
                if path.exists():
                    try:
                        os.chmod(path, 0o600)
                        changed.append(path.name)
                    except OSError:
                        pass
            for path in (QUARANTINE_DIR,):
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    pass
            message = f"Restricted permissions on {len(changed)} runtime file(s)"
            details["changed"] = changed

        elif action == "verify_audit_chain":
            valid, broken = verify_chain()
            ok = valid
            message = "Audit chain intact" if valid else f"Audit chain broken at line {broken}"
            details.update({"valid": valid, "broken_at": broken})

        elif action == "reset_runtime":
            backup = _backup([EVIDENCE_QUEUE_PATH, ATTACK_JOURNAL_PATH], "runtime_reset")
            with open(EVIDENCE_QUEUE_PATH, "w") as handle:
                json.dump([], handle)
            ATTACK_JOURNAL_PATH.write_text("")
            message = "Attack journal and evidence queue quarantined and reset"
            details["backup"] = str(backup) if backup else None

        elif action == "run_safe_repairs":
            results = []
            for sub_action in ("reset_gateway", "repair_defense_store", "repair_permissions"):
                results.append(run_repair(sub_action, confirm=False))
            ok = all(item.get("ok") for item in results)
            message = "Safe repair bundle completed"
            details["results"] = results

    except Exception as exc:  # pragma: no cover - repair failures must be reported
        ok = False
        message = f"Repair failed: {exc}"

    entry = {
        "ok": ok,
        "action": action,
        "message": message,
        "note": note,
        "details": details,
        "started": started,
        "finished": time.time(),
        "timestamp": time.time(),
        "timestamp_iso": to_iso(time.time()),
        "timestamp_local": to_local_iso(time.time()),
        "duration_seconds": round(time.time() - started, 2),
    }
    _save_state({"last_repair": entry})
    log_event(
        EventType.SANDBOX_REPAIR,
        "blue_team",
        {
            "action": action,
            "ok": ok,
            "message": message,
            "note": note,
            "duration_seconds": entry["duration_seconds"],
            "confirm": confirm,
        },
    )
    return entry
