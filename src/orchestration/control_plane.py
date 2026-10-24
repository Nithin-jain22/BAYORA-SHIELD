"""Control plane — orchestrates the red/blue remediation loop.

Flow:
1. A red team attack bypasses every defence layer.
2. Sanitised evidence is released to the blue team (raw payload withheld).
3. Blue team analyses the finding and applies a defence update.
4. Blue team requests a retest; the *system* replays the withheld payload
   through the updated pipeline and reports the verdict.

Isolation guarantees:
* the red team never sees blue team analysis or defence updates,
* the blue team never sees the raw attack sequence, only sanitised evidence,
* every step is written to the tamper-evident audit log.
"""

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional

from ..config import (
    EVIDENCE_QUEUE_PATH,
    RETIRED_EVIDENCE_PATH,
    DEFENSE_UPDATES_PATH,
)
from ..core.response_assessor import assess_response
from ..core.timeutil import to_iso
from ..infrastructure.security_plane import EventType, log_event
from .evidence import excerpt_response_for_blue_team
from .pipeline import run_pipeline


class WorkspaceRole(str, Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"


class EvidenceStatus(str, Enum):
    NEW = "new"
    ANALYZED = "analyzed"
    FIX_APPLIED = "fix_applied"
    RETESTED_FIXED = "retested_fixed"
    RETESTED_VULNERABLE = "retested_vulnerable"
    RETESTED_INCONCLUSIVE = "retested_inconclusive"


EVIDENCE_FIELDS = {
    "id", "timestamp", "attack_type", "attack_prompt", "llm_response",
    "layers_bypassed", "session_id", "status", "severity", "root_cause",
    "recommended_fix", "defense_update", "analysis_at", "retest_result",
    "retest_at", "attack_name", "outcome", "assessment", "conditions",
    "journal_id", "operator",
}


@dataclass
class EvidenceItem:
    """Sanitised failure evidence released to the blue team."""

    id: str
    timestamp: float
    attack_type: str
    attack_prompt: str
    llm_response: str
    layers_bypassed: list[str]
    session_id: str
    attack_name: str = "Custom Attack"
    status: str = EvidenceStatus.NEW.value
    severity: Optional[str] = None
    root_cause: Optional[str] = None
    recommended_fix: Optional[str] = None
    defense_update: Optional[str] = None
    analysis_at: Optional[float] = None
    retest_result: Optional[dict] = None
    retest_at: Optional[float] = None
    outcome: str = "complied"
    assessment: Optional[dict] = None
    conditions: Optional[dict] = None
    journal_id: Optional[str] = None
    operator: Optional[str] = None


@dataclass
class DefenseUpdate:
    """Blue team's defence improvement."""

    id: str
    timestamp: str
    evidence_id: str
    update_type: str
    description: str
    applied: bool = False


def _load_evidence(raw: dict) -> EvidenceItem:
    """Load an evidence item, tolerating older schemas."""
    if "analysis" in raw and "root_cause" not in raw:
        analysis = raw.pop("analysis") or ""
        raw["root_cause"] = analysis
        raw.pop("analyzed", None)
    filtered = {k: v for k, v in raw.items() if k in EVIDENCE_FIELDS}
    return EvidenceItem(**filtered)


class ControlPlane:
    """Central orchestrator that maintains team isolation."""

    def __init__(self):
        self._evidence_queue: list[EvidenceItem] = []
        self._defense_updates: list[DefenseUpdate] = []
        self._sessions: dict[str, dict] = {}
        self._load_state()

    def _load_state(self):
        if EVIDENCE_QUEUE_PATH.exists():
            try:
                with open(EVIDENCE_QUEUE_PATH) as f:
                    self._evidence_queue = [
                        _load_evidence(item) for item in json.load(f)
                    ]
            except (json.JSONDecodeError, TypeError, KeyError):
                self._evidence_queue = []
        if DEFENSE_UPDATES_PATH.exists():
            try:
                with open(DEFENSE_UPDATES_PATH) as f:
                    self._defense_updates = [
                        DefenseUpdate(**item) for item in json.load(f)
                    ]
            except (json.JSONDecodeError, TypeError, KeyError):
                self._defense_updates = []

        self._reconcile_evidence()

    def _reconcile_evidence(self) -> None:
        """Withdraw legacy findings that do not survive response assessment.

        Early builds released any response that cleared the output filter.  That
        produced false findings where the model actually refused.  Reassess
        those records once, keep the validated bypasses, and move everything
        else to an append-only retired-evidence file with an audit event.
        """
        kept: list[EvidenceItem] = []
        retired: list[dict] = []
        changed = False

        for item in self._evidence_queue:
            is_released_bypass = item.outcome in ("complied", "bypassed")
            assessment = item.assessment
            if not assessment and item.llm_response:
                assessment = assess_response(
                    item.attack_prompt or "", item.llm_response
                ).to_dict()
                item.assessment = assessment
                changed = True

            actual = (assessment or {}).get("outcome")
            if is_released_bypass and actual == "complied":
                kept.append(item)
                continue

            item.outcome = actual or item.outcome
            retired.append(
                {
                    **asdict(item),
                    "retired_at": time.time(),
                    "retired_at_iso": to_iso(time.time()),
                    "retired_reason": (
                        "Legacy evidence did not meet the confirmed-bypass threshold"
                        if is_released_bypass
                        else "Evidence was not a confirmed bypass"
                    ),
                }
            )
            changed = True

        if not retired:
            self._evidence_queue = kept
            if changed:
                self._save_state()
            return

        RETIRED_EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(RETIRED_EVIDENCE_PATH, "a") as handle:
            for entry in retired:
                handle.write(json.dumps(entry, default=str) + "\n")

        self._evidence_queue = kept
        self._save_state()
        log_event(
            EventType.EVIDENCE_RETIRED,
            "system",
            {
                "action": "legacy_evidence_reassessment",
                "retired": [entry["id"] for entry in retired],
                "kept": [entry.id for entry in kept],
                "retired_count": len(retired),
            },
        )

    def _save_state(self):
        with open(EVIDENCE_QUEUE_PATH, "w") as f:
            json.dump([asdict(item) for item in self._evidence_queue], f, indent=2)
        with open(DEFENSE_UPDATES_PATH, "w") as f:
            json.dump([asdict(item) for item in self._defense_updates], f, indent=2)

    def create_session(self, role: WorkspaceRole) -> str:
        session_id = hashlib.sha256(
            f"{role.value}:{time.time()}:{id(self)}".encode()
        ).hexdigest()[:16]
        self._sessions[session_id] = {
            "role": role.value,
            "created_at": time.time(),
            "active": True,
        }
        log_event(
            EventType.AUTH_SUCCESS,
            role.value,
            {"session_id": session_id, "role": role.value},
            session_id,
        )
        return session_id

    def submit_attack(
        self,
        prompt: str,
        attack_name: str,
        attack_type: str,
        session_id: str,
        layers_bypassed: list[str],
        llm_response: str,
        outcome: str = "complied",
        assessment: Optional[dict] = None,
        conditions: Optional[dict] = None,
        journal_id: Optional[str] = None,
        operator: Optional[str] = None,
    ) -> EvidenceItem:
        evidence = EvidenceItem(
            id=hashlib.sha256(f"{session_id}:{time.time()}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            attack_type=attack_type,
            attack_prompt=prompt,
            llm_response=llm_response,
            layers_bypassed=layers_bypassed,
            session_id=session_id,
            attack_name=attack_name,
            outcome=outcome,
            assessment=assessment,
            conditions=conditions,
            journal_id=journal_id,
            operator=operator,
        )
        self._evidence_queue.append(evidence)
        self._save_state()

        log_event(
            EventType.EVIDENCE_RELEASED,
            "system",
            {
                "evidence_id": evidence.id,
                "attack_type": attack_type,
                "layers_bypassed": layers_bypassed,
                "outcome": outcome,
                "journal_id": journal_id,
            },
            session_id,
        )
        return evidence

    def get_all_evidence(self, status: Optional[str] = None) -> list[EvidenceItem]:
        items = self._evidence_queue
        if status:
            items = [i for i in items if i.status == status]
        return items

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        return next((i for i in self._evidence_queue if i.id == evidence_id), None)

    def analyze_evidence(
        self,
        evidence_id: str,
        root_cause: str,
        severity: str,
        recommended_fix: str,
        session_id: str,
    ) -> bool:
        item = self.get_evidence(evidence_id)
        if not item:
            return False
        item.root_cause = root_cause
        item.severity = severity
        item.recommended_fix = recommended_fix
        item.analysis_at = time.time()
        if item.status == EvidenceStatus.NEW.value:
            item.status = EvidenceStatus.ANALYZED.value
        self._save_state()

        log_event(
            EventType.BLUE_TEAM_UPDATE,
            "blue_team",
            {
                "evidence_id": evidence_id,
                "action": "analysis",
                "severity": severity,
            },
            session_id,
        )
        return True

    def submit_defense_update(
        self,
        evidence_id: str,
        update_type: str,
        description: str,
        session_id: str,
    ) -> DefenseUpdate:
        update = DefenseUpdate(
            id=hashlib.sha256(f"update:{time.time()}".encode()).hexdigest()[:12],
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            evidence_id=evidence_id,
            update_type=update_type,
            description=description,
            applied=True,
        )
        self._defense_updates.append(update)

        item = self.get_evidence(evidence_id)
        if item:
            item.defense_update = update.id
            item.status = EvidenceStatus.FIX_APPLIED.value
        self._save_state()

        log_event(
            EventType.BLUE_TEAM_UPDATE,
            "blue_team",
            {
                "evidence_id": evidence_id,
                "update_type": update_type,
                "update_id": update.id,
            },
            session_id,
        )
        return update

    def retest_evidence(self, evidence_id: str, session_id: str) -> dict:
        """Replay the withheld payload through the updated pipeline.

        Returns a sanitised verdict (no prompt, no raw response).
        """
        item = self.get_evidence(evidence_id)
        if not item:
            return {"error": "Evidence not found"}

        result = run_pipeline(
            item.attack_prompt,
            session_id=session_id,
            actor="system",
            phase="retest",
            attack_name=item.attack_name,
            attack_type=item.attack_type,
            operator=item.operator,
            evidence_id=item.id,
        )

        verdict = {
            "blocked": result.blocked,
            "defended": result.defended,
            "bypassed": result.outcome == "complied",
            "outcome": result.outcome,
            "blocked_by": result.blocked_by,
            "containment_layer": result.containment_layer,
            "layers_bypassed": result.layers_bypassed,
            "layer_trace": [asdict(layer) for layer in result.layer_trace],
            "assessment": result.assessment,
            "response_excerpt": excerpt_response_for_blue_team(
                result.llm_response, limit=800
            ),
            "conditions": result.conditions,
            "journal_id": result.journal_id,
            "timestamp": time.time(),
            "timestamp_iso": to_iso(time.time()),
            "error": result.gateway_error,
            "inconclusive": bool(
                result.gateway_error or result.outcome in ("uncertain", "empty", "safe_completion")
            ),
        }
        item.retest_result = verdict
        item.retest_at = time.time()

        if result.gateway_error or result.outcome in ("uncertain", "empty", "safe_completion"):
            item.status = EvidenceStatus.RETESTED_INCONCLUSIVE.value
        elif result.defended or result.outcome in ("blocked", "filtered", "refused"):
            item.status = EvidenceStatus.RETESTED_FIXED.value
        else:
            item.status = EvidenceStatus.RETESTED_VULNERABLE.value
        self._save_state()

        log_event(
            EventType.BLUE_TEAM_UPDATE,
            "blue_team",
            {
                "evidence_id": evidence_id,
                "action": "retest",
                "fixed": item.status == EvidenceStatus.RETESTED_FIXED.value,
                "inconclusive": item.status == EvidenceStatus.RETESTED_INCONCLUSIVE.value,
                "outcome": result.outcome,
                "blocked_by": result.blocked_by,
            },
            session_id,
        )
        return verdict

    def get_red_team_view(self, session_id: str) -> dict:
        return {
            "session_id": session_id,
            "role": "red_team",
            "pending_evidence": len(
                [e for e in self._evidence_queue if e.session_id == session_id]
            ),
            "total_attacks_submitted": len(
                [e for e in self._evidence_queue if e.session_id == session_id]
            ),
        }

    def get_blue_team_view(self, session_id: str) -> dict:
        return {
            "session_id": session_id,
            "role": "blue_team",
            "unanalyzed_evidence": len(
                [e for e in self._evidence_queue if e.status == EvidenceStatus.NEW.value]
            ),
            "total_evidence": len(self._evidence_queue),
            "defense_updates": len(self._defense_updates),
        }


_control_plane: Optional[ControlPlane] = None


def get_control_plane() -> ControlPlane:
    global _control_plane
    if _control_plane is None:
        _control_plane = ControlPlane()
    return _control_plane
