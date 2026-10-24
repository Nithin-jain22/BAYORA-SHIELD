"""Red team interface backend.

The red team works in an isolated session. They can submit adversarial
prompts and see the model's response, but they never see blue team analysis,
defence updates, or the internals of the defence layers.

Every run is written to the attack journal with its exact input conditions,
layer trace and response assessment.  A finding is released to the blue team
*only* when the response assessment confirms a real bypass — a polite refusal
is a defence win, not a finding.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from ..core.conditions import analyse_prompt
from ..core.llm import SYSTEM_PROMPT
from ..core.timeutil import to_iso, to_local_iso
from ..infrastructure.security_plane import EventType, log_event
from . import journal
from .control_plane import WorkspaceRole, get_control_plane
from .pipeline import run_pipeline


@dataclass
class AttackResult:
    """Result of a single attack attempt."""

    id: str
    timestamp: float
    attack_name: str
    attack_type: str
    prompt: str
    blocked: bool
    blocked_by: Optional[str]
    llm_response: Optional[str]
    raw_response: Optional[str] = None
    layers_bypassed: list[str] = field(default_factory=list)
    layer_trace: list[dict] = field(default_factory=list)
    ml_confidence: float = 0.0
    outcome: str = "blocked"
    assessment: Optional[dict] = None
    conditions: Optional[dict] = None
    defended: bool = False
    bypassed: bool = False
    inconclusive: bool = False
    containment_layer: Optional[str] = None
    journal_id: Optional[str] = None
    evidence_id: Optional[str] = None
    first_failed_layer: Optional[int] = None
    breach_path: str = ""
    timestamp_iso: Optional[str] = None
    timestamp_local: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "timestamp_local": self.timestamp_local,
            "attack_name": self.attack_name,
            "attack_type": self.attack_type,
            "prompt": self.prompt,
            "blocked": self.blocked,
            "blocked_by": self.blocked_by,
            "llm_response": self.llm_response,
            "raw_response": self.raw_response,
            "layers_bypassed": self.layers_bypassed,
            "layer_trace": self.layer_trace,
            "ml_confidence": self.ml_confidence,
            "outcome": self.outcome,
            "assessment": self.assessment,
            "conditions": self.conditions,
            "defended": self.defended,
            "bypassed": self.bypassed,
            "inconclusive": self.inconclusive,
            "containment_layer": self.containment_layer,
            "journal_id": self.journal_id,
            "evidence_id": self.evidence_id,
            "first_failed_layer": self.first_failed_layer,
            "breach_path": self.breach_path,
        }


class RedTeamSession:
    """Isolated red team workspace with no blue team visibility."""

    def __init__(self, operator_name: str):
        self.operator_name = operator_name
        self.session_id = get_control_plane().create_session(WorkspaceRole.RED_TEAM)
        self.attack_history: list[AttackResult] = []

    def submit_attack(
        self,
        prompt: str,
        attack_name: str = "Custom Attack",
        attack_type: str = "custom",
    ) -> AttackResult:
        """Run an adversarial prompt through every defence layer."""
        log_event(
            EventType.ATTACK_SUBMITTED,
            "red_team",
            {
                "session_id": self.session_id,
                "attack_name": attack_name,
                "attack_type": attack_type,
                "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
            },
            self.session_id,
        )

        pipeline = run_pipeline(
            prompt,
            session_id=self.session_id,
            actor="red_team",
            system_prompt=SYSTEM_PROMPT,
            phase="attack",
            attack_name=attack_name,
            attack_type=attack_type,
            operator=self.operator_name,
        )

        now = time.time()
        result = AttackResult(
            id=hashlib.sha256(f"{self.session_id}:{now}".encode()).hexdigest()[:12],
            timestamp=now,
            timestamp_iso=to_iso(now),
            timestamp_local=to_local_iso(now),
            attack_name=attack_name,
            attack_type=attack_type,
            prompt=prompt,
            blocked=pipeline.blocked,
            blocked_by=pipeline.blocked_by,
            llm_response=pipeline.llm_response,
            raw_response=pipeline.raw_response,
            layers_bypassed=pipeline.layers_bypassed,
            layer_trace=[
                {
                    "layer": layer.layer,
                    "name": layer.name,
                    "outcome": layer.outcome,
                    "detail": layer.detail,
                }
                for layer in pipeline.layer_trace
            ],
            ml_confidence=pipeline.ml_confidence,
            outcome=pipeline.outcome,
            assessment=pipeline.assessment,
            conditions=pipeline.conditions or analyse_prompt(prompt).to_dict(),
            defended=pipeline.defended,
            bypassed=pipeline.outcome == "complied",
            inconclusive=pipeline.inconclusive,
            containment_layer=pipeline.containment_layer,
            journal_id=pipeline.journal_id,
            first_failed_layer=pipeline.first_failed_layer,
            breach_path=pipeline.breach_path,
        )
        self.attack_history.append(result)

        if result.bypassed:
            evidence = get_control_plane().submit_attack(
                prompt=prompt,
                attack_name=attack_name,
                attack_type=attack_type,
                session_id=self.session_id,
                layers_bypassed=result.layers_bypassed,
                llm_response=result.llm_response or "",
                outcome=result.outcome,
                assessment=result.assessment,
                conditions=result.conditions,
                journal_id=result.journal_id,
                operator=self.operator_name,
            )
            result.evidence_id = evidence.id

        return result

    def get_history(self) -> list[AttackResult]:
        return self.attack_history.copy()

    def get_stats(self) -> dict:
        total = len(self.attack_history)
        defended = sum(1 for a in self.attack_history if a.defended)
        refused = sum(1 for a in self.attack_history if a.outcome == "refused")
        bypassed = sum(1 for a in self.attack_history if a.bypassed)
        inconclusive = sum(
            1 for a in self.attack_history if a.outcome in ("uncertain", "empty", "error")
        )
        no_signal = sum(
            1 for a in self.attack_history if a.outcome == "safe_completion"
        )
        blocked = sum(
            1 for a in self.attack_history if a.outcome in ("blocked", "filtered")
        )
        return {
            "operator": self.operator_name,
            "session_id": self.session_id,
            "total_attacks": total,
            "blocked": blocked,
            "refused": refused,
            "defended": defended,
            "bypassed": bypassed,
            "inconclusive": inconclusive,
            "no_signal": no_signal,
            "bypass_rate": bypassed / total if total > 0 else 0.0,
            "defense_rate": defended / total if total > 0 else 0.0,
        }

    def clear_history(self) -> None:
        self.attack_history.clear()
