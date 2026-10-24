"""Blue team interface backend.

The blue team receives sanitised evidence only. Their workflow is:

    analyse finding  ->  apply defence fix  ->  request retest

Retests are executed by the control plane, which replays the withheld payload
through the updated pipeline and returns a verdict.
"""

from dataclasses import dataclass
from typing import Optional

import time

from ..core import updater
from ..infrastructure.security_plane import EventType, log_event
from .control_plane import WorkspaceRole, get_control_plane
from .evidence import sanitize_evidence


@dataclass
class AnalysisReport:
    evidence_id: str
    analyst_name: str
    root_cause: str
    severity: str
    recommended_fix: str
    timestamp: float


class BlueTeamSession:
    """Isolated blue team workspace without red team visibility."""

    def __init__(self, operator_name: str):
        self.operator_name = operator_name
        self.session_id = get_control_plane().create_session(WorkspaceRole.BLUE_TEAM)
        self.analysis_reports: list[AnalysisReport] = []

    def get_evidence(self, status: Optional[str] = None) -> list[dict]:
        """Return sanitised evidence — never the raw attack prompt."""
        items = get_control_plane().get_all_evidence(status=status)
        return [sanitize_evidence(item) for item in items]

    def get_evidence_item(self, evidence_id: str) -> Optional[dict]:
        item = get_control_plane().get_evidence(evidence_id)
        return sanitize_evidence(item) if item else None

    def analyze_evidence(
        self,
        evidence_id: str,
        root_cause: str,
        severity: str,
        recommended_fix: str,
    ) -> bool:
        success = get_control_plane().analyze_evidence(
            evidence_id=evidence_id,
            root_cause=root_cause,
            severity=severity,
            recommended_fix=recommended_fix,
            session_id=self.session_id,
        )
        if success:
            self.analysis_reports.append(
                AnalysisReport(
                    evidence_id=evidence_id,
                    analyst_name=self.operator_name,
                    root_cause=root_cause,
                    severity=severity,
                    recommended_fix=recommended_fix,
                    timestamp=time.time(),
                )
            )
        return success

    def apply_defense_update(
        self,
        evidence_id: str,
        update_type: str,
        description: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Apply a defence fix and record it.

        Returns ``(update_id, error)``. A validation error leaves the defence
        unchanged so a bad regex can never break the pipeline.
        """
        description = (description or "").strip()
        if not description:
            return None, "Defence update cannot be empty"

        try:
            if update_type == "rule":
                updater.add_attack_keyword(description)
            elif update_type == "ml_training":
                updater.add_ml_attack(description)
            elif update_type == "output_filter":
                updater.add_output_pattern(description)
        except ValueError as exc:
            return None, str(exc)

        update = get_control_plane().submit_defense_update(
            evidence_id=evidence_id,
            update_type=update_type,
            description=description,
            session_id=self.session_id,
        )
        log_event(
            EventType.BLUE_TEAM_UPDATE,
            "blue_team",
            {
                "evidence_id": evidence_id,
                "action": "apply_defense_update",
                "update_type": update_type,
            },
            self.session_id,
        )
        return update.id, None

    def retest(self, evidence_id: str) -> dict:
        """Ask the control plane to replay the withheld payload."""
        return get_control_plane().retest_evidence(evidence_id, self.session_id)

    def get_stats(self) -> dict:
        items = get_control_plane().get_all_evidence()
        fixed = sum(1 for i in items if i.status == "retested_fixed")
        vulnerable = sum(1 for i in items if i.status == "retested_vulnerable")
        inconclusive = sum(
            1 for i in items if i.status in ("retested_inconclusive", "fix_applied")
        )
        pending = sum(
            1 for i in items if i.status in ("new", "analyzed", "fix_applied")
        )
        return {
            "operator": self.operator_name,
            "session_id": self.session_id,
            "total_evidence": len(items),
            "pending": pending,
            "fixed": fixed,
            "still_vulnerable": vulnerable,
            "inconclusive": inconclusive,
            "evidence_analyzed": len(self.analysis_reports),
        }
