"""
evaluation_plane.py — Reproducible Test Runs and Metrics

Provides:
  - Structured test runs with versioning
  - Per-attack-type breakdowns
  - Response-outcome breakdown (blocked / refused / complied / uncertain)
  - Regression tracking (compare runs over time)
  - Exportable reports (JSON)
"""

from __future__ import annotations

import json
import time
import hashlib
from typing import Optional
from dataclasses import dataclass, field, asdict

from ..config import EVALUATION_RUNS_DIR
from ..core.timeutil import to_iso

RUNS_DIR = EVALUATION_RUNS_DIR
RUNS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class TestRun:
    """A single evaluation run."""

    run_id: str
    timestamp: str
    model: str
    total_attacks: int
    blocked: int
    bypassed: int
    block_rate: float
    bypass_rate: float
    per_type_breakdown: dict
    duration_seconds: float = 0.0
    defense_version: str = "v1"
    refused: int = 0
    inconclusive: int = 0
    outcome_breakdown: dict = field(default_factory=dict)
    session_id: Optional[str] = None


class EvaluationPlane:
    """Manages evaluation runs and computes comparative metrics."""

    def __init__(self):
        self.runs: list[TestRun] = []
        self._load_runs()

    def _load_runs(self):
        for run_file in sorted(RUNS_DIR.glob("run_*.json")):
            try:
                with open(run_file) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            allowed = TestRun.__dataclass_fields__.keys()
            filtered = {k: v for k, v in data.items() if k in allowed}
            try:
                self.runs.append(TestRun(**filtered))
            except TypeError:
                continue

    def create_run(
        self,
        model: str,
        results: list[dict],
        defense_version: str = "v1",
        session_id: Optional[str] = None,
    ) -> TestRun:
        """Create a new evaluation run from attack results.

        Each result may carry an explicit ``outcome`` (preferred) or the legacy
        ``blocked`` boolean.  A refused response counts as defended, never as a
        bypass.
        """
        total = len(results)
        outcomes: dict[str, int] = {}
        per_type: dict[str, dict] = {}

        for result in results:
            outcome = result.get("outcome")
            if not outcome:
                outcome = "blocked" if result.get("blocked") else "complied"
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

            attack_type = result.get("attack_type", "unknown")
            bucket = per_type.setdefault(
                attack_type,
                {
                    "total": 0,
                    "blocked": 0,
                    "refused": 0,
                    "bypassed": 0,
                    "inconclusive": 0,
                },
            )
            bucket["total"] += 1
            if outcome in ("blocked", "filtered"):
                bucket["blocked"] += 1
            elif outcome == "refused":
                bucket["refused"] += 1
            elif outcome == "complied":
                bucket["bypassed"] += 1
            else:
                bucket["inconclusive"] += 1

        blocked = outcomes.get("blocked", 0) + outcomes.get("filtered", 0)
        refused = outcomes.get("refused", 0)
        bypassed = outcomes.get("complied", 0)
        inconclusive = total - blocked - refused - bypassed
        defended = blocked + refused

        run = TestRun(
            run_id=hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
            timestamp=to_iso(time.time()) or "",
            model=model,
            total_attacks=total,
            blocked=defended,
            bypassed=bypassed,
            block_rate=defended / total if total > 0 else 0.0,
            bypass_rate=bypassed / total if total > 0 else 0.0,
            per_type_breakdown=per_type,
            duration_seconds=0.0,
            defense_version=defense_version,
            refused=refused,
            inconclusive=inconclusive,
            outcome_breakdown=outcomes,
            session_id=session_id,
        )

        self.runs.append(run)
        self._save_run(run)
        return run

    def _save_run(self, run: TestRun):
        run_file = RUNS_DIR / f"run_{run.run_id}.json"
        with open(run_file, "w") as f:
            json.dump(asdict(run), f, indent=2)

    def compare_runs(self, run_id_1: str, run_id_2: str) -> dict:
        """Compare two runs to track regression or improvement."""
        run1 = next((r for r in self.runs if r.run_id == run_id_1), None)
        run2 = next((r for r in self.runs if r.run_id == run_id_2), None)

        if not run1 or not run2:
            return {"error": "One or both runs not found"}

        return {
            "run_1": run1.run_id,
            "run_2": run2.run_id,
            "block_rate_change": run2.block_rate - run1.block_rate,
            "bypass_rate_change": run2.bypass_rate - run1.bypass_rate,
            "new_attacks_blocked": run2.blocked - run1.blocked,
            "new_attacks_bypassed": run2.bypassed - run1.bypassed,
            "defense_improved": run2.block_rate > run1.block_rate,
        }

    def get_trend(self) -> list[dict]:
        """Get block rate trend across all runs."""
        return [
            {
                "run_id": r.run_id,
                "timestamp": r.timestamp,
                "block_rate": r.block_rate,
                "bypass_rate": r.bypass_rate,
                "defense_version": r.defense_version,
                "refused": r.refused,
                "inconclusive": r.inconclusive,
                "total": r.total_attacks,
            }
            for r in sorted(self.runs, key=lambda x: x.timestamp)
        ]

    def export_report(self, run_id: str) -> str:
        """Export a run as a JSON report."""
        run = next((r for r in self.runs if r.run_id == run_id), None)
        if not run:
            return json.dumps({"error": "Run not found"})
        return json.dumps(asdict(run), indent=2)


_evaluation_plane: Optional[EvaluationPlane] = None


def get_evaluation_plane() -> EvaluationPlane:
    global _evaluation_plane
    if _evaluation_plane is None:
        _evaluation_plane = EvaluationPlane()
    return _evaluation_plane
