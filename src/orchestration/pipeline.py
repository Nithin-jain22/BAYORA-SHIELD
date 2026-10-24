"""Single executable defence pipeline shared by attacks and retests.

Both the red team attack path and the blue team retest path call
:func:`run_pipeline`, which guarantees that a remediation is verified with
exactly the same layered defences as the original attack.

Outcome model
-------------
``blocked``      a defence layer stopped the prompt (L1/L2)
``filtered``     the output filter replaced a leaking response (L4)
``refused``      the model itself declined / stayed on policy (model alignment)
``complied``     confirmed bypass — the model leaked or followed the attack
``uncertain``    no clear refusal or compliance; needs manual review
``error``        the gateway/sandbox failed before a verdict was possible

Only ``complied`` is released to the blue team as a finding.  This prevents the
old false-positive where a polite refusal was counted as a bypass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.conditions import analyse_prompt
from ..core.defense import check_defense
from ..core.llm import SYSTEM_PROMPT
from ..core.ml_classifier import ml_check
from ..core.output_filter import filter_output
from ..core.response_assessor import assess_response
from ..infrastructure.gateway import get_gateway
from ..infrastructure.security_plane import EventType, log_event
from . import journal

DEFENDED_OUTCOMES = {"blocked", "filtered", "refused"}
INCONCLUSIVE_OUTCOMES = {"uncertain", "empty", "safe_completion"}
BYPASS_OUTCOMES = {"complied"}


@dataclass
class LayerResult:
    layer: int
    name: str
    outcome: str  # blocked | allowed | filtered | clean | refused | uncertain | error
    detail: str


@dataclass
class PipelineResult:
    prompt: str
    blocked: bool
    blocked_by: Optional[str]
    llm_response: Optional[str]
    raw_response: Optional[str]
    layers_bypassed: list[str] = field(default_factory=list)
    layer_trace: list[LayerResult] = field(default_factory=list)
    gateway_error: Optional[str] = None
    ml_confidence: float = 0.0
    outcome: str = "blocked"
    assessment: Optional[dict] = None
    conditions: Optional[dict] = None
    bypassed: bool = False
    defended: bool = False
    inconclusive: bool = False
    containment_layer: Optional[str] = None
    journal_id: Optional[str] = None
    first_failed_layer: Optional[int] = None
    breach_path: str = ""


def run_pipeline(
    prompt: str,
    session_id: str = "default",
    actor: str = "system",
    system_prompt: str = SYSTEM_PROMPT,
    phase: str = "attack",
    attack_name: str = "Custom Attack",
    attack_type: str = "custom",
    operator: Optional[str] = None,
    evidence_id: Optional[str] = None,
) -> PipelineResult:
    """Run one prompt through every defence layer.

    ``phase`` is recorded in the audit trail so a blue-team retest can be
    distinguished from the original attack.
    """
    trace: list[LayerResult] = []
    bypassed: list[str] = []
    conditions = analyse_prompt(prompt).to_dict()

    l1_blocked, l1_reason = check_defense(prompt)
    if l1_blocked:
        trace.append(LayerResult(1, "Rule-based filter", "blocked", l1_reason))
        log_event(
            EventType.DEFENSE_BLOCKED,
            "system",
            {"layer": 1, "reason": l1_reason, "phase": phase, "session_id": session_id},
            session_id,
        )
        return _finish(
            PipelineResult(
                prompt=prompt,
                blocked=True,
                blocked_by=f"Layer 1 (Rules): {l1_reason}",
                llm_response=None,
                raw_response=None,
                layer_trace=trace,
                outcome="blocked",
                conditions=conditions,
                defended=True,
                containment_layer="L1 · Rule-based filter",
            ),
            session_id=session_id,
            phase=phase,
            attack_name=attack_name,
            attack_type=attack_type,
            operator=operator,
            evidence_id=evidence_id,
        )
    trace.append(LayerResult(1, "Rule-based filter", "allowed", l1_reason))
    bypassed.append("layer_1_rules")

    l2_blocked, l2_confidence, l2_reason = ml_check(prompt)
    if l2_blocked:
        trace.append(LayerResult(2, "ML classifier", "blocked", l2_reason))
        log_event(
            EventType.DEFENSE_BLOCKED,
            "system",
            {
                "layer": 2,
                "reason": l2_reason,
                "confidence": l2_confidence,
                "phase": phase,
                "session_id": session_id,
            },
            session_id,
        )
        return _finish(
            PipelineResult(
                prompt=prompt,
                blocked=True,
                blocked_by=f"Layer 2 (ML): {l2_reason}",
                llm_response=None,
                raw_response=None,
                layers_bypassed=bypassed,
                layer_trace=trace,
                ml_confidence=l2_confidence,
                outcome="blocked",
                conditions=conditions,
                defended=True,
                containment_layer="L2 · ML classifier",
            ),
            session_id=session_id,
            phase=phase,
            attack_name=attack_name,
            attack_type=attack_type,
            operator=operator,
            evidence_id=evidence_id,
        )
    trace.append(LayerResult(2, "ML classifier", "allowed", l2_reason))
    bypassed.append("layer_2_ml")

    gateway_result = get_gateway().query(
        prompt,
        system_prompt=system_prompt,
        session_id=session_id,
        actor=actor,
    )
    if not gateway_result["success"]:
        trace.append(
            LayerResult(3, "Model gateway", "error", gateway_result["error"] or "gateway error")
        )
        log_event(
            EventType.VIOLATION_DETECTED,
            actor,
            {
                "reason": "gateway_error",
                "error": gateway_result["error"],
                "phase": phase,
                "session_id": session_id,
            },
            session_id,
        )
        return _finish(
            PipelineResult(
                prompt=prompt,
                blocked=False,
                blocked_by=f"Gateway: {gateway_result['error']}",
                llm_response=None,
                raw_response=None,
                layers_bypassed=bypassed,
                layer_trace=trace,
                gateway_error=gateway_result["error"],
                ml_confidence=l2_confidence,
                outcome="error",
                conditions=conditions,
                inconclusive=True,
            ),
            session_id=session_id,
            phase=phase,
            attack_name=attack_name,
            attack_type=attack_type,
            operator=operator,
            evidence_id=evidence_id,
        )
    trace.append(LayerResult(3, "Model gateway", "allowed", "Prompt delivered to the sandboxed model"))
    bypassed.append("layer_3_hardened_prompt")

    raw_response = gateway_result["response"]
    final_response, was_filtered, filter_reason = filter_output(raw_response)

    if was_filtered:
        trace.append(LayerResult(4, "Output filter", "filtered", filter_reason))
        assessment = assess_response(
            prompt, raw_response, filtered=True, filter_reason=filter_reason
        )
        trace.append(
            LayerResult(5, "Response assessment", "filtered", assessment.reason)
        )
        log_event(
            EventType.OUTPUT_FILTERED,
            "system",
            {"reason": filter_reason, "phase": phase, "session_id": session_id},
            session_id,
        )
        return _finish(
            PipelineResult(
                prompt=prompt,
                blocked=True,
                blocked_by=f"Layer 4 (Output Filter): {filter_reason}",
                llm_response=final_response,
                raw_response=raw_response,
                layers_bypassed=bypassed,
                layer_trace=trace,
                ml_confidence=l2_confidence,
                outcome="filtered",
                assessment=assessment.to_dict(),
                conditions=conditions,
                defended=True,
                containment_layer="L4 · Output filter",
            ),
            session_id=session_id,
            phase=phase,
            attack_name=attack_name,
            attack_type=attack_type,
            operator=operator,
            evidence_id=evidence_id,
        )
    trace.append(LayerResult(4, "Output filter", "clean", filter_reason))
    bypassed.append("layer_4_output_filter")

    assessment = assess_response(prompt, raw_response)
    layer_outcome = {
        "complied": "bypassed",
        "refused": "refused",
        "uncertain": "uncertain",
        "empty": "uncertain",
        "safe_completion": "clean",
        "filtered": "filtered",
    }.get(assessment.outcome, "uncertain")
    trace.append(LayerResult(5, "Response assessment", layer_outcome, assessment.reason))

    if assessment.outcome == "complied":
        outcome = "complied"
        blocked = False
        blocked_by = None
        defended = False
        inconclusive = False
        containment = None
        first_failed_layer = 1
        breach_path = " → ".join(
            {
                "layer_1_rules": "L1 Rules",
                "layer_2_ml": "L2 ML",
                "layer_3_hardened_prompt": "L3 Prompt",
                "layer_4_output_filter": "L4 Output",
            }.get(layer, layer)
            for layer in bypassed
        )
        for layer in bypassed:
            log_event(
                EventType.LAYER_BREACH,
                "system",
                {
                    "layer": layer,
                    "phase": phase,
                    "attack_type": attack_type,
                    "outcome": outcome,
                    "session_id": session_id,
                },
                session_id,
            )
    elif assessment.outcome == "refused":
        outcome = "refused"
        blocked = True
        blocked_by = f"Model alignment (L5): {assessment.reason}"
        defended = True
        inconclusive = False
        containment = "L5 · Model alignment"
        first_failed_layer = None
        breach_path = ""
    elif assessment.outcome == "safe_completion":
        outcome = "safe_completion"
        blocked = False
        blocked_by = None
        defended = False
        inconclusive = True
        containment = None
        first_failed_layer = None
        breach_path = ""
    else:
        outcome = assessment.outcome if assessment.outcome != "empty" else "empty"
        blocked = False
        blocked_by = None
        defended = False
        inconclusive = True
        containment = None
        first_failed_layer = None
        breach_path = ""

    log_event(
        EventType.RESPONSE_ASSESSED,
        "system",
        {
            "outcome": outcome,
            "reason": assessment.reason,
            "refusal_score": assessment.refusal_score,
            "compliance_score": assessment.compliance_score,
            "leaked_prompt": assessment.leaked_prompt,
            "harmful_compliance": assessment.harmful_compliance,
            "persona_adopted": assessment.persona_adopted,
            "phase": phase,
            "session_id": session_id,
        },
        session_id,
    )

    if outcome in DEFENDED_OUTCOMES:
        log_event(
            EventType.DEFENSE_BLOCKED,
            "system",
            {
                "layer": 5,
                "reason": assessment.reason,
                "outcome": outcome,
                "phase": phase,
                "session_id": session_id,
            },
            session_id,
        )

    if outcome not in ("complied",):
        log_event(
            EventType.DEFENSE_PASSED,
            "system",
            {
                "phase": phase,
                "session_id": session_id,
                "layers_bypassed": bypassed,
                "outcome": outcome,
            },
            session_id,
        )

    return _finish(
        PipelineResult(
            prompt=prompt,
            blocked=blocked,
            blocked_by=blocked_by,
            llm_response=final_response,
            raw_response=raw_response,
            layers_bypassed=bypassed,
            layer_trace=trace,
            ml_confidence=l2_confidence,
            outcome=outcome,
            assessment=assessment.to_dict(),
            conditions=conditions,
            bypassed=outcome == "complied",
            defended=defended,
            inconclusive=inconclusive,
            containment_layer=containment,
            first_failed_layer=first_failed_layer,
            breach_path=breach_path,
        ),
        session_id=session_id,
        phase=phase,
        attack_name=attack_name,
        attack_type=attack_type,
        operator=operator,
        evidence_id=evidence_id,
    )


def _finish(
    result: PipelineResult,
    *,
    session_id: str,
    phase: str,
    attack_name: str,
    attack_type: str,
    operator: Optional[str],
    evidence_id: Optional[str],
) -> PipelineResult:
    """Write the run to the journal without letting reporting break the flow."""
    try:
        entry = journal.record_pipeline_run(
            result=result,
            session_id=session_id,
            phase=phase,
            attack_name=attack_name,
            attack_type=attack_type,
            operator=operator,
            evidence_id=evidence_id,
        )
        result.journal_id = entry["id"]
        result.first_failed_layer = entry.get("first_failed_layer")
        result.breach_path = entry.get("breach_path", result.breach_path)
    except Exception:  # pragma: no cover - journal must never break the pipeline
        pass
    return result
