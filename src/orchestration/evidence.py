"""Controlled release of failure evidence to the blue team.

The blue team must be able to diagnose a defence gap without ever reading the
red team's raw attack sequence. This module produces a *sanitised* evidence
view:

* the payload is masked (token structure survives, wording does not),
* behavioural signals and defence hints are extracted,
* a stable fingerprint lets the blue team reference the finding,
* the model's own output is shown as failure evidence (truncated).

The raw prompt stays inside the control plane and is only used by the system
when the blue team requests a retest.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from ..core.timeutil import to_iso, to_local_iso

SIGNAL_RULES = {
    "instruction_override": [
        r"\b(ignore|disregard|forget|override|bypass|skip)\b",
    ],
    "instruction_extraction": [
        r"\b(system prompt|instructions|hidden|confidential|configured|guidance|directives)\b",
    ],
    "role_manipulation": [
        r"\b(you are now|act as|pretend|persona|dan|alice|developer mode|jailbreak)\b",
    ],
    "policy_bypass": [
        r"\b(no rules|no restrictions|unrestricted|unfiltered|no limits|anything now)\b",
    ],
    "indirect_injection": [
        r"\b(document|summarize|found online|embedded|translation)\b",
    ],
    "social_engineering": [
        r"\b(grandmother|audit|compliance|emergency|hypothetical|game)\b",
    ],
}

SIGNAL_LABELS = {
    "instruction_override": "Instruction override attempt",
    "instruction_extraction": "Instruction / prompt extraction",
    "role_manipulation": "Role or persona manipulation",
    "policy_bypass": "Policy bypass language",
    "indirect_injection": "Indirect / embedded injection",
    "social_engineering": "Social-engineering framing",
}

DEFENCE_HINTS = {
    "instruction_override": "Add Layer 1 rules for paraphrased override verbs (restate, disregard, skip).",
    "instruction_extraction": "Block requests that ask for startup guidance, configuration or earlier text.",
    "role_manipulation": "Reinforce role-lock rules and add persona names to the output filter.",
    "policy_bypass": "Extend the rule and ML sets with 'mode / limits / filters disabled' phrasing.",
    "indirect_injection": "Scan embedded documents for imperative instructions before summarisation.",
    "social_engineering": "Flag benign-sounding wrappers (audits, games, emergencies) that request policy data.",
}

LAYER_LABELS = {
    "layer_1_rules": "L1 · Rule filter",
    "layer_2_ml": "L2 · ML classifier",
    "layer_3_hardened_prompt": "L3 · Hardened prompt",
    "layer_4_output_filter": "L4 · Output filter",
}


def extract_signals(prompt: str) -> list[str]:
    signals = []
    for signal, patterns in SIGNAL_RULES.items():
        if any(re.search(pattern, prompt, re.IGNORECASE) for pattern in patterns):
            signals.append(signal)
    return signals


def mask_prompt(prompt: str, max_chars: int = 320) -> str:
    """Replace every word with a uniform block while preserving structure."""
    masked = re.sub(r"[A-Za-z0-9_]+", "████", prompt)
    masked = re.sub(r"\n{3,}", "\n\n", masked)
    if len(masked) > max_chars:
        masked = masked[:max_chars].rstrip() + " …"
    return masked


def _truncate(text: Optional[str], limit: int = 600) -> str:
    if not text:
        return "—"
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " …"


def sanitize_evidence(item) -> dict:
    """Build the blue team's sanitised view of an evidence item."""
    prompt = getattr(item, "attack_prompt", "") or ""
    signals = extract_signals(prompt)
    response = getattr(item, "llm_response", None)

    return {
        "evidence_id": item.id,
        "timestamp": item.timestamp,
        "timestamp_iso": to_iso(item.timestamp),
        "timestamp_local": to_local_iso(item.timestamp),
        "attack_type": item.attack_type,
        "attack_name": getattr(item, "attack_name", "Custom Attack"),
        "status": getattr(item, "status", "new"),
        "severity": getattr(item, "severity", None),
        "outcome": getattr(item, "outcome", "complied"),
        "assessment": getattr(item, "assessment", None),
        "conditions": getattr(item, "conditions", None),
        "journal_id": getattr(item, "journal_id", None),
        "operator": getattr(item, "operator", None),
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "prompt_length": len(prompt),
        "word_count": len(prompt.split()),
        "redacted_prompt": mask_prompt(prompt),
        "signals": signals,
        "signal_labels": [SIGNAL_LABELS[s] for s in signals],
        "defence_hints": [DEFENCE_HINTS[s] for s in signals],
        "layers_bypassed": list(getattr(item, "layers_bypassed", []) or []),
        "layer_labels": [
            LAYER_LABELS.get(layer, layer)
            for layer in (getattr(item, "layers_bypassed", []) or [])
        ],
        "response_excerpt": _truncate(response),
        "root_cause": getattr(item, "root_cause", None),
        "recommended_fix": getattr(item, "recommended_fix", None),
        "defense_update": getattr(item, "defense_update", None),
        "retest_result": getattr(item, "retest_result", None),
        "retest_at": getattr(item, "retest_at", None),
        "analysis_at": getattr(item, "analysis_at", None),
    }


def excerpt_response_for_blue_team(response: Optional[str], limit: int = 600) -> str:
    """Return the model's actual response (truncated) as failure evidence.

    The blue team must be able to judge the bypass from the model's own words,
    so this deliberately does not mask content. The payload text stays masked
    elsewhere; only the model output is surfaced.
    """
    return _truncate(response, limit)
