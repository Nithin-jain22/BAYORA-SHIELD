"""Layer 5 — continuous defence updates with persistence.

Blue team improvements (new rules, output patterns and ML training examples)
are applied in-memory *and* persisted so a restart keeps the reinforced
defences. This is what makes a later retest reproducible.
"""

import json
import re

from ..config import DEFENSE_STORE_PATH
from . import defense, output_filter
from .ml_classifier import add_training_example

_STORE_VERSION = 1
_APPLIED = False


def _empty_store() -> dict:
    return {"version": _STORE_VERSION, "rules": [], "output_patterns": [], "ml_attacks": [], "ml_safe": []}


def _load_store() -> dict:
    if not DEFENSE_STORE_PATH.exists():
        return _empty_store()
    try:
        with open(DEFENSE_STORE_PATH) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return _empty_store()
    store = _empty_store()
    for key in store:
        if key in data and isinstance(data[key], list):
            store[key] = data[key]
    return store


def _save_store(store: dict) -> None:
    with open(DEFENSE_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)


def _validate_pattern(pattern: str) -> str:
    pattern = (pattern or "").strip()
    if not pattern:
        raise ValueError("Defence pattern cannot be empty")
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc
    return pattern


def _append(store_key: str, value: str) -> None:
    store = _load_store()
    if value not in store[store_key]:
        store[store_key].append(value)
        _save_store(store)


def add_attack_keyword(pattern: str) -> str:
    """Layer 1 — add a regex rule and persist it."""
    pattern = _validate_pattern(pattern)
    if pattern not in defense.BLOCKED_PATTERNS:
        defense.BLOCKED_PATTERNS.append(pattern)
        defense._COMPILED.append(re.compile(pattern, re.IGNORECASE))
        _append("rules", pattern)
    return pattern


def add_output_pattern(pattern: str) -> str:
    """Layer 4 — add a response pattern and persist it."""
    pattern = _validate_pattern(pattern)
    if pattern not in output_filter.SUSPICIOUS_OUTPUT_PATTERNS:
        output_filter.SUSPICIOUS_OUTPUT_PATTERNS.append(pattern)
        output_filter._COMPILED.append(re.compile(pattern, re.IGNORECASE))
        _append("output_patterns", pattern)
    return pattern


def add_ml_attack(prompt: str) -> str:
    """Layer 2 — add an attack example, retrain and persist it."""
    prompt = (prompt or "").strip()
    if not prompt:
        raise ValueError("Training text cannot be empty")
    add_training_example(prompt, is_attack=True)
    _append("ml_attacks", prompt)
    return prompt


def add_ml_safe(prompt: str) -> str:
    """Layer 2 — add a benign example, retrain and persist it."""
    prompt = (prompt or "").strip()
    if not prompt:
        raise ValueError("Training text cannot be empty")
    add_training_example(prompt, is_attack=False)
    _append("ml_safe", prompt)
    return prompt


def apply_persisted_updates() -> dict:
    """Re-apply every stored update. Safe to call more than once."""
    global _APPLIED
    if _APPLIED:
        return {"rules": 0, "output_patterns": 0, "ml_examples": 0}

    store = _load_store()
    applied = {"rules": 0, "output_patterns": 0, "ml_examples": 0}

    for pattern in store["rules"]:
        try:
            pattern = _validate_pattern(pattern)
        except ValueError:
            continue
        if pattern not in defense.BLOCKED_PATTERNS:
            defense.BLOCKED_PATTERNS.append(pattern)
            defense._COMPILED.append(re.compile(pattern, re.IGNORECASE))
            applied["rules"] += 1

    for pattern in store["output_patterns"]:
        try:
            pattern = _validate_pattern(pattern)
        except ValueError:
            continue
        if pattern not in output_filter.SUSPICIOUS_OUTPUT_PATTERNS:
            output_filter.SUSPICIOUS_OUTPUT_PATTERNS.append(pattern)
            output_filter._COMPILED.append(re.compile(pattern, re.IGNORECASE))
            applied["output_patterns"] += 1

    for prompt in store["ml_attacks"]:
        add_training_example(prompt, is_attack=True)
        applied["ml_examples"] += 1
    for prompt in store["ml_safe"]:
        add_training_example(prompt, is_attack=False)
        applied["ml_examples"] += 1

    _APPLIED = True
    return applied


def defense_summary() -> dict:
    store = _load_store()
    return {
        "rules": len(defense.BLOCKED_PATTERNS),
        "output_patterns": len(output_filter.SUSPICIOUS_OUTPUT_PATTERNS),
        "learned_rules": len(store["rules"]),
        "learned_output_patterns": len(store["output_patterns"]),
        "learned_ml_examples": len(store["ml_attacks"]) + len(store["ml_safe"]),
    }


def update_all(new_attack_prompt: str) -> None:
    """Convenience used by the CLI simulator for a newly bypassing attack."""
    add_ml_attack(new_attack_prompt)
