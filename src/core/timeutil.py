"""Timezone-aware timestamp helpers.

Every persisted record keeps an epoch float (``timestamp``) *and* a canonical
UTC ISO-8601 string with an explicit offset.  The UI is responsible for
rendering that epoch in the operator's local timezone, which removes the
"timestamp is wrong" class of bugs caused by mixing ``gmtime`` strings with
local wall-clock expectations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now().astimezone()


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def local_now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def to_iso(timestamp: Optional[float]) -> Optional[str]:
    """Convert an epoch float to an ISO-8601 UTC string with offset."""
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat(
            timespec="seconds"
        )
    except (TypeError, ValueError, OSError):
        return None


def to_local_iso(timestamp: Optional[float]) -> Optional[str]:
    """Convert an epoch float to an ISO-8601 string in the local timezone."""
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(
            timespec="seconds"
        )
    except (TypeError, ValueError, OSError):
        return None


def parse_timestamp(value) -> Optional[float]:
    """Best-effort parse of epoch numbers or ISO strings (naive treated as UTC)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        normalised = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def display_local(timestamp) -> str:
    """Human-friendly local timestamp used by the fallback Streamlit views."""
    epoch = parse_timestamp(timestamp)
    if epoch is None:
        return "—"
    return datetime.fromtimestamp(epoch).astimezone().strftime("%d %b %Y · %H:%M:%S %Z")
