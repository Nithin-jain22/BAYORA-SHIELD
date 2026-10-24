"""Security audit view: tamper-evident audit log explorer."""

import json

import pandas as pd
import streamlit as st

from ..infrastructure.security_plane import EventType, get_events, verify_chain
from ..core.timeutil import display_local, parse_timestamp


def render() -> None:
    st.header("🔒 Security Audit")
    st.caption("Append-only, SHA-256 hash-chained record of every security-relevant event.")

    valid, broken = verify_chain()
    if valid:
        st.success("✅ Audit log chain is intact — no tampering detected.")
    else:
        st.error(f"🚨 Audit log chain is BROKEN at line {broken} — possible tampering!")

    st.markdown("---")

    event_types = ["all"] + [event.value for event in EventType]
    col1, col2 = st.columns(2)
    event_filter = col1.selectbox("Filter by event type", event_types)
    actor_filter = col2.selectbox("Filter by actor", ["all", "red_team", "blue_team", "system"])

    kwargs = {}
    if event_filter != "all":
        kwargs["event_type"] = EventType(event_filter)
    if actor_filter != "all":
        kwargs["actor"] = actor_filter

    events = get_events(**kwargs)
    st.markdown(f"**{len(events)} events found**")

    if not events:
        st.caption("No events match the selected filters.")
        return

    df = pd.DataFrame([
        {
            "Local time": display_local(event.get("timestamp")),
            "UTC": event["timestamp_iso"],
            "Event": event["event_type"],
            "Actor": event["actor"],
            "Session": (event.get("session_id") or "—")[:8],
            "Details": json.dumps(event["details"], default=str)[:70] + "…",
            "Hash": event["hash"][:12] + "…",
        }
        for event in reversed(events[-150:])
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)
    with st.expander("Latest event detail"):
        st.json(events[-1])
