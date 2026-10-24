"""Evaluation plane view: reproducible runs, trends and per-type breakdown."""

import pandas as pd
import streamlit as st

from ..config import MODEL
from ..core.timeutil import display_local, parse_timestamp
from ..orchestration.evaluation_plane import get_evaluation_plane


def _snapshot(plane) -> None:
    session = st.session_state.get("red_session")
    if not session:
        st.caption("Start a red team session to snapshot its results.")
        return
    history = session.get_history()
    if not history:
        st.caption("No attacks in the current session yet.")
        return
    if st.button("📸 Snapshot current red team session", type="primary"):
        results = [
            {
                "attack_type": a.attack_type,
                "blocked": a.blocked,
                "outcome": a.outcome,
            }
            for a in history
        ]
        plane.create_run(
            model=MODEL,
            results=results,
            defense_version="live",
            session_id=session.session_id,
        )
        st.success("Run recorded in the evaluation plane.")
        st.rerun()


def _render_trend(plane) -> None:
    trend = plane.get_trend()
    if not trend:
        st.info("No evaluation runs yet. Snapshot a session above to record one.")
        return
    st.subheader("Block rate trend")
    df = pd.DataFrame(trend)
    df["timestamp"] = pd.to_datetime(
        df["timestamp"].map(lambda value: parse_timestamp(value)), unit="s", utc=True
    )
    df = df.set_index("timestamp")[["block_rate", "bypass_rate"]]
    st.area_chart(df, color=["#10b981", "#ef4444"], height=300)
    st.dataframe(
        pd.DataFrame(trend).assign(
            local_time=lambda frame: frame["timestamp"].map(
                lambda value: display_local(parse_timestamp(value))
            )
        ),
        use_container_width=True,
        hide_index=True,
    )


def _render_runs(plane) -> None:
    st.subheader("Recorded runs")
    if not plane.runs:
        st.caption("No runs recorded yet.")
        return
    runs_df = pd.DataFrame([
        {
            "Run ID": r.run_id,
            "Local time": display_local(parse_timestamp(r.timestamp)),
            "UTC": r.timestamp,
            "Model": r.model,
            "Total": r.total_attacks,
            "Defended": r.blocked,
            "Refused": r.refused,
            "Bypassed": r.bypassed,
            "Inconclusive": r.inconclusive,
            "Defence rate": f"{r.block_rate:.0%}",
            "Defence version": r.defense_version,
        }
        for r in plane.runs
    ])
    st.dataframe(runs_df, use_container_width=True, hide_index=True)


def _render_latest_breakdown(plane) -> None:
    if not plane.runs:
        return
    latest = sorted(plane.runs, key=lambda r: r.timestamp)[-1]
    st.subheader(f"Latest run breakdown · {latest.run_id}")
    rows = [
        {
            "Attack type": attack_type,
            "Total": counts["total"],
            "Blocked": counts.get("blocked", 0),
            "Refused": counts.get("refused", 0),
            "Bypassed": counts.get("bypassed", 0),
            "Inconclusive": counts.get("inconclusive", 0),
        }
        for attack_type, counts in latest.per_type_breakdown.items()
    ]
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render() -> None:
    st.header("📊 Evaluation Plane")
    st.caption("Security outcomes recorded as reproducible, versioned runs.")

    plane = get_evaluation_plane()
    _snapshot(plane)
    st.markdown("---")
    _render_trend(plane)
    st.markdown("---")
    _render_runs(plane)
    st.markdown("---")
    _render_latest_breakdown(plane)
