"""Blue-team sandbox repair view (Streamlit fallback)."""

import streamlit as st

from ..core.timeutil import display_local
from ..infrastructure.sandbox_health import REPAIR_ACTIONS, check_health, run_repair

DESTRUCTIVE = {"recreate_sandbox", "quarantine_evidence", "reset_runtime"}


def render() -> None:
    st.header("🧰 Sandbox Repair")
    st.caption(
        "Inspect isolation layers and manually repair sandbox damage. Every action is "
        "written to the tamper-evident audit chain."
    )

    health = check_health()
    if health["status"] == "healthy":
        st.success(f"✅ Isolation intact · health score {health['score']}/100")
    elif health["status"] == "critical":
        st.error(f"🚨 Damage detected · health score {health['score']}/100")
    else:
        st.warning(f"⚠️ Degraded posture · health score {health['score']}/100")
    st.caption(f"Checked {display_local(health['timestamp'])}")

    rows = [
        {
            "Layer": layer["name"],
            "Status": layer["status"],
            "Detail": layer["detail"],
            "Recommendation": layer["recommendation"],
        }
        for layer in health["layers"]
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Manual repair actions")
    label = st.selectbox(
        "Repair action",
        list(REPAIR_ACTIONS),
        format_func=lambda key: f"{key} — {REPAIR_ACTIONS[key]}",
    )
    note = st.text_area("Operator note", placeholder="Why is this repair needed?")
    confirm = False
    if label in DESTRUCTIVE:
        st.warning("This action is destructive. A backup is written to data/runtime/quarantine.")
        confirm = st.checkbox("I understand and want to proceed")

    if st.button("Run repair", type="primary"):
        if label in DESTRUCTIVE and not confirm:
            st.error("Confirm the destructive action first.")
        else:
            with st.spinner("Running repair…"):
                result = run_repair(label, confirm=confirm, note=note)
            if result["ok"]:
                st.success(result["message"])
            else:
                st.error(result["message"])
            st.rerun()
