"""Bayora-Shield — Streamlit entry point.

Red team attacks the client LLM, bypasses are released to the blue team as
sanitised evidence, and blue team hardens the defence and retests.

Run with:
    streamlit run app.py
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.core import updater
from src.infrastructure.sandbox import SandboxError, get_sandbox
from src.ui import audit_view, blue_team_view, evaluation_view, red_team_view, repair_view
from src.ui.components import inject_theme

st.set_page_config(
    page_title="Bayora-Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()
updater.apply_persisted_updates()

PAGES = {
    "🔴 Red Team": red_team_view.render,
    "🔵 Blue Team": blue_team_view.render,
    "🧰 Sandbox Repair": repair_view.render,
    "📊 Evaluation": evaluation_view.render,
    "🔒 Security Audit": audit_view.render,
}


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown(
            "<div class='bs-brand'>BAYORA<span>-SHIELD</span></div>"
            "<div class='bs-tagline'>Secure the environment. Trust the evaluation.</div>",
            unsafe_allow_html=True,
        )
        st.markdown("---")

        sandbox = get_sandbox()
        status = sandbox.status()
        st.markdown("### 🖥️ Sandbox")
        if status["running"]:
            st.success(f"🟢 Running · {str(status['backend']).title()} backend")
            if st.button("Stop sandbox", use_container_width=True):
                sandbox.stop()
                st.rerun()
        else:
            st.error("🔴 Stopped")
            if st.button("Start sandbox", type="primary", use_container_width=True):
                try:
                    with st.spinner("Starting sandbox…"):
                        sandbox.start()
                    st.rerun()
                except SandboxError as exc:
                    st.error(f"Failed to start sandbox: {exc}")

        if not status["docker_available"]:
            st.caption(
                "Docker daemon not detected — using the process sandbox. "
                "No container will appear in `docker ps`."
            )

        with st.expander("Sandbox details"):
            st.json(status)

        st.markdown("---")
        return st.radio("Workspace", list(PAGES))


page = render_sidebar()
PAGES[page]()
