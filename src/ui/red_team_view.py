"""Red team workspace: chat-style attack console."""

import streamlit as st

from ..core.attacks import ATTACKS, ATTACK_TYPES, EVASIVE_ATTACKS
from ..core.tinyfish import harvest_live_jailbreak
from ..core.timeutil import display_local
from ..orchestration.red_team import RedTeamSession
from .components import outcome_pill, render_layer_trace


def _submit(session: RedTeamSession, prompt: str, name: str, attack_type: str) -> None:
    with st.spinner("Running prompt through the defence pipeline and sandboxed model…"):
        session.submit_attack(prompt, name, attack_type)
    st.rerun()


def _render_join_screen() -> None:
    st.info(
        "You are entering an isolated workspace. You can submit adversarial prompts "
        "and observe the model's response. You cannot see blue team defences."
    )
    operator = st.text_input("Operator name", placeholder="e.g. red-lead")
    if st.button("Enter Red Team Workspace", type="primary", disabled=not operator.strip()):
        st.session_state.red_session = RedTeamSession(operator.strip())
        st.rerun()


def _render_metrics(session: RedTeamSession) -> None:
    stats = session.get_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Attacks", stats["total_attacks"])
    c2.metric("Defended", stats["defended"], help="Layer blocks + model refusals")
    c3.metric("Bypassed", stats["bypassed"])
    c4.metric("Bypass rate", f"{stats['bypass_rate']:.0%}")


def _render_examples(session: RedTeamSession) -> None:
    with st.expander("📚 Example attacks — click Run to fire"):
        st.caption("Obvious payloads are usually caught. The evasive set is more likely to reach the model.")
        for group_name, group in (("Obvious", ATTACKS), ("Evasive", EVASIVE_ATTACKS)):
            st.markdown(f"**{group_name}**")
            for attack in group:
                cols = st.columns([5, 1])
                with cols[0]:
                    st.markdown(
                        f"`{attack['type']}` **{attack['name']}**  \n"
                        f"<span class='bs-muted'>{attack['prompt']}</span>",
                        unsafe_allow_html=True,
                    )
                if cols[1].button("Run", key=f"example_{attack['name']}", use_container_width=True):
                    _submit(session, attack["prompt"], attack["name"], attack["type"])

        if st.button("⚡ Run the full evasive set"):
            with st.spinner("Firing evasive attacks…"):
                for attack in EVASIVE_ATTACKS:
                    session.submit_attack(attack["prompt"], attack["name"], attack["type"])
            st.rerun()


def _render_message(attack) -> None:
    with st.chat_message("user"):
        st.markdown(
            f"<span class='bs-muted'>{attack.attack_name} · {attack.attack_type} · "
            f"{display_local(attack.timestamp)}</span>",
            unsafe_allow_html=True,
        )
        st.markdown(attack.prompt)

    avatar = "🚨" if attack.bypassed else "🛡️"
    with st.chat_message("assistant", avatar=avatar):
        title = {
            "refused": "Defended by model alignment (the model refused)",
            "filtered": "Defended by the output filter",
            "blocked": "Defence held",
            "complied": "Confirmed bypass — the model complied",
            "uncertain": "Inconclusive — needs review",
            "error": "Pipeline error",
        }.get(attack.outcome, "No clear verdict")
        st.markdown(
            f"{outcome_pill(attack.outcome)} &nbsp; {title}", unsafe_allow_html=True
        )
        if attack.blocked_by:
            st.caption(attack.blocked_by)
        if attack.llm_response:
            st.markdown(f"> {attack.llm_response}")
        elif not attack.bypassed:
            st.caption("No response returned to the operator.")
        if attack.raw_response and attack.raw_response != attack.llm_response:
            with st.expander("Raw model output"):
                st.code(attack.raw_response, language="text")
        if attack.conditions:
            st.markdown(
                "**Conditions:** " + ", ".join(attack.conditions.get("labels", []))
            )
        if attack.assessment:
            st.caption(
                f"Assessment: {attack.assessment.get('reason')} · refusal "
                f"{attack.assessment.get('refusal_score', 0):.0%} · compliance "
                f"{attack.assessment.get('compliance_score', 0):.0%}"
            )
        if attack.bypassed and attack.evidence_id:
            st.caption(f"Released to blue team as evidence `{attack.evidence_id}`.")
        with st.expander("Defence layer trace"):
            render_layer_trace(attack.layer_trace)



def _render_tinyfish_harvester(session: RedTeamSession) -> None:
    with st.expander("🐟 TinyFish Web Agent — Live Threat Harvester", expanded=True):
        st.caption(
            "Autonomous Web Agent scours live threat intelligence repositories and extracts emerging zero-day jailbreaks."
        )
        col1, col2 = st.columns([4, 1])
        with col1:
            target_url = st.text_input(
                "Target Threat Intelligence URL",
                value="https://github.com/verazuo/jailbreak_llms",
                key="tf_target_url",
            )
        with col2:
            st.write("")
            st.write("")
            harvest_btn = st.button("🎣 Ingest & Run", key="btn_tinyfish_harvest", width="stretch")

        if harvest_btn:
            with st.spinner("TinyFish Web Agent navigating live web and extracting novel payload…"):
                payload = harvest_live_jailbreak(target_url=target_url)
                st.success(f"Harvested: **{payload["name"]}** ({payload.get("source", "Web Agent")})")
                _submit(session, payload["prompt"], payload["name"], payload.get("category", "Zero-Day Jailbreak"))


def render() -> None:
    st.header("🔴 Red Team Workspace")
    st.caption("Attack the client LLM. Every bypass is released to the blue team as sanitised evidence.")

    if "red_session" not in st.session_state:
        _render_join_screen()
        return

    session: RedTeamSession = st.session_state.red_session
    _render_metrics(session)
    _render_examples(session)
    _render_tinyfish_harvester(session)

    with st.sidebar:
        st.markdown("---")
        st.markdown("### 🎯 Attack controls")
        attack_type = st.selectbox("Attack type", ATTACK_TYPES, key="red_attack_type")
        label = st.text_input("Label (optional)", key="red_attack_label", placeholder="name this attack")
        if st.button("🧹 Clear conversation", use_container_width=True):
            session.clear_history()
            st.rerun()

    st.markdown("---")
    st.subheader("Attack conversation")
    history = session.get_history()
    if not history:
        st.caption("No attacks yet. Fire an example above or type a prompt below.")

    for attack in history:
        _render_message(attack)

    prompt = st.chat_input("Type an adversarial prompt and press Enter…")
    if prompt and prompt.strip():
        name = label.strip() or prompt.strip()[:40]
        _submit(session, prompt.strip(), name, attack_type)
