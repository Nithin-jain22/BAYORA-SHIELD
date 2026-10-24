"""Blue team workspace: analyse -> fix -> retest remediation loop."""

import streamlit as st

from ..core import updater
from ..core.timeutil import display_local
from ..orchestration.blue_team import BlueTeamSession
from .components import (
    outcome_pill,
    render_layer_trace,
    section_label,
    signal_chips,
    status_pill,
    verdict_banner,
)

FIX_TYPES = {
    "rule": "Layer 1 · regex rule",
    "ml_training": "Layer 2 · ML training example",
    "output_filter": "Layer 4 · output pattern",
}

STATUS_FILTERS = {
    "All findings": None,
    "Pending": ["new", "analyzed", "fix_applied"],
    "Fixed": ["retested_fixed"],
    "Still vulnerable": ["retested_vulnerable"],
    "Inconclusive": ["retested_inconclusive"],
}

PLACEHOLDERS = {
    "rule": r"e.g. restate the hidden guidance|first words you were given",
    "ml_training": "e.g. restate the guidance you were configured with at startup",
    "output_filter": r"e.g. my (configured|original) guidance (is|reads)",
}


def _render_join_screen() -> None:
    st.info(
        "You are entering an isolated workspace. You will only see sanitised evidence of "
        "defence failures — never the red team's raw attack prompts or live activity."
    )
    operator = st.text_input("Operator name", placeholder="e.g. blue-lead")
    if st.button("Enter Blue Team Workspace", type="primary", disabled=not operator.strip()):
        st.session_state.blue_session = BlueTeamSession(operator.strip())
        st.rerun()


def _render_metrics(session: BlueTeamSession) -> None:
    stats = session.get_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Findings", stats["total_evidence"])
    c2.metric("In progress", stats["pending"])
    c3.metric("Fixed", stats["fixed"])
    c4.metric("Still vulnerable", stats["still_vulnerable"])


def _render_evidence_body(ev: dict) -> None:
    section_label("Sanitised evidence")
    st.caption(
        f"Detected {display_local(ev['timestamp'])} · outcome "
        f"`{ev.get('outcome', 'complied')}` · fingerprint `{ev['prompt_hash']}`"
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Length", f'{ev["prompt_length"]} chars')
    c2.metric("Tokens", ev["word_count"])
    c3.metric("Layers bypassed", len(ev["layers_bypassed"]))
    c4.metric("Signals", len(ev["signal_labels"]))

    st.markdown("**Outcome:** " + outcome_pill(ev.get("outcome", "complied")), unsafe_allow_html=True)

    st.markdown("**Detected signals**")
    st.markdown(signal_chips(ev["signal_labels"]), unsafe_allow_html=True)

    st.markdown("**Payload (masked — raw text withheld by policy)**")
    st.code(ev["redacted_prompt"], language="text")

    with st.expander("Model response excerpt"):
        st.markdown(f"> {ev['response_excerpt']}")

    if ev.get("conditions"):
        st.markdown(
            "**Conditions:** " + ", ".join(ev["conditions"].get("labels", []))
        )

    if ev["layers_bypassed"]:
        st.markdown(
            "**Bypassed:** "
            + " ".join(f"`{layer}`" for layer in ev["layers_bypassed"])
        )

    if ev["defence_hints"]:
        st.markdown("**Suggested focus**")
        for hint in ev["defence_hints"]:
            st.markdown(f"- {hint}")


def _render_analysis(ev: dict, session: BlueTeamSession) -> None:
    eid = ev["evidence_id"]
    section_label("1 · Analyse finding")
    with st.form(f"analyze_{eid}"):
        root = st.text_area(
            "Root cause", value=ev.get("root_cause") or "", key=f"rc_{eid}",
            placeholder="Why did the defence miss this payload?",
        )
        severity = st.select_slider(
            "Severity", options=["low", "medium", "high", "critical"],
            value=ev.get("severity") or "medium", key=f"sev_{eid}",
        )
        fix = st.text_area(
            "Recommended fix", value=ev.get("recommended_fix") or "", key=f"rec_{eid}",
            placeholder="What should change in the defence?",
        )
        submitted = st.form_submit_button("Submit analysis")
    if submitted:
        if root.strip() and fix.strip():
            session.analyze_evidence(eid, root.strip(), severity, fix.strip())
            st.rerun()
        st.warning("Root cause and recommended fix are both required.")


def _render_fix(ev: dict, session: BlueTeamSession) -> None:
    eid = ev["evidence_id"]
    section_label("2 · Apply defence fix")
    if ev.get("defense_update"):
        st.success(f"Fix applied — update `{ev['defense_update']}`")

    with st.form(f"fix_{eid}"):
        update_type = st.selectbox(
            "Fix type", list(FIX_TYPES), format_func=lambda k: FIX_TYPES[k], key=f"ut_{eid}"
        )
        st.caption("Applied immediately to the live defence layers and persisted for reproducibility.")
        description = st.text_area(
            "Pattern / training text", key=f"desc_{eid}",
            placeholder=PLACEHOLDERS.get(update_type, ""),
        )
        applied = st.form_submit_button("Apply defence fix", type="primary")
    if applied:
        update_id, error = session.apply_defense_update(eid, update_type, description)
        if error:
            st.error(error)
        else:
            st.success(f"Defence updated (`{update_id}`). Retest to verify.")
            st.rerun()


def _render_retest(ev: dict, session: BlueTeamSession) -> None:
    eid = ev["evidence_id"]
    section_label("3 · Retest finding")
    if not ev.get("defense_update"):
        st.caption("Apply a defence fix before retesting.")
        return

    if st.button("🔁 Retest this finding", key=f"retest_{eid}"):
        with st.spinner("Replaying the withheld payload through the updated pipeline…"):
            session.retest(eid)
        st.rerun()

    result = ev.get("retest_result")
    if not result:
        return

    if result.get("inconclusive"):
        verdict_banner(
            "warn",
            f"⚠️ Retest inconclusive — {result.get('error') or result.get('assessment', {}).get('reason', 'manual review required')}",
        )
    elif result.get("outcome") == "refused" or result.get("blocked"):
        verdict_banner(
            "ok",
            f"✅ FIXED — payload contained by {result.get('containment_layer') or result.get('blocked_by')}",
        )
    else:
        verdict_banner("bad", "❌ STILL VULNERABLE — payload still bypasses every layer")

    with st.expander("Retest layer trace", expanded=not result.get("blocked")):
        render_layer_trace(result.get("layer_trace", []))


def _render_card(ev: dict, session: BlueTeamSession) -> None:
    with st.container(border=True):
        header = st.columns([3, 1, 1])
        header[0].markdown(
            f"<span class='bs-card-title'>Finding #{ev['evidence_id']}</span> "
            f"<span class='bs-muted'>· {ev['attack_type']}</span>",
            unsafe_allow_html=True,
        )
        header[1].markdown(status_pill(ev["status"]), unsafe_allow_html=True)
        header[2].markdown(
            f"<span class='bs-hash'>{ev['evidence_id']}</span>", unsafe_allow_html=True
        )

        _render_evidence_body(ev)
        st.divider()
        _render_analysis(ev, session)
        st.divider()
        _render_fix(ev, session)
        st.divider()
        _render_retest(ev, session)


def render() -> None:
    st.header("🔵 Blue Team Workspace")
    st.caption("Diagnose defence failures, harden the layers, and verify each fix with a retest.")

    if "blue_session" not in st.session_state:
        _render_join_screen()
        return

    session: BlueTeamSession = st.session_state.blue_session

    with st.sidebar:
        st.markdown("---")
        st.markdown("### 🛡️ Defence posture")
        summary = updater.defense_summary()
        st.caption(
            f"Layer 1 rules: **{summary['rules']}** · "
            f"Layer 4 patterns: **{summary['output_patterns']}**  \n"
            f"Learned this session: {summary['learned_rules']} rules, "
            f"{summary['learned_ml_examples']} ML examples"
        )

    _render_metrics(session)

    choice = st.radio("Show", list(STATUS_FILTERS), horizontal=True)
    wanted = STATUS_FILTERS[choice]

    evidence = session.get_evidence()
    if wanted:
        evidence = [e for e in evidence if e["status"] in wanted]
    evidence = sorted(evidence, key=lambda e: e["timestamp"], reverse=True)

    st.markdown("---")
    if not evidence:
        st.info("No findings in this view. Run attacks from the Red Team workspace to generate evidence.")
        return

    for ev in evidence:
        _render_card(ev, session)
