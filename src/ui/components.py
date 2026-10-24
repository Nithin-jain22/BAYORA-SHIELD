"""Shared UI helpers: theme, status pills and layer-trace rendering."""

import streamlit as st

STATUS_STYLES = {
    "new": ("NEW", "#8b5cf6", "rgba(139,92,246,0.16)"),
    "analyzed": ("ANALYZED", "#3b82f6", "rgba(59,130,246,0.16)"),
    "fix_applied": ("FIX APPLIED", "#f59e0b", "rgba(245,158,11,0.16)"),
    "retested_fixed": ("FIXED", "#10b981", "rgba(16,185,129,0.18)"),
    "retested_vulnerable": ("STILL VULNERABLE", "#ef4444", "rgba(239,68,68,0.18)"),
    "retested_inconclusive": ("INCONCLUSIVE", "#f59e0b", "rgba(245,158,11,0.16)"),
}

OUTCOME_STYLES = {
    "blocked": ("BLOCKED", "#38bdf8"),
    "filtered": ("FILTERED", "#a78bfa"),
    "refused": ("REFUSED", "#10b981"),
    "complied": ("BYPASSED", "#ef4444"),
    "bypassed": ("BYPASSED", "#ef4444"),
    "uncertain": ("REVIEW", "#f59e0b"),
    "empty": ("EMPTY", "#94a3b8"),
    "safe_completion": ("NO SIGNAL", "#94a3b8"),
    "error": ("ERROR", "#f97316"),
}


def inject_theme() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.6rem; padding-bottom: 6rem; }
        .bs-brand { font-size: 1.35rem; font-weight: 800; letter-spacing: .02em; }
        .bs-brand span { color: #10b981; }
        .bs-tagline { color: #94a3b8; font-size: .78rem; margin-top: -.3rem; }
        .bs-pill {
            display: inline-block; padding: 2px 10px; border-radius: 999px;
            font-size: .72rem; font-weight: 700; letter-spacing: .04em;
            border: 1px solid currentColor;
        }
        .bs-signal {
            display: inline-block; padding: 2px 9px; margin: 2px 4px 2px 0;
            border-radius: 999px; font-size: .72rem; font-weight: 600;
            background: rgba(148,163,184,.16); border: 1px solid rgba(148,163,184,.35);
        }
        .bs-card-title { font-weight: 700; font-size: 1rem; }
        .bs-hash { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .75rem; color: #94a3b8; }
        .bs-step { color: #94a3b8; font-size: .78rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
        .bs-verdict { padding: .7rem .9rem; border-radius: .6rem; font-weight: 600; }
        .bs-verdict.ok { background: rgba(16,185,129,.14); border: 1px solid rgba(16,185,129,.45); }
        .bs-verdict.bad { background: rgba(239,68,68,.14); border: 1px solid rgba(239,68,68,.45); }
        .bs-verdict.warn { background: rgba(245,158,11,.14); border: 1px solid rgba(245,158,11,.45); }
        .bs-muted { color: #94a3b8; font-size: .82rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def pill(text: str, color: str = "#94a3b8", background: str = "rgba(148,163,184,.14)") -> str:
    return (
        f'<span class="bs-pill" style="color:{color};background:{background};'
        f'border-color:{color}55;">{text}</span>'
    )


def status_pill(status: str) -> str:
    label, color, background = STATUS_STYLES.get(
        status, (status.upper(), "#94a3b8", "rgba(148,163,184,.14)")
    )
    return pill(label, color, background)


def result_pill(blocked: bool) -> str:
    if blocked:
        return pill("DEFENDED", "#10b981", "rgba(16,185,129,.16)")
    return pill("BYPASSED", "#ef4444", "rgba(239,68,68,.16)")


def outcome_pill(outcome: str) -> str:
    label, color = OUTCOME_STYLES.get(outcome, (str(outcome).upper(), "#94a3b8"))
    return pill(label, color, f"{color}22")


def signal_chips(labels: list[str]) -> str:
    if not labels:
        return '<span class="bs-muted">No structural signals detected</span>'
    return "".join(f'<span class="bs-signal">{label}</span>' for label in labels)


OUTCOME_ICONS = {
    "blocked": "🛡️",
    "allowed": "✅",
    "filtered": "🚫",
    "clean": "✅",
    "refused": "🙅",
    "bypassed": "🚨",
    "uncertain": "❓",
    "error": "⚠️",
}


def render_layer_trace(trace: list[dict]) -> None:
    if not trace:
        st.caption("No layer trace available.")
        return
    for step in trace:
        icon = OUTCOME_ICONS.get(step.get("outcome"), "•")
        st.markdown(
            f"{icon} **L{step.get('layer')} · {step.get('name')}** — "
            f"`{step.get('outcome')}`  \n"
            f"<span class='bs-muted'>{step.get('detail', '')}</span>",
            unsafe_allow_html=True,
        )


def section_label(text: str) -> None:
    st.markdown(f"<div class='bs-step'>{text}</div>", unsafe_allow_html=True)


def verdict_banner(kind: str, message: str) -> None:
    st.markdown(
        f"<div class='bs-verdict {kind}'>{message}</div>",
        unsafe_allow_html=True,
    )
