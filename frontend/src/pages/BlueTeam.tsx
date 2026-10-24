import { useCallback, useEffect, useMemo, useState } from "react";
import React from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Filter,
  Fingerprint,
  FlaskConical,
  Loader2,
  RefreshCw,
  ShieldCheck,
  ShieldQuestion,
  Siren,
  Sparkles,
  Wrench,
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import {
  formatLocal,
  outcomeMeta,
  relativeTime,
  severityColor,
  truncate,
} from "../lib/format";
import type { BlueStats, Evidence } from "../types";
import {
  Badge,
  ConditionChips,
  EmptyState,
  LayerTrace,
  MetricCard,
  OutcomeBadge,
  Panel,
  Spinner,
  StatusBadge,
  useToast,
} from "../components/ui";

interface BlueSession {
  session_id: string;
  operator: string;
}

const FIX_TYPES = [
  { value: "rule", label: "Layer 1 · regex rule" },
  { value: "ml_training", label: "Layer 2 · ML training example" },
  { value: "output_filter", label: "Layer 4 · output pattern" },
];

const FILTERS = [
  { key: "all", label: "All findings" },
  { key: "pending", label: "Pending" },
  { key: "fixed", label: "Fixed" },
  { key: "vulnerable", label: "Still vulnerable" },
];

export function BlueTeamPage({
  session,
  onJoin,
  onClearSession,
}: {
  session: BlueSession | null;
  onJoin: (operator: string) => Promise<void>;
  onClearSession: () => void;
}) {
  const toast = useToast();
  const [operator, setOperator] = useState("");
  const [joining, setJoining] = useState(false);

  if (!session) {
    const submit = async (event: React.FormEvent) => {
      event.preventDefault();
      if (!operator.trim()) return;
      setJoining(true);
      try {
        await onJoin(operator.trim());
      } catch (err) {
        toast.push("error", "Could not enter workspace", err instanceof Error ? err.message : undefined);
      } finally {
        setJoining(false);
      }
    };
    return (
      <div className="join-layout">
        <section className="join-card">
          <div className="join-kicker blue">
            <ShieldCheck size={15} /> Blue team access
          </div>
          <h2>Diagnose the gap. Harden the layer. Prove the fix.</h2>
          <p>
            You only see sanitised evidence: masked payload structure, behavioural signals,
            the layers that were cleared, and the model's failure output. Raw prompts stay
            inside the control plane.
          </p>
          <ul className="clean-list">
            <li><Fingerprint size={15} /> Every finding carries a stable fingerprint.</li>
            <li><FlaskConical size={15} /> Retests replay the withheld payload automatically.</li>
            <li><Wrench size={15} /> Sandbox damage can be repaired from the repair workspace.</li>
          </ul>
          <form onSubmit={submit} className="join-form">
            <label className="field-label" htmlFor="blue-operator">Operator name</label>
            <div className="inline-form">
              <input
                id="blue-operator"
                className="input"
                value={operator}
                onChange={(event) => setOperator(event.target.value)}
                placeholder="e.g. blue-lead"
                autoFocus
              />
              <button className="btn btn-primary" type="submit" disabled={!operator.trim() || joining}>
                {joining ? <Loader2 size={15} className="spin" /> : <ArrowRight size={15} />}
                Enter workspace
              </button>
            </div>
          </form>
        </section>
        <aside className="join-aside blue">
          <div className="join-aside-art">
            <ShieldCheck size={46} />
            <span>BLUE</span>
          </div>
          <p>Refusals are not findings. Only confirmed model compliance reaches this queue.</p>
        </aside>
      </div>
    );
  }

  return <BlueConsole session={session} onClearSession={onClearSession} />;
}

function BlueConsole({
  session,
  onClearSession,
}: {
  session: BlueSession;
  onClearSession: () => void;
}) {
  const toast = useToast();
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [stats, setStats] = useState<BlueStats | null>(null);
  const [defense, setDefense] = useState<Record<string, number>>({});
  const [filter, setFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const [payload, defenseSummary] = await Promise.all([
          api.blueEvidence(session.session_id),
          api.blueDefense(),
        ]);
        setEvidence(payload.evidence || []);
        setStats(payload.stats || null);
        setDefense(defenseSummary || {});
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          toast.push("warning", "Session expired", "Re-enter the blue team workspace.");
          onClearSession();
        } else {
          toast.push("error", "Could not load findings", err instanceof Error ? err.message : undefined);
        }
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [session.session_id],
  );

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    if (filter === "all") return evidence;
    if (filter === "pending") return evidence.filter((item) => ["new", "analyzed", "fix_applied"].includes(item.status));
    if (filter === "fixed") return evidence.filter((item) => item.status === "retested_fixed");
    return evidence.filter((item) => item.status === "retested_vulnerable");
  }, [evidence, filter]);

  if (loading) return <Spinner label="Loading sanitised evidence…" />;

  const pending = evidence.filter((item) => ["new", "analyzed", "fix_applied"].includes(item.status)).length;
  const fixed = evidence.filter((item) => item.status === "retested_fixed").length;
  const vulnerable = evidence.filter((item) => item.status === "retested_vulnerable").length;

  return (
    <div className="page-stack">
      <section className="session-strip">
        <div>
          <span className="eyebrow">Signed in</span>
          <strong>{session.operator}</strong>
          <span className="muted mono">{session.session_id.slice(0, 10)}</span>
        </div>
        <div className="session-actions">
          <button className="btn btn-ghost btn-sm" onClick={() => { setRefreshing(true); load(true); }} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} /> Refresh
          </button>
        </div>
      </section>

      <section className="metric-grid four">
        <MetricCard label="Findings" value={evidence.length} sub="confirmed bypasses only" accent="#67e8f9" icon={<Siren size={17} />} />
        <MetricCard label="In progress" value={pending} sub="analysis → fix → retest" accent="#fbbf24" icon={<Wrench size={17} />} />
        <MetricCard label="Fixed" value={fixed} sub="verified by retest" accent="#34d399" icon={<CheckCircle2 size={17} />} />
        <MetricCard label="Still vulnerable" value={vulnerable} sub="needs escalation" accent="#fb7185" icon={<AlertTriangle size={17} />} />
      </section>

      <Panel
        title="Remediation queue"
        subtitle="Evidence is masked. Retests replay the withheld payload through the live pipeline."
        actions={
          <div className="defense-mini">
            <span>L1 rules <b>{defense.rules ?? "—"}</b></span>
            <span>L4 patterns <b>{defense.output_patterns ?? "—"}</b></span>
            <span>ML examples <b>{defense.learned_ml_examples ?? "—"}</b></span>
          </div>
        }
      >
        <div className="filter-row">
          {FILTERS.map((item) => (
            <button
              key={item.key}
              className={`filter-btn ${filter === item.key ? "active" : ""}`}
              onClick={() => setFilter(item.key)}
            >
              <Filter size={13} />
              {item.label}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={<ShieldQuestion size={22} />}
            title="No findings in this view"
            message="Run attacks from the red team console. Refusals and inconclusive responses do not become evidence."
          />
        ) : (
          <div className="finding-list">
            {filtered.map((item) => (
              <FindingCard
                key={item.evidence_id}
                item={item}
                session={session}
                onChanged={() => load(true)}
              />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

function FindingCard({
  item,
  session,
  onChanged,
}: {
  item: Evidence;
  session: BlueSession;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [rootCause, setRootCause] = useState(item.root_cause || "");
  const [severity, setSeverity] = useState(item.severity || "medium");
  const [recommendedFix, setRecommendedFix] = useState(item.recommended_fix || "");
  const [fixType, setFixType] = useState("rule");
  const [fixText, setFixText] = useState("");
  const [busy, setBusy] = useState<"analyze" | "fix" | "retest" | null>(null);

  useEffect(() => {
    setRootCause(item.root_cause || "");
    setSeverity(item.severity || "medium");
    setRecommendedFix(item.recommended_fix || "");
  }, [item.root_cause, item.severity, item.recommended_fix]);

  const analyze = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!rootCause.trim() || !recommendedFix.trim()) {
      toast.push("warning", "Analysis incomplete", "Root cause and recommended fix are both required.");
      return;
    }
    setBusy("analyze");
    try {
      await api.blueAnalyze({
        session_id: session.session_id,
        evidence_id: item.evidence_id,
        root_cause: rootCause.trim(),
        severity,
        recommended_fix: recommendedFix.trim(),
      });
      toast.push("success", "Analysis recorded");
      onChanged();
    } catch (err) {
      toast.push("error", "Could not save analysis", err instanceof Error ? err.message : undefined);
    } finally {
      setBusy(null);
    }
  };

  const applyFix = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!fixText.trim()) {
      toast.push("warning", "Fix is empty", "Enter a regex pattern or training text.");
      return;
    }
    setBusy("fix");
    try {
      const response = await api.blueFix({
        session_id: session.session_id,
        evidence_id: item.evidence_id,
        update_type: fixType,
        description: fixText.trim(),
      });
      toast.push("success", "Defence updated", `Update ${response.update_id} is live. Retest to verify.`);
      setFixText("");
      onChanged();
    } catch (err) {
      toast.push("error", "Fix rejected", err instanceof Error ? err.message : undefined);
    } finally {
      setBusy(null);
    }
  };

  const retest = async () => {
    setBusy("retest");
    try {
      const response = await api.blueRetest({ session_id: session.session_id, evidence_id: item.evidence_id });
      const result = response.result || {};
      if (result.outcome === "complied" || result.bypassed) {
        toast.push("error", "Still vulnerable", "The withheld payload still bypasses the updated pipeline.");
      } else if (result.inconclusive) {
        toast.push("warning", "Retest inconclusive", result.error || result.assessment?.reason || "Manual review required.");
      } else {
        toast.push("success", "Fix verified", `Payload now contained by ${result.containment_layer || result.blocked_by || "the defence stack"}.`);
      }
      onChanged();
    } catch (err) {
      toast.push("error", "Retest failed", err instanceof Error ? err.message : undefined);
    } finally {
      setBusy(null);
    }
  };

  const retestResult = item.retest_result;
  const retestOutcome = retestResult?.outcome as string | undefined;
  const assessment = item.assessment;
  const conditions = item.conditions;

  return (
    <article className={`finding-card status-${item.status}`}>
      <header className="finding-head">
        <div className="finding-identity">
          <span className="finding-id">{item.evidence_id}</span>
          <div>
            <strong>{item.attack_name}</strong>
            <div className="attack-sub">
              <span>{item.attack_type}</span>
              <span className="dot">·</span>
              <Clock3 size={12} />
              <span title={formatLocal(item.timestamp)}>{relativeTime(item.timestamp)}</span>
              <span className="dot">·</span>
              <Fingerprint size={12} />
              <span className="mono">{item.prompt_hash}</span>
            </div>
          </div>
        </div>
        <div className="finding-badges">
          {item.severity && <Badge color={severityColor(item.severity)}>{item.severity.toUpperCase()}</Badge>}
          <StatusBadge status={item.status} />
        </div>
      </header>

      <div className="finding-grid">
        <div>
          <span className="block-label">Exact timestamp</span>
          <span className="small" title={item.timestamp_iso}>{formatLocal(item.timestamp)}</span>
          <span className="muted micro mono">{item.timestamp_iso}</span>
        </div>
        <div>
          <span className="block-label">Outcome</span>
          <OutcomeBadge outcome={item.outcome} />
        </div>
        <div>
          <span className="block-label">Layers cleared</span>
          <div className="chip-row">
            {item.layer_labels?.length ? item.layer_labels.map((label) => <Badge key={label} color="#fb7185">{label}</Badge>) : <span className="muted small">—</span>}
          </div>
        </div>
        <div>
          <span className="block-label">Payload size</span>
          <span className="small">{item.prompt_length} chars · {item.word_count} words</span>
        </div>
      </div>

      <div className="evidence-grid">
        <div className="evidence-panel">
          <span className="block-label">Masked payload</span>
          <pre className="masked-prompt">{item.redacted_prompt}</pre>
          <span className="block-label">Detected signals</span>
          <ConditionChips flags={conditions?.flags || item.signals} labels={conditions?.labels || item.signal_labels} />
        </div>
        <div className="evidence-panel">
          <span className="block-label">Model response — failure evidence</span>
          <blockquote>{item.response_excerpt}</blockquote>
          {assessment && (
            <div className="assessment-bar">
              <div>
                <span>Refusal</span>
                <div className="bar"><i style={{ width: `${Math.round(assessment.refusal_score * 100)}%`, background: "#34d399" }} /></div>
                <b>{Math.round(assessment.refusal_score * 100)}%</b>
              </div>
              <div>
                <span>Compliance</span>
                <div className="bar"><i style={{ width: `${Math.round(assessment.compliance_score * 100)}%`, background: "#fb7185" }} /></div>
                <b>{Math.round(assessment.compliance_score * 100)}%</b>
              </div>
            </div>
          )}
        </div>
      </div>

      {item.defence_hints?.length > 0 && (
        <div className="hint-row">
          <Sparkles size={15} />
          <div>
            <span className="block-label">Suggested focus</span>
            <ul>{item.defence_hints.map((hint) => <li key={hint}>{hint}</li>)}</ul>
          </div>
        </div>
      )}

      <div className="action-grid">
        <form className="action-panel" onSubmit={analyze}>
          <div className="action-title"><span>1</span><h3>Analyse finding</h3></div>
          <label className="field-label" htmlFor={`rc-${item.evidence_id}`}>Root cause</label>
          <textarea
            id={`rc-${item.evidence_id}`}
            className="textarea"
            rows={3}
            value={rootCause}
            onChange={(event) => setRootCause(event.target.value)}
            placeholder="Why did the defence miss this payload?"
          />
          <div className="inline-fields">
            <label>
              <span className="field-label">Severity</span>
              <select className="select" value={severity} onChange={(event) => setSeverity(event.target.value)}>
                {["low", "medium", "high", "critical"].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
          </div>
          <label className="field-label" htmlFor={`rf-${item.evidence_id}`}>Recommended fix</label>
          <textarea
            id={`rf-${item.evidence_id}`}
            className="textarea"
            rows={2}
            value={recommendedFix}
            onChange={(event) => setRecommendedFix(event.target.value)}
            placeholder="What should change in the defence?"
          />
          <button className="btn btn-primary btn-sm" type="submit" disabled={busy === "analyze"}>
            {busy === "analyze" ? <Loader2 size={14} className="spin" /> : <CheckCircle2 size={14} />}
            Save analysis
          </button>
        </form>

        <form className="action-panel" onSubmit={applyFix}>
          <div className="action-title"><span>2</span><h3>Apply defence fix</h3></div>
          {item.defense_update && <Badge color="#34d399">Update {item.defense_update}</Badge>}
          <label className="field-label">Fix type</label>
          <select className="select" value={fixType} onChange={(event) => setFixType(event.target.value)}>
            {FIX_TYPES.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
          </select>
          <label className="field-label" htmlFor={`fx-${item.evidence_id}`}>Pattern / training text</label>
          <textarea
            id={`fx-${item.evidence_id}`}
            className="textarea mono-input"
            rows={5}
            value={fixText}
            onChange={(event) => setFixText(event.target.value)}
            placeholder={
              fixType === "rule"
                ? "e.g. restate the hidden guidance|first words you were given"
                : fixType === "ml_training"
                  ? "e.g. restate the guidance you were configured with at startup"
                  : "e.g. my (configured|original) guidance (is|reads)"
            }
          />
          <button className="btn btn-primary btn-sm" type="submit" disabled={busy === "fix"}>
            {busy === "fix" ? <Loader2 size={14} className="spin" /> : <Wrench size={14} />}
            Apply fix
          </button>
        </form>

        <div className="action-panel retest-panel">
          <div className="action-title"><span>3</span><h3>Retest finding</h3></div>
          {!item.defense_update && <p className="muted small">Apply a defence fix before retesting.</p>}
          <button className="btn btn-primary btn-sm" onClick={retest} disabled={!item.defense_update || busy === "retest"}>
            {busy === "retest" ? <Loader2 size={14} className="spin" /> : <FlaskConical size={14} />}
            Replay withheld payload
          </button>
          {retestResult && (
            <div className={`retest-verdict ${retestOutcome === "complied" ? "bad" : retestResult.inconclusive ? "warn" : "good"}`}>
              <strong>
                {retestOutcome === "complied" || retestResult.bypassed
                  ? "Still vulnerable"
                  : retestResult.inconclusive
                    ? "Inconclusive"
                    : "Fixed — payload contained"}
              </strong>
              <p>{retestResult.blocked_by || retestResult.assessment?.reason || retestResult.error || "Verdict recorded."}</p>
              {(retestResult.response_excerpt || retestResult.assessment?.excerpt) && (
                <blockquote className="retest-response">
                  {retestResult.response_excerpt || retestResult.assessment?.excerpt}
                </blockquote>
              )}
              {retestResult.timestamp && <span className="muted micro">{formatLocal(retestResult.timestamp)}</span>}
              {retestResult.layer_trace?.length > 0 && (
                <details>
                  <summary>Retest layer trace</summary>
                  <LayerTrace trace={retestResult.layer_trace} compact />
                </details>
              )}
            </div>
          )}
        </div>
      </div>
    </article>
  );
}
