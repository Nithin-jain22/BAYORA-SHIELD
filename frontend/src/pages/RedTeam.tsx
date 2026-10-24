import { useCallback, useEffect, useMemo, useState } from "react";
import React from "react";
import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  Clock3,
  Eraser,
  Fingerprint,
  Loader2,
  Play,
  Search,
  Send,
  ShieldCheck,
  Swords,
  Target,
  Zap,
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import {
  CONDITION_LABELS,
  LAYER_LABELS,
  formatLocal,
  outcomeMeta,
  relativeTime,
} from "../lib/format";
import type { Attack, RedStats } from "../types";
import {
  Badge,
  ConditionChips,
  EmptyState,
  LayerTrace,
  MetricCard,
  OutcomeBadge,
  Panel,
  Spinner,
  useToast,
} from "../components/ui";

interface RedSession {
  session_id: string;
  operator: string;
}

export function RedTeamPage({
  session,
  onJoin,
  onClearSession,
}: {
  session: RedSession | null;
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
          <div className="join-kicker">
            <Swords size={15} /> Red team access
          </div>
          <h2>Attack the model. Never see the defence.</h2>
          <p>
            You get an isolated console with the model's responses and your own history.
            Blue-team analysis, learned rules and raw defence internals stay hidden.
          </p>
          <ul className="clean-list">
            <li><ShieldCheck size={15} /> Every attempt receives a response assessment.</li>
            <li><Fingerprint size={15} /> Confirmed bypasses are fingerprinted for remediation.</li>
            <li><Target size={15} /> Conditions and layer breaks are journaled automatically.</li>
          </ul>
          <form onSubmit={submit} className="join-form">
            <label className="field-label" htmlFor="red-operator">Operator name</label>
            <div className="inline-form">
              <input
                id="red-operator"
                className="input"
                value={operator}
                onChange={(event) => setOperator(event.target.value)}
                placeholder="e.g. red-lead"
                autoFocus
              />
              <button className="btn btn-primary" type="submit" disabled={!operator.trim() || joining}>
                {joining ? <Loader2 size={15} className="spin" /> : <ArrowRight size={15} />}
                Enter workspace
              </button>
            </div>
          </form>
        </section>
        <aside className="join-aside">
          <div className="join-aside-art">
            <Swords size={46} />
            <span>RED</span>
          </div>
          <p>Obvious payloads are normally caught. The evasive set is designed to find the gaps.</p>
        </aside>
      </div>
    );
  }

  return (
    <RedConsole session={session} onClearSession={onClearSession} />
  );
}

function RedConsole({
  session,
  onClearSession,
}: {
  session: RedSession;
  onClearSession: () => void;
}) {
  const toast = useToast();
  const [stats, setStats] = useState<RedStats | null>(null);
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [examples, setExamples] = useState<{ obvious: any[]; evasive: any[]; attack_types: string[] }>({
    obvious: [],
    evasive: [],
    attack_types: [],
  });
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [runningLabel, setRunningLabel] = useState("");
  const [prompt, setPrompt] = useState("");
  const [attackName, setAttackName] = useState("");
  const [attackType, setAttackType] = useState("custom");
  const [showExamples, setShowExamples] = useState(true);

  const load = useCallback(async () => {
    try {
      const [history, ex] = await Promise.all([api.redHistory(session.session_id), api.redExamples()]);
      setAttacks(history.attacks || []);
      setStats(history.stats || null);
      setExamples(ex);
      if (!ex.attack_types?.includes(attackType)) {
        setAttackType(ex.attack_types?.[0] || "custom");
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        toast.push("warning", "Session expired", "Re-enter the red team workspace.");
        onClearSession();
      } else {
        toast.push("error", "Could not load console", err instanceof Error ? err.message : undefined);
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.session_id]);

  useEffect(() => {
    load();
  }, [load]);

  const fire = async (payload: { prompt: string; name: string; type: string }) => {
    if (!payload.prompt.trim() || running) return;
    setRunning(true);
    setRunningLabel(payload.name || "Custom attack");
    try {
      const response = await api.redAttack({
        session_id: session.session_id,
        prompt: payload.prompt.trim(),
        attack_name: payload.name.trim() || "Custom Attack",
        attack_type: payload.type,
      });
      const attack: Attack = response.attack;
      setAttacks((prev) => [...prev, attack]);
      setStats(response.stats);
      if (attack.outcome === "complied" || attack.bypassed) {
        toast.push("warning", "Confirmed bypass", `${attack.attack_name} reached the model and complied. Released as evidence.`);
      } else if (attack.outcome === "refused") {
        toast.push("success", "Defended by model alignment", "The model refused — not counted as a bypass.");
      } else if (attack.outcome === "uncertain") {
        toast.push("info", "Inconclusive", "No clear refusal or compliance. Not released as evidence.");
      } else if (attack.outcome === "safe_completion" || attack.outcome === "empty") {
        toast.push("info", "No attack signal", "The response was assessed as a normal completion, not a bypass.");
      } else if (attack.outcome === "error") {
        toast.push("error", "Pipeline error", attack.blocked_by || "The sandbox did not return a response.");
      } else {
        toast.push("success", "Defence held", attack.blocked_by || outcomeMeta(attack.outcome).label);
      }
    } catch (err) {
      toast.push("error", "Attack failed", err instanceof Error ? err.message : undefined);
    } finally {
      setRunning(false);
      setRunningLabel("");
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!prompt.trim()) return;
    const body = { prompt, name: attackName || prompt.slice(0, 40), type: attackType };
    setPrompt("");
    setAttackName("");
    await fire(body);
  };

  const runEvasive = async () => {
    if (running) return;
    for (const attack of examples.evasive) {
      await fire({ prompt: attack.prompt, name: attack.name, type: attack.type });
    }
  };

  const clear = async () => {
    try {
      const response = await api.redClear(session.session_id);
      setAttacks([]);
      setStats(response.stats);
      toast.push("success", "Conversation cleared");
    } catch (err) {
      toast.push("error", "Could not clear", err instanceof Error ? err.message : undefined);
    }
  };

  const counts = useMemo(() => {
    const total = stats?.total_attacks || 0;
    return {
      total,
      defended: stats?.defended || 0,
      bypassed: stats?.bypassed || 0,
      inconclusive: stats?.inconclusive || 0,
      noSignal: stats?.no_signal || 0,
      rate: total ? Math.round(((stats?.bypassed || 0) / total) * 100) : 0,
    };
  }, [stats]);

  if (loading) return <Spinner label="Opening red team console…" />;

  return (
    <div className="page-stack">
      <section className="session-strip">
        <div>
          <span className="eyebrow">Signed in</span>
          <strong>{session.operator}</strong>
          <span className="muted mono">{session.session_id.slice(0, 10)}</span>
        </div>
        <div className="session-actions">
          <button className="btn btn-ghost btn-sm" onClick={clear}>
            <Eraser size={14} /> Clear conversation
          </button>
        </div>
      </section>

      <section className="metric-grid four">
        <MetricCard label="Attacks" value={counts.total} sub="this session" accent="#67e8f9" icon={<Swords size={17} />} />
        <MetricCard label="Defended" value={counts.defended} sub="layers + model refusal" accent="#34d399" icon={<ShieldCheck size={17} />} />
        <MetricCard label="Confirmed bypasses" value={counts.bypassed} sub={`${counts.rate}% of attempts`} accent="#fb7185" icon={<AlertTriangle size={17} />} />
        <MetricCard label="Needs review" value={counts.inconclusive} sub={`${counts.noSignal} safe completion(s)`} accent="#fbbf24" icon={<Search size={17} />} />
      </section>

      <Panel
        title="Attack console"
        subtitle="Prompts run through L1 rules → L2 ML → hardened model → L4 output filter → response assessment"
        actions={
          <button className="link-btn" onClick={() => setShowExamples((value) => !value)}>
            {showExamples ? "Hide examples" : "Show examples"} <ChevronDown size={14} className={showExamples ? "flip" : ""} />
          </button>
        }
      >
        <form className="attack-form" onSubmit={submit}>
          <textarea
            className="textarea composer"
            rows={4}
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Type an adversarial prompt. Ctrl/⌘ + Enter to fire…"
            onKeyDown={(event) => {
              if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
                event.preventDefault();
                submit(event as unknown as React.FormEvent);
              }
            }}
            disabled={running}
          />
          <div className="composer-bar">
            <div className="composer-fields">
              <label>
                <span>Attack type</span>
                <select className="select" value={attackType} onChange={(event) => setAttackType(event.target.value)}>
                  {(examples.attack_types || []).map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Label</span>
                <input
                  className="input"
                  value={attackName}
                  onChange={(event) => setAttackName(event.target.value)}
                  placeholder="name this attack"
                />
              </label>
            </div>
            <button className="btn btn-primary" type="submit" disabled={!prompt.trim() || running}>
              {running ? <Loader2 size={15} className="spin" /> : <Send size={15} />}
              {running ? "Running…" : "Fire prompt"}
            </button>
          </div>
        </form>

        {showExamples && (
          <div className="example-grid">
            <div className="example-column">
              <div className="example-head">
                <h3>Obvious payloads</h3>
                <span className="muted small">Usually caught by L1</span>
              </div>
              {examples.obvious.map((attack) => (
                <ExampleRow key={attack.name} attack={attack} disabled={running} onRun={fire} />
              ))}
            </div>
            <div className="example-column">
              <div className="example-head">
                <h3>Evasive payloads</h3>
                <button className="btn btn-outline btn-sm" onClick={runEvasive} disabled={running || examples.evasive.length === 0}>
                  {running ? <Loader2 size={13} className="spin" /> : <Zap size={13} />} Run full set
                </button>
              </div>
              {examples.evasive.map((attack) => (
                <ExampleRow key={attack.name} attack={attack} disabled={running} onRun={fire} />
              ))}
            </div>
          </div>
        )}
      </Panel>

      <div className="conversation-head">
        <h2>Conversation</h2>
        <span className="muted small">{attacks.length} attempt(s) · newest last</span>
      </div>

      {running && (
        <div className="attack-card pending">
          <Loader2 size={18} className="spin" />
          <div>
            <strong>Running {runningLabel}</strong>
            <p className="muted">Waiting for the sandboxed model and the response assessor…</p>
          </div>
        </div>
      )}

      {attacks.length === 0 && !running ? (
        <EmptyState
          icon={<Swords size={22} />}
          title="No attacks yet"
          message="Fire an example above or write your own prompt. Every attempt is journaled with its conditions."
        />
      ) : (
        <div className="attack-list">
          {attacks.map((attack, index) => (
            <AttackCard key={attack.id} attack={attack} index={index + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function ExampleRow({ attack, disabled, onRun }: { attack: any; disabled: boolean; onRun: (payload: { prompt: string; name: string; type: string }) => void }) {
  return (
    <div className="example-row">
      <div>
        <div className="example-title">
          <Badge color="#67e8f9">{attack.type}</Badge>
          <strong>{attack.name}</strong>
        </div>
        <p>{attack.prompt}</p>
      </div>
      <button
        className="btn btn-ghost btn-sm"
        onClick={() => onRun({ prompt: attack.prompt, name: attack.name, type: attack.type })}
        disabled={disabled}
      >
        <Play size={12} /> Run
      </button>
    </div>
  );
}

function AttackCard({ attack, index }: { attack: Attack; index: number }) {
  const meta = outcomeMeta(attack.outcome);
  const assessment = attack.assessment;
  const conditions = attack.conditions;
  const defended = attack.defended || ["blocked", "filtered", "refused"].includes(attack.outcome);
  const bypassed = attack.outcome === "complied" || attack.bypassed;

  return (
    <article className={`attack-card ${bypassed ? "is-bypass" : defended ? "is-defended" : "is-neutral"}`}>
      <header className="attack-head">
        <div className="attack-identity">
          <span className="attack-index">{String(index).padStart(2, "0")}</span>
          <div>
            <strong>{attack.attack_name}</strong>
            <div className="attack-sub">
              <span>{attack.attack_type}</span>
              <span className="dot">·</span>
              <Clock3 size={12} />
              <span title={formatLocal(attack.timestamp)}>{relativeTime(attack.timestamp)}</span>
              {attack.journal_id && (
                <>
                  <span className="dot">·</span>
                  <Fingerprint size={12} />
                  <span className="mono">{attack.journal_id}</span>
                </>
              )}
            </div>
          </div>
        </div>
        <OutcomeBadge outcome={attack.outcome} large />
      </header>

      <div className="prompt-block">
        <span className="block-label">Submitted prompt</span>
        <pre>{attack.prompt}</pre>
      </div>

      <div className={`verdict-strip ${bypassed ? "bad" : defended ? "good" : "warn"}`}>
        <div>
          <strong>
            {bypassed
              ? "Confirmed bypass — the model complied"
              : attack.outcome === "refused"
                ? "Defended by model alignment — the model refused"
                : attack.outcome === "filtered"
                  ? "Defended by output filter"
                  : attack.outcome === "blocked"
                    ? "Defended by an input layer"
                    : attack.outcome === "error"
                      ? "Pipeline error"
                      : attack.outcome === "safe_completion" || attack.outcome === "empty"
                        ? "No attack signal — normal completion"
                        : "Inconclusive — needs review"}
          </strong>
          <p>
            {bypassed
              ? attack.breach_path || "All defence layers cleared; response assessment confirmed compliance."
              : attack.outcome === "safe_completion"
                ? "The model answered without refusing or complying, and the prompt showed no attack signal. This is not a bypass or a defence win."
                : attack.blocked_by || assessment?.reason || "No clear verdict was reached."}
          </p>
        </div>
        {bypassed && attack.evidence_id && <Badge color="#fb7185">Evidence {attack.evidence_id}</Badge>}
      </div>

      <div className="response-block">
        <div className="response-head">
          <span className="block-label">{bypassed ? "Model response — bypass evidence" : "Model response"}</span>
          {assessment && (
            <div className="score-pair">
              <span>refusal <b>{Math.round(assessment.refusal_score * 100)}%</b></span>
              <span>compliance <b>{Math.round(assessment.compliance_score * 100)}%</b></span>
            </div>
          )}
        </div>
        <div className="response-body">
          {attack.llm_response ? (
            <p>{attack.llm_response}</p>
          ) : (
            <p className="muted">No response was returned to the operator.</p>
          )}
        </div>
        {attack.raw_response && attack.raw_response !== attack.llm_response && (
          <details className="raw-details">
            <summary>Raw model output (before output filter)</summary>
            <pre>{attack.raw_response}</pre>
          </details>
        )}
      </div>

      <div className="attack-meta-grid">
        <div>
          <span className="block-label">Detected conditions</span>
          <ConditionChips flags={conditions?.flags} labels={conditions?.labels} />
        </div>
        <div>
          <span className="block-label">Risk</span>
          <div className="chip-row">
            <Badge color={conditions?.risk_level === "critical" ? "#fb7185" : conditions?.risk_level === "high" ? "#fb923c" : "#fbbf24"}>
              {(conditions?.risk_level || "low").toUpperCase()} · {conditions?.risk_score || 0}
            </Badge>
            <span className="muted small">{conditions?.length || attack.prompt.length} chars</span>
          </div>
        </div>
        <div>
          <span className="block-label">Layers cleared</span>
          {attack.layers_bypassed?.length ? (
            <div className="chip-row">
              {attack.layers_bypassed.map((layer) => (
                <Badge key={layer} color={bypassed ? "#fb7185" : "#38bdf8"}>
                  {LAYER_LABELS[layer] || layer}
                </Badge>
              ))}
            </div>
          ) : (
            <span className="muted small">None</span>
          )}
        </div>
        <div>
          <span className="block-label">Containment</span>
          <span className="small">{attack.containment_layer || (bypassed ? "No containment" : "—")}</span>
        </div>
      </div>

      <details className="trace-details">
        <summary>Defence layer trace</summary>
        <LayerTrace trace={attack.layer_trace} />
      </details>
    </article>
  );
}
