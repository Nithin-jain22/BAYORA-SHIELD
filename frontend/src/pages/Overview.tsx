import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity,
  ArrowUpRight,
  ChevronRight,
  CircleGauge,
  FileWarning,
  ShieldCheck,
  Swords,
  Wrench,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import { CONDITION_LABELS, formatLocal, outcomeMeta, relativeTime } from "../lib/format";
import type { OverviewData } from "../types";
import {
  ConditionChips,
  EmptyState,
  MetricCard,
  OutcomeBadge,
  Panel,
  Spinner,
  outcomeCounts,
  useInterval,
} from "../components/ui";
import type { PageKey } from "../components/Layout";

const OUTCOME_COLORS = ["#38bdf8", "#34d399", "#fb7185", "#fbbf24", "#a78bfa", "#94a3b8"];

export function OverviewPage({
  onNavigate,
  onStartSandbox,
  sandboxBusy,
}: {
  onNavigate: (page: PageKey) => void;
  onStartSandbox: () => void;
  sandboxBusy: boolean;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const payload = await api.overview();
      setData(payload);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load overview");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useInterval(load, 12000);

  if (loading && !data) {
    return <Spinner label="Loading command center…" />;
  }
  if (error && !data) {
    return (
      <EmptyState
        icon={<FileWarning size={22} />}
        title="API unavailable"
        message={error}
        action={
          <button className="btn btn-primary" onClick={load}>
            Retry
          </button>
        }
      />
    );
  }
  if (!data) return null;

  const counts = outcomeCounts(data.summary.outcomes);
  const retests = Math.max(0, data.journal_total - data.summary.total);
  const journalSub = retests
    ? `${data.journal_total} journal entries · ${retests} retest${retests === 1 ? "" : "s"} excluded`
    : `${data.journal_total} journal entries`;
  const outcomeData = [
    { name: "Blocked layer", value: data.summary.outcomes.blocked || 0, color: "#38bdf8" },
    { name: "Output filtered", value: data.summary.outcomes.filtered || 0, color: "#a78bfa" },
    { name: "Model refused", value: data.summary.outcomes.refused || 0, color: "#34d399" },
    { name: "Confirmed bypass", value: counts.bypassed, color: "#fb7185" },
    {
      name: "Inconclusive",
      value:
        (data.summary.outcomes.uncertain || 0) +
        (data.summary.outcomes.empty || 0) +
        (data.summary.outcomes.safe_completion || 0),
      color: "#fbbf24",
    },
    { name: "Pipeline error", value: data.summary.outcomes.error || 0, color: "#f97316" },
  ].filter((item) => item.value > 0);

  const conditionRows = Object.entries(data.summary.conditions.counts)
    .map(([flag, attacks]) => ({
      flag,
      label: CONDITION_LABELS[flag] || flag,
      attacks,
      bypasses: data.summary.conditions.bypass_counts[flag] || 0,
      rate:
        attacks > 0 ? Math.round(((data.summary.conditions.bypass_counts[flag] || 0) / attacks) * 100) : 0,
    }))
    .sort((a, b) => b.bypasses - a.bypasses || b.attacks - a.attacks)
    .slice(0, 7);

  const running = Boolean(data.sandbox?.running || data.sandbox?.listening);

  return (
    <div className="page-stack">
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className={`status-dot ${running ? "live" : "dead"}`} />
            {running ? "Live adversarial evaluation" : "Sandbox offline"}
          </div>
          <h2>
            Prove the attack.
            <br />
            <span>Trust the evidence.</span>
          </h2>
          <p>
            A layered defence pipeline, isolated model execution, and a tamper-evident
            record of every attempt. Refusals count as defence wins — only confirmed
            compliance becomes a finding.
          </p>
          <div className="hero-actions">
            <button className="btn btn-primary" onClick={() => onNavigate("red")}>
              <Swords size={16} /> Launch red team
            </button>
            <button className="btn btn-ghost" onClick={() => onNavigate("blue")}>
              <ShieldCheck size={16} /> Review findings
            </button>
            {!running && (
              <button className="btn btn-outline" onClick={onStartSandbox} disabled={sandboxBusy}>
                Start sandbox
              </button>
            )}
          </div>
        </div>
        <div className="hero-signal">
          <div className="signal-orbit">
            <CircleGauge size={42} />
            <strong>{Math.round((counts.blocked + counts.refused) * 100 / Math.max(1, data.summary.total))}%</strong>
            <span>defended</span>
          </div>
          <div className="signal-note">
            <span>Audit chain</span>
            <strong>{data.audit.valid ? "Intact" : `Broken @ ${data.audit.broken_at}`}</strong>
            <small>{data.audit.valid ? "SHA-256 hash chain verified" : "Investigate tampering"}</small>
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard label="Total attacks" value={data.summary.total} sub={journalSub} accent="#67e8f9" icon={<Activity size={17} />} />
        <MetricCard label="Confirmed bypasses" value={counts.bypassed} sub={`${Math.round(data.summary.bypass_rate * 100)}% bypass rate`} accent="#fb7185" icon={<FileWarning size={17} />} />
        <MetricCard label="Defended" value={counts.blocked + counts.refused} sub={`${counts.refused} by model refusal`} accent="#34d399" icon={<ShieldCheck size={17} />} />
        <MetricCard label="Open findings" value={data.evidence.pending} sub={`${data.evidence.fixed} fixed · ${data.evidence.vulnerable} still vulnerable`} accent="#fbbf24" icon={<Wrench size={17} />} />
      </section>

      <section className="split-grid">
        <Panel
          title="Attack activity"
          subtitle="Defended vs confirmed bypasses over recorded days"
          actions={
            <button className="link-btn" onClick={() => onNavigate("evaluation")}>
              Full evaluation <ArrowUpRight size={14} />
            </button>
          }
        >
          {data.summary.timeline.length === 0 ? (
            <EmptyState
              icon={<Swords size={22} />}
              title="No attacks recorded"
              message="Run an evasion set from the red team console to populate the timeline."
              action={<button className="btn btn-primary btn-sm" onClick={() => onNavigate("red")}>Open red team</button>}
            />
          ) : (
            <div className="chart-frame">
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={data.summary.timeline} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
                  <defs>
                    <linearGradient id="defended" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#34d399" stopOpacity={0.32} />
                      <stop offset="100%" stopColor="#34d399" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="bypassed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#fb7185" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#fb7185" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(148,163,184,.12)" vertical={false} />
                  <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="defended" stroke="#34d399" strokeWidth={2} fill="url(#defended)" name="Defended" />
                  <Area type="monotone" dataKey="bypassed" stroke="#fb7185" strokeWidth={2} fill="url(#bypassed)" name="Bypassed" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title="Outcome mix" subtitle="Every attack is assessed before it becomes evidence">
          {outcomeData.length === 0 ? (
            <p className="muted">No outcomes yet.</p>
          ) : (
            <div className="donut-layout">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={outcomeData} dataKey="value" nameKey="name" innerRadius={62} outerRadius={88} paddingAngle={3} stroke="none">
                    {outcomeData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend">
                {outcomeData.map((entry) => (
                  <div key={entry.name} className="legend-row">
                    <span className="legend-dot" style={{ background: entry.color }} />
                    <span>{entry.name}</span>
                    <strong>{entry.value}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </section>

      <section className="split-grid">
        <Panel
          title="Conditions correlated with bypasses"
          subtitle="Exact structural signals recorded in the attack journal"
          actions={
            <button className="link-btn" onClick={() => onNavigate("reports")}>
              Export report <ArrowUpRight size={14} />
            </button>
          }
        >
          {conditionRows.length === 0 ? (
            <p className="muted">No structural conditions recorded yet.</p>
          ) : (
            <div className="chart-frame">
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={conditionRows} layout="vertical" margin={{ left: 12, right: 18, top: 4, bottom: 4 }}>
                  <CartesianGrid stroke="rgba(148,163,184,.12)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="label" width={132} tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="attacks" fill="#1e3a3a" radius={[0, 6, 6, 0]} name="Attacks" />
                  <Bar dataKey="bypasses" fill="#fb7185" radius={[0, 6, 6, 0]} name="Bypasses" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title="Recent attacks" subtitle="Latest verdicts from the shared pipeline" actions={<button className="link-btn" onClick={() => onNavigate("red")}>Open console <ChevronRight size={14} /></button>}>
          {data.recent_attacks.length === 0 ? (
            <p className="muted">No attacks yet.</p>
          ) : (
            <div className="activity-list">
              {data.recent_attacks.map((attack) => {
                const meta = outcomeMeta(attack.outcome);
                return (
                  <div key={attack.id} className="activity-row">
                    <span className="activity-marker" style={{ background: meta.color }} />
                    <div className="activity-main">
                      <div className="activity-title">
                        <strong>{attack.attack_name}</strong>
                        <OutcomeBadge outcome={attack.outcome} />
                      </div>
                      <ConditionChips flags={attack.conditions?.flags} labels={attack.conditions?.labels} limit={3} />
                    </div>
                    <span className="activity-time" title={attack.timestamp_iso || formatLocal(attack.timestamp)}>
                      {relativeTime(attack.timestamp)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </section>

      <section className="split-grid three">
        <Panel title="Defence posture" subtitle="Live learned state">
          <div className="stat-list">
            <StatRow label="Layer 1 rules" value={data.defense.rules} />
            <StatRow label="Layer 4 patterns" value={data.defense.output_patterns} />
            <StatRow label="Learned rules" value={data.defense.learned_rules} />
            <StatRow label="Learned ML examples" value={data.defense.learned_ml_examples} />
          </div>
        </Panel>
        <Panel title="Sandbox" subtitle="Isolation boundary">
          <div className="stat-list">
            <StatRow label="Backend" value={data.sandbox?.backend || "not started"} />
            <StatRow label="Port" value={data.sandbox?.port || 11435} />
            <StatRow label="Listening" value={data.sandbox?.listening ? "yes" : "no"} />
            <StatRow label="Docker" value={data.sandbox?.docker_available ? "available" : "unavailable"} />
          </div>
          <button className="btn btn-ghost btn-sm full" onClick={() => onNavigate("repair")}>
            <Wrench size={14} /> Open repair workspace
          </button>
        </Panel>
        <Panel title="Retest closure" subtitle="Findings released to blue team">
          <div className="stat-list">
            <StatRow label="Total findings" value={data.evidence.total} />
            <StatRow label="Pending" value={data.evidence.pending} />
            <StatRow label="Fixed" value={data.evidence.fixed} />
            <StatRow label="Still vulnerable" value={data.evidence.vulnerable} />
          </div>
        </Panel>
      </section>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="stat-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      {label && <strong>{label}</strong>}
      {payload.map((item: any) => (
        <div key={item.name}>
          <span style={{ background: item.color || item.fill }} />
          {item.name}: <b>{item.value}</b>
        </div>
      ))}
    </div>
  );
}
