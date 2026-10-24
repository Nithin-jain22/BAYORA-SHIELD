import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownRight,
  ArrowUpRight,
  BarChart3,
  Camera,
  GitCompareArrows,
  Loader2,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import { formatLocal } from "../lib/format";
import type { EvaluationRun } from "../types";
import {
  Badge,
  EmptyState,
  MetricCard,
  Panel,
  Spinner,
  useToast,
} from "../components/ui";

export function EvaluationPage({
  redSession,
}: {
  redSession: { session_id: string; operator: string } | null;
}) {
  const toast = useToast();
  const [runs, setRuns] = useState<EvaluationRun[]>([]);
  const [trend, setTrend] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [snapshotting, setSnapshotting] = useState(false);
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");

  const load = useCallback(async () => {
    try {
      const payload = await api.evaluation();
      setRuns(payload.runs || []);
      setTrend(payload.trend || []);
      const ids = (payload.runs || []).map((run: EvaluationRun) => run.run_id);
      setLeft((prev) => prev || ids[1] || ids[0] || "");
      setRight((prev) => prev || ids[0] || "");
    } catch (err) {
      toast.push("error", "Could not load evaluation", err instanceof Error ? err.message : undefined);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const snapshot = async (sessionId?: string) => {
    setSnapshotting(true);
    try {
      const response = await api.snapshot({ session_id: sessionId, defense_version: "live" });
      toast.push("success", "Run recorded", `Evaluation run ${response.run.run_id} saved.`);
      await load();
    } catch (err) {
      toast.push("error", "Snapshot failed", err instanceof Error ? err.message : undefined);
    } finally {
      setSnapshotting(false);
    }
  };

  const chartData = useMemo(
    () =>
      trend.map((row) => ({
        ...row,
        label: row.timestamp ? new Date(row.timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "—",
        block_pct: Math.round((row.block_rate || 0) * 100),
        bypass_pct: Math.round((row.bypass_rate || 0) * 100),
      })),
    [trend],
  );

  const latest = runs[0];
  const compareLeft = runs.find((run) => run.run_id === left);
  const compareRight = runs.find((run) => run.run_id === right);

  if (loading) return <Spinner label="Loading evaluation runs…" />;

  const avgBlock = runs.length
    ? Math.round((runs.reduce((sum, run) => sum + run.block_rate, 0) / runs.length) * 100)
    : 0;
  const totalAttacks = runs.reduce((sum, run) => sum + run.total_attacks, 0);
  const totalBypasses = runs.reduce((sum, run) => sum + run.bypassed, 0);

  return (
    <div className="page-stack">
      <section className="page-header">
        <div>
          <span className="eyebrow">Reproducible measurement</span>
          <h2>Evaluation plane</h2>
          <p>Versioned runs, outcome composition, and regressions across the defence lifecycle.</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost" onClick={load}>
            <RefreshCw size={15} /> Refresh
          </button>
          <button
            className="btn btn-primary"
            onClick={() => snapshot(redSession?.session_id)}
            disabled={snapshotting || (!redSession && latest === undefined)}
          >
            {snapshotting ? <Loader2 size={15} className="spin" /> : <Camera size={15} />}
            {redSession ? "Snapshot current session" : "Snapshot journal"}
          </button>
        </div>
      </section>

      <section className="metric-grid four">
        <MetricCard label="Recorded runs" value={runs.length} sub="versioned snapshots" accent="#67e8f9" icon={<BarChart3 size={17} />} />
        <MetricCard label="Average block rate" value={`${avgBlock}%`} sub="defended + refused" accent="#34d399" icon={<ShieldCheck size={17} />} />
        <MetricCard label="Attacks measured" value={totalAttacks} sub="across all runs" accent="#a78bfa" icon={<Camera size={17} />} />
        <MetricCard label="Confirmed bypasses" value={totalBypasses} sub="across all runs" accent="#fb7185" icon={<ArrowDownRight size={17} />} />
      </section>

      <Panel title="Block rate trend" subtitle="Defence rate should rise as fixes are applied and retested">
        {chartData.length === 0 ? (
          <EmptyState
            icon={<BarChart3 size={22} />}
            title="No evaluation runs"
            message="Snapshot a red-team session or the attack journal to create the first run."
            action={
              <button className="btn btn-primary" onClick={() => snapshot(redSession?.session_id)} disabled={snapshotting}>
                <Camera size={15} /> Record first run
              </button>
            }
          />
        ) : (
          <div className="chart-frame">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData} margin={{ top: 12, right: 16, left: -16, bottom: 0 }}>
                <CartesianGrid stroke="rgba(148,163,184,.12)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} unit="%" />
                <Tooltip content={<EvalTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12, color: "#94a3b8" }} />
                <Line type="monotone" dataKey="block_pct" name="Defended %" stroke="#34d399" strokeWidth={2.5} dot={{ r: 3, fill: "#34d399" }} />
                <Line type="monotone" dataKey="bypass_pct" name="Bypassed %" stroke="#fb7185" strokeWidth={2.5} dot={{ r: 3, fill: "#fb7185" }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Panel>

      {latest && (
        <section className="split-grid">
          <Panel title="Latest run composition" subtitle={`${latest.run_id} · ${formatLocal(latest.timestamp)}`}>
            <div className="chart-frame">
              <ResponsiveContainer width="100%" height={250}>
                <BarChart
                  data={[
                    { name: "Blocked", value: latest.outcome_breakdown?.blocked || 0, fill: "#38bdf8" },
                    { name: "Filtered", value: latest.outcome_breakdown?.filtered || 0, fill: "#a78bfa" },
                    { name: "Refused", value: latest.refused || latest.outcome_breakdown?.refused || 0, fill: "#34d399" },
                    { name: "Bypassed", value: latest.bypassed, fill: "#fb7185" },
                    {
                      name: "Inconclusive",
                      value:
                        latest.inconclusive ||
                        Object.entries(latest.outcome_breakdown || {})
                          .filter(([key]) => ["uncertain", "empty", "safe_completion", "error"].includes(key))
                          .reduce((sum, [, value]) => sum + Number(value || 0), 0),
                      fill: "#fbbf24",
                    },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <CartesianGrid stroke="rgba(148,163,184,.12)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<EvalTooltip />} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                    {[
                      "#38bdf8",
                      "#a78bfa",
                      "#34d399",
                      "#fb7185",
                      "#fbbf24",
                    ].map((color, index) => (
                      <Cell key={index} fill={color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Latest per-type breakdown" subtitle="Where the remaining risk is concentrated">
            <div className="type-breakdown">
              {Object.entries(latest.per_type_breakdown || {}).map(([type, counts]) => {
                const total = counts.total || 0;
                const bypassed = counts.bypassed || 0;
                const rate = total ? Math.round((bypassed / total) * 100) : 0;
                return (
                  <div key={type} className="type-row">
                    <div className="type-label">
                      <strong>{type}</strong>
                      <span>{total} attack(s)</span>
                    </div>
                    <div className="type-bar">
                      <i style={{ width: `${rate}%`, background: rate > 0 ? "#fb7185" : "#34d399" }} />
                    </div>
                    <Badge color={rate > 0 ? "#fb7185" : "#34d399"}>{rate}% bypass</Badge>
                  </div>
                );
              })}
              {Object.keys(latest.per_type_breakdown || {}).length === 0 && (
                <p className="muted">No per-type data recorded.</p>
              )}
            </div>
          </Panel>
        </section>
      )}

      <Panel title="Compare runs" subtitle="Track improvement or regression between two snapshots">
        {runs.length < 2 ? (
          <p className="muted">Record at least two runs to compare.</p>
        ) : (
          <>
            <div className="compare-controls">
              <label>
                <span className="field-label">Baseline</span>
                <select className="select" value={left} onChange={(event) => setLeft(event.target.value)}>
                  {runs.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id} · {formatLocal(run.timestamp)}</option>)}
                </select>
              </label>
              <label>
                <span className="field-label">Comparison</span>
                <select className="select" value={right} onChange={(event) => setRight(event.target.value)}>
                  {runs.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id} · {formatLocal(run.timestamp)}</option>)}
                </select>
              </label>
            </div>
            {compareLeft && compareRight && (
              <div className="compare-grid">
                <CompareMetric
                  label="Defence rate"
                  before={compareLeft.block_rate}
                  after={compareRight.block_rate}
                  invert
                />
                <CompareMetric
                  label="Bypass rate"
                  before={compareLeft.bypass_rate}
                  after={compareRight.bypass_rate}
                />
                <CompareMetric
                  label="Confirmed bypasses"
                  before={compareLeft.bypassed}
                  after={compareRight.bypassed}
                  raw
                />
                <CompareMetric
                  label="Attacks measured"
                  before={compareLeft.total_attacks}
                  after={compareRight.total_attacks}
                  raw
                  neutral
                />
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel title="Recorded runs" subtitle="Immutable snapshots stored in data/runtime/evaluation_runs">
        {runs.length === 0 ? (
          <p className="muted">No runs recorded.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Recorded</th>
                  <th>Model</th>
                  <th>Attacks</th>
                  <th>Defended</th>
                  <th>Refused</th>
                  <th>Bypassed</th>
                  <th>Inconclusive</th>
                  <th>Defence rate</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.run_id}>
                    <td className="mono">{run.run_id}</td>
                    <td>{formatLocal(run.timestamp)}</td>
                    <td>{run.model}</td>
                    <td>{run.total_attacks}</td>
                    <td>{run.blocked}</td>
                    <td>{run.refused || 0}</td>
                    <td><span className={run.bypassed ? "text-bad" : "text-good"}>{run.bypassed}</span></td>
                    <td>{run.inconclusive || 0}</td>
                    <td>{Math.round(run.block_rate * 100)}%</td>
                    <td><Badge color="#67e8f9">{run.defense_version}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function CompareMetric({
  label,
  before,
  after,
  invert = false,
  raw = false,
  neutral = false,
}: {
  label: string;
  before: number;
  after: number;
  invert?: boolean;
  raw?: boolean;
  neutral?: boolean;
}) {
  const delta = after - before;
  const good = neutral ? false : invert ? delta >= 0 : delta <= 0;
  const color = neutral ? "#94a3b8" : good ? "#34d399" : "#fb7185";
  const Icon = delta === 0 ? GitCompareArrows : delta > 0 ? ArrowUpRight : ArrowDownRight;
  return (
    <div className="compare-card">
      <span>{label}</span>
      <div>
        <strong>{raw ? before : `${Math.round(before * 100)}%`}</strong>
        <span className="muted">→</span>
        <strong>{raw ? after : `${Math.round(after * 100)}%`}</strong>
      </div>
      <Badge color={color}><Icon size={12} /> {delta > 0 ? "+" : ""}{raw ? delta : `${Math.round(delta * 100)}%`}</Badge>
    </div>
  );
}

function EvalTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      {label && <strong>{label}</strong>}
      {payload.map((item: any) => (
        <div key={item.name}>
          <span style={{ background: item.color || item.fill }} />
          {item.name}: <b>{item.value}{typeof item.value === "number" && item.name?.includes("%") ? "%" : ""}</b>
        </div>
      ))}
    </div>
  );
}
