import { useCallback, useEffect, useState } from "react";
import type { ElementType } from "react";
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  ClipboardCheck,
  Container,
  FileWarning,
  HardDrive,
  Loader2,
  LockKeyhole,
  Network,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Wrench,
} from "lucide-react";
import { api } from "../lib/api";
import { formatLocal, relativeTime } from "../lib/format";
import type { AuditEvent, SandboxHealth } from "../types";
import {
  Badge,
  EmptyState,
  HealthBadge,
  MetricCard,
  Modal,
  Panel,
  ScoreRing,
  Spinner,
  useToast,
} from "../components/ui";

interface RepairAction {
  id: string;
  description: string;
  destructive: boolean;
}

const ACTION_ICONS: Record<string, ElementType> = {
  restart_sandbox: Play,
  recreate_sandbox: Container,
  reset_gateway: Activity,
  repair_defense_store: ShieldCheck,
  quarantine_evidence: HardDrive,
  repair_permissions: LockKeyhole,
  verify_audit_chain: ClipboardCheck,
  reset_runtime: Trash2,
  run_safe_repairs: Wrench,
};

export function RepairPage() {
  const toast = useToast();
  const [health, setHealth] = useState<SandboxHealth | null>(null);
  const [actions, setActions] = useState<RepairAction[]>([]);
  const [repairs, setRepairs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<RepairAction | null>(null);
  const [note, setNote] = useState("");
  const [lastResult, setLastResult] = useState<any>(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [healthPayload, actionPayload, auditPayload] = await Promise.all([
        api.sandboxHealth(),
        api.sandboxActions(),
        api.auditEvents({ event_type: "sandbox_repair", limit: 40 }),
      ]);
      setHealth(healthPayload);
      setActions(actionPayload.actions || []);
      setRepairs(auditPayload.events || []);
    } catch (err) {
      toast.push("error", "Could not load repair workspace", err instanceof Error ? err.message : undefined);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const execute = async (action: RepairAction, confirmed = false) => {
    setBusy(action.id);
    try {
      const result = await api.sandboxRepair({
        action: action.id,
        confirm: confirmed,
        note: note.trim(),
        operator: "blue_team",
      });
      setLastResult(result);
      if (result.ok) {
        toast.push("success", "Repair completed", result.message);
        setSelected(null);
        setNote("");
        await load(true);
      } else {
        toast.push("warning", "Repair did not complete", result.message);
      }
    } catch (err: any) {
      if (err?.status === 409) {
        setSelected(action);
        toast.push("warning", "Confirmation required", "Review the impact before running this destructive repair.");
      } else {
        toast.push("error", "Repair failed", err instanceof Error ? err.message : undefined);
      }
    } finally {
      setBusy(null);
    }
  };

  if (loading && !health) return <Spinner label="Inspecting sandbox isolation layers…" />;
  if (!health) {
    return (
      <EmptyState
        icon={<FileWarning size={22} />}
        title="Health check unavailable"
        message="The API could not inspect the sandbox."
        action={<button className="btn btn-primary" onClick={() => load()}>Retry</button>}
      />
    );
  }

  const breached = health.layers.filter((layer) => layer.status === "breached");
  const degraded = health.layers.filter((layer) => layer.status === "degraded");

  return (
    <div className="page-stack">
      <section className={`repair-hero ${health.status}`}>
        <div className="repair-score">
          <ScoreRing score={health.score} size={126} />
          <div>
            <span className="eyebrow">Sandbox health</span>
            <h2>
              {health.status === "healthy"
                ? "Isolation layers intact"
                : health.status === "critical"
                  ? "Damage detected"
                  : "Degraded posture"}
            </h2>
            <p>
              {breached.length} breached · {degraded.length} degraded · checked {relativeTime(health.timestamp)}
            </p>
            <span className="muted micro">Last check: {formatLocal(health.timestamp)}</span>
          </div>
        </div>
        <div className="repair-hero-actions">
          <button className="btn btn-ghost btn-sm" onClick={() => load(true)}>
            <RotateCcw size={14} /> Re-check
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => {
              const safe = actions.find((action) => action.id === "run_safe_repairs");
              if (safe) execute(safe);
            }}
            disabled={Boolean(busy)}
          >
            {busy === "run_safe_repairs" ? <Loader2 size={14} className="spin" /> : <Wrench size={14} />}
            Run safe repairs
          </button>
        </div>
      </section>

      <section className="metric-grid four">
        <MetricCard label="Health score" value={`${health.score}/100`} sub={`${health.damage_score} damage points`} accent="#34d399" icon={<ShieldCheck size={17} />} />
        <MetricCard label="Breached layers" value={breached.length} sub={breached.map((layer) => layer.name).join(", ") || "none"} accent="#fb7185" icon={<ShieldAlert size={17} />} />
        <MetricCard label="Degraded layers" value={degraded.length} sub={degraded.map((layer) => layer.name).join(", ") || "none"} accent="#fbbf24" icon={<AlertOctagon size={17} />} />
        <MetricCard label="Repairs logged" value={repairs.length} sub="tamper-evident audit trail" accent="#67e8f9" icon={<ClipboardCheck size={17} />} />
      </section>

      <Panel title="Isolation layer checks" subtitle="Each boundary is inspected independently before and after repair">
        <div className="health-grid">
          {health.layers.map((layer) => (
            <div key={layer.id} className={`health-card ${layer.status}`}>
              <div className="health-head">
                <div className="health-icon">
                  {layer.id.includes("network") ? <Network size={17} /> : layer.id.includes("audit") ? <LockKeyhole size={17} /> : layer.id.includes("runtime") ? <HardDrive size={17} /> : <ShieldCheck size={17} />}
                </div>
                <div>
                  <strong>{layer.name}</strong>
                  {layer.critical && <span className="muted micro">critical</span>}
                </div>
                <HealthBadge status={layer.status} />
              </div>
              <p>{layer.detail}</p>
              {layer.recommendation && (
                <div className="health-rec">
                  <Terminal size={13} />
                  <span>{layer.recommendation}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Manual repair actions" subtitle="Explicit, audited, and backed up where destructive">
        <div className="repair-grid">
          {actions.map((action) => {
            const Icon = ACTION_ICONS[action.id] || Wrench;
            return (
              <div key={action.id} className={`repair-card ${action.destructive ? "destructive" : ""}`}>
                <div className="repair-card-head">
                  <div className="repair-icon"><Icon size={18} /></div>
                  <div>
                    <strong>{action.id.replaceAll("_", " ")}</strong>
                    {action.destructive && <Badge color="#fb7185">DESTRUCTIVE</Badge>}
                  </div>
                </div>
                <p>{action.description}</p>
                <button
                  className={`btn btn-sm ${action.destructive ? "btn-danger" : "btn-ghost"}`}
                  onClick={() => {
                    if (action.destructive) {
                      setSelected(action);
                      setNote("");
                    } else {
                      execute(action);
                    }
                  }}
                  disabled={Boolean(busy)}
                >
                  {busy === action.id ? <Loader2 size={14} className="spin" /> : <Play size={13} />}
                  Run repair
                </button>
              </div>
            );
          })}
        </div>
      </Panel>

      <section className="split-grid">
        <Panel title="Manual runbook" subtitle="Use when automation cannot restore trust">
          <ol className="runbook">
            <li>
              <strong>Contain.</strong> Stop the sandbox and quarantine the evidence queue. Do not edit the audit log in place.
            </li>
            <li>
              <strong>Recreate.</strong> Remove the container and start a fresh sandbox so read-only root, dropped capabilities, PID/memory limits and loopback binding are re-applied.
            </li>
            <li>
              <strong>Repair state.</strong> Validate learned regex patterns and ML examples; remove malformed entries and keep a backup.
            </li>
            <li>
              <strong>Verify.</strong> Re-run the audit chain verification and the full isolation health check.
            </li>
            <li>
              <strong>Retest.</strong> Replay withheld payloads through the updated pipeline before closing findings.
            </li>
          </ol>
        </Panel>

        <Panel title="Repair history" subtitle="Every action is written to the SHA-256 audit chain">
          {repairs.length === 0 ? (
            <p className="muted">No repair actions recorded yet.</p>
          ) : (
            <div className="repair-history">
              {repairs.map((event) => (
                <div key={`${event.timestamp}-${event.hash}`} className="repair-history-row">
                  <span className={`status-dot ${event.details?.ok ? "live" : "dead"}`} />
                  <div>
                    <strong>{String(event.details?.action || "repair").replaceAll("_", " ")}</strong>
                    <p>{event.details?.message || "—"}</p>
                    {event.details?.note && <p className="muted micro">Note: {event.details.note}</p>}
                  </div>
                  <span className="muted micro" title={formatLocal(event.timestamp)}>{relativeTime(event.timestamp)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </section>

      {lastResult && (
        <Panel title="Last repair result" subtitle={`${lastResult.action} · ${lastResult.duration_seconds}s`}>
          <div className={`repair-result ${lastResult.ok ? "good" : "bad"}`}>
            <CheckCircle2 size={18} />
            <div>
              <strong>{lastResult.message}</strong>
              <p className="muted micro">{formatLocal(lastResult.timestamp)}</p>
            </div>
          </div>
        </Panel>
      )}

      <Modal
        open={Boolean(selected)}
        title={`Run ${selected?.id.replaceAll("_", " ") || "repair"}?`}
        onClose={() => setSelected(null)}
        danger
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => setSelected(null)}>Cancel</button>
            <button className="btn btn-danger" onClick={() => selected && execute(selected, true)} disabled={Boolean(busy)}>
              {busy ? <Loader2 size={14} className="spin" /> : <AlertOctagon size={14} />}
              Confirm repair
            </button>
          </>
        }
      >
        <p>{selected?.description}</p>
        <p className="muted small">
          This action is destructive. Files are backed up to <code>data/runtime/quarantine</code> where possible,
          and the action is logged to the audit chain.
        </p>
        <label className="field-label" htmlFor="repair-note">Operator note (optional)</label>
        <textarea
          id="repair-note"
          className="textarea"
          rows={3}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Why is this repair needed?"
        />
      </Modal>
    </div>
  );
}
