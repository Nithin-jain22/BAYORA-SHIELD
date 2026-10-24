import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, Loader2, X, XCircle } from "lucide-react";
import {
  CONDITION_LABELS,
  LAYER_LABELS,
  OUTCOME_META,
  STATUS_META,
  outcomeMeta,
} from "../lib/format";
import type { LayerTrace as LayerTraceType } from "../types";

/* ── Toast ─────────────────────────────────────────────────────────────── */

type ToastKind = "success" | "error" | "info" | "warning";
interface ToastItem {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

const ToastContext = createContext<{
  push: (kind: ToastKind, title: string, message?: string) => void;
}>({ push: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const push = useCallback((kind: ToastKind, title: string, message?: string) => {
    const id = Date.now() + Math.random();
    setItems((prev) => [...prev, { id, kind, title, message }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((item) => item.id !== id));
    }, 5200);
  }, []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {items.map((item) => {
          const Icon =
            item.kind === "success"
              ? CheckCircle2
              : item.kind === "error"
                ? XCircle
                : item.kind === "warning"
                  ? AlertTriangle
                  : Info;
          return (
            <div key={item.id} className={`toast toast-${item.kind}`}>
              <Icon size={18} className="toast-icon" />
              <div>
                <strong>{item.title}</strong>
                {item.message && <p>{item.message}</p>}
              </div>
              <button
                className="toast-close"
                onClick={() => setItems((prev) => prev.filter((entry) => entry.id !== item.id))}
                aria-label="Dismiss notification"
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

/* ── Badges / chips ────────────────────────────────────────────────────── */

export function Badge({
  children,
  color = "#94a3b8",
  soft = true,
  title,
}: {
  children: React.ReactNode;
  color?: string;
  soft?: boolean;
  title?: string;
}) {
  return (
    <span
      className="badge"
      title={title}
      style={{
        color,
        borderColor: `${color}55`,
        background: soft ? `${color}18` : "transparent",
      }}
    >
      {children}
    </span>
  );
}

export function OutcomeBadge({ outcome, large = false }: { outcome?: string | null; large?: boolean }) {
  const meta = outcomeMeta(outcome);
  return (
    <span
      className={`outcome-badge ${large ? "outcome-badge-lg" : ""}`}
      style={{ color: meta.color, borderColor: `${meta.color}66`, background: `${meta.color}16` }}
      title={meta.label}
    >
      <span className="outcome-dot" style={{ background: meta.color }} />
      {meta.short}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const meta = STATUS_META[status] || { label: status.toUpperCase(), color: "#94a3b8" };
  return <Badge color={meta.color}>{meta.label}</Badge>;
}

export function HealthBadge({ status }: { status: string }) {
  const color =
    status === "healthy"
      ? "#34d399"
      : status === "degraded"
        ? "#fbbf24"
        : status === "breached"
          ? "#fb7185"
          : "#94a3b8";
  return <Badge color={color}>{status.toUpperCase()}</Badge>;
}

export function Chip({ children, color = "#94a3b8", icon }: { children: React.ReactNode; color?: string; icon?: React.ReactNode }) {
  return (
    <span className="chip" style={{ color, borderColor: `${color}45`, background: `${color}12` }}>
      {icon}
      {children}
    </span>
  );
}

export function ConditionChips({
  flags,
  labels,
  limit = 8,
}: {
  flags?: string[];
  labels?: string[];
  limit?: number;
}) {
  if (!flags || flags.length === 0) {
    return <span className="muted small">No strong structural conditions</span>;
  }
  return (
    <div className="chip-row">
      {flags.slice(0, limit).map((flag, index) => (
        <Chip key={flag} color="#67e8f9">
          {labels?.[index] || CONDITION_LABELS[flag] || flag}
        </Chip>
      ))}
      {flags.length > limit && <Chip color="#94a3b8">+{flags.length - limit} more</Chip>}
    </div>
  );
}

/* ── Layout primitives ─────────────────────────────────────────────────── */

export function Panel({
  children,
  className = "",
  title,
  subtitle,
  actions,
}: {
  children: React.ReactNode;
  className?: string;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p className="muted">{subtitle}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function MetricCard({
  label,
  value,
  sub,
  accent = "#34d399",
  icon,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div className="metric-card" style={{ "--accent": accent } as React.CSSProperties}>
      <div className="metric-top">
        <span>{label}</span>
        {icon && <span className="metric-icon">{icon}</span>}
      </div>
      <strong>{value}</strong>
      {sub && <small>{sub}</small>}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  message,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  message: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-icon">{icon}</div>}
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="spinner-wrap">
      <Loader2 size={16} className="spin" />
      {label && <span>{label}</span>}
    </span>
  );
}

export function Modal({
  open,
  title,
  children,
  onClose,
  footer,
  danger = false,
}: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  footer?: React.ReactNode;
  danger?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" onClick={onClose}>
      <div className={`modal ${danger ? "modal-danger" : ""}`} onClick={(event) => event.stopPropagation()}>
        <header>
          <h3>{title}</h3>
          <button className="icon-btn" onClick={onClose} aria-label="Close dialog">
            <X size={16} />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  );
}

/* ── Layer trace ───────────────────────────────────────────────────────── */

const LAYER_OUTCOME_COLOR: Record<string, string> = {
  blocked: "#38bdf8",
  allowed: "#34d399",
  filtered: "#a78bfa",
  clean: "#34d399",
  refused: "#34d399",
  uncertain: "#fbbf24",
  bypassed: "#fb7185",
  error: "#f97316",
};

export function LayerTrace({ trace, compact = false }: { trace?: LayerTraceType[]; compact?: boolean }) {
  if (!trace || trace.length === 0) {
    return <p className="muted small">No layer trace recorded.</p>;
  }
  return (
    <ol className={`layer-trace ${compact ? "compact" : ""}`}>
      {trace.map((step) => {
        const color = LAYER_OUTCOME_COLOR[step.outcome] || "#94a3b8";
        return (
          <li key={`${step.layer}-${step.name}`} style={{ "--step": color } as React.CSSProperties}>
            <span className="layer-index">L{step.layer}</span>
            <div className="layer-body">
              <div className="layer-line">
                <strong>{step.name}</strong>
                <span className="layer-outcome" style={{ color }}>
                  {step.outcome}
                </span>
              </div>
              <p>{step.detail}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function LayerChips({ layers }: { layers?: string[] }) {
  if (!layers || layers.length === 0) return <span className="muted small">None</span>;
  return (
    <div className="chip-row">
      {layers.map((layer) => (
        <Chip key={layer} color="#fb7185">
          {LAYER_LABELS[layer] || layer}
        </Chip>
      ))}
    </div>
  );
}

export function ScoreRing({ score, size = 96 }: { score: number; size?: number }) {
  const color = score >= 85 ? "#34d399" : score >= 60 ? "#fbbf24" : "#fb7185";
  return (
    <div
      className="score-ring"
      style={
        {
          width: size,
          height: size,
          background: `conic-gradient(${color} ${score * 3.6}deg, rgba(148,163,184,.14) 0deg)`,
        } as React.CSSProperties
      }
    >
      <div className="score-ring-inner">
        <strong style={{ color }}>{Math.round(score)}</strong>
        <span>health</span>
      </div>
    </div>
  );
}

export function Divider() {
  return <div className="divider" />;
}

export function outcomeCounts(summary?: Record<string, number>) {
  const counts = summary || {};
  return {
    blocked: (counts.blocked || 0) + (counts.filtered || 0),
    refused: counts.refused || 0,
    bypassed: (counts.complied || 0) + (counts.bypassed || 0),
    inconclusive:
      (counts.uncertain || 0) +
      (counts.empty || 0) +
      (counts.safe_completion || 0) +
      (counts.error || 0),
  };
}

export function useInterval(callback: () => void, delay: number | null) {
  useEffect(() => {
    if (delay === null) return;
    const id = window.setInterval(callback, delay);
    return () => window.clearInterval(id);
  }, [callback, delay]);
}
