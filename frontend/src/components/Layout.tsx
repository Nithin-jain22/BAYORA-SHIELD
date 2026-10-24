import React from "react";
import {
  Activity,
  BarChart3,
  FileText,
  LockKeyhole,
  Menu,
  Play,
  RefreshCw,
  Shield,
  ShieldCheck,
  Square,
  Swords,
  Wrench,
  X,
} from "lucide-react";
import type { SandboxStatus } from "../types";
import { Badge, ScoreRing } from "./ui";

export type PageKey =
  | "overview"
  | "red"
  | "blue"
  | "repair"
  | "evaluation"
  | "reports"
  | "audit";

export const NAV_ITEMS: Array<{ key: PageKey; label: string; icon: React.ElementType; hint: string }> = [
  { key: "overview", label: "Command center", icon: Activity, hint: "Posture & activity" },
  { key: "red", label: "Red team", icon: Swords, hint: "Attack console" },
  { key: "blue", label: "Blue team", icon: ShieldCheck, hint: "Findings & retest" },
  { key: "repair", label: "Sandbox repair", icon: Wrench, hint: "Manual restoration" },
  { key: "evaluation", label: "Evaluation", icon: BarChart3, hint: "Runs & trends" },
  { key: "reports", label: "Reports", icon: FileText, hint: "Export evidence" },
  { key: "audit", label: "Security audit", icon: LockKeyhole, hint: "Hash-chained log" },
];

export function Layout({
  page,
  onNavigate,
  sandbox,
  healthScore,
  busy,
  onStartSandbox,
  onStopSandbox,
  children,
}: {
  page: PageKey;
  onNavigate: (page: PageKey) => void;
  sandbox: SandboxStatus | null;
  healthScore: number | null;
  busy: boolean;
  onStartSandbox: () => void;
  onStopSandbox: () => void;
  children: React.ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const active = NAV_ITEMS.find((item) => item.key === page);
  const running = Boolean(sandbox?.running || sandbox?.listening);

  const navigate = (key: PageKey) => {
    onNavigate(key);
    setMobileOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark">
            <Shield size={22} />
          </div>
          <div>
            <div className="brand-name">
              BAYORA<span>-SHIELD</span>
            </div>
            <div className="brand-tag">Secure the environment. Trust the evaluation.</div>
          </div>
          <button className="icon-btn mobile-close" onClick={() => setMobileOpen(false)} aria-label="Close menu">
            <X size={16} />
          </button>
        </div>

        <div className="sandbox-card">
          <div className="sandbox-head">
            <span className={`status-dot ${running ? "live" : "dead"}`} />
            <div>
              <strong>{running ? "Sandbox online" : "Sandbox offline"}</strong>
              <small>
                {running
                  ? `${sandbox?.backend || "process"} · port ${sandbox?.port || 11435}`
                  : "Start before running attacks"}
              </small>
            </div>
            {healthScore !== null && <ScoreRing score={healthScore} size={46} />}
          </div>
          <div className="sandbox-actions">
            {running ? (
              <button className="btn btn-ghost btn-sm" onClick={onStopSandbox} disabled={busy}>
                <Square size={13} /> Stop
              </button>
            ) : (
              <button className="btn btn-primary btn-sm" onClick={onStartSandbox} disabled={busy}>
                <Play size={13} /> Start sandbox
              </button>
            )}
            <button className="btn btn-ghost btn-sm" onClick={() => navigate("repair")}>
              <Wrench size={13} /> Repair
            </button>
          </div>
        </div>

        <nav className="nav">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                className={`nav-item ${page === item.key ? "active" : ""}`}
                onClick={() => navigate(item.key)}
              >
                <Icon size={17} />
                <span>
                  <strong>{item.label}</strong>
                  <small>{item.hint}</small>
                </span>
              </button>
            );
          })}
        </nav>

        <footer className="sidebar-foot">
          <div className="foot-row">
            <Badge color="#34d399">AUDIT CHAIN</Badge>
            <span className="muted small">SHA-256</span>
          </div>
          <p>Red and blue workspaces are isolated. Bypasses are released as sanitised evidence only.</p>
        </footer>
      </aside>

      <div className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setMobileOpen(true)} aria-label="Open menu">
            <Menu size={18} />
          </button>
          <div className="topbar-title">
            <span className="eyebrow">Workspace</span>
            <h1>{active?.label}</h1>
          </div>
          <div className="topbar-right">
            <span className={`live-pill ${running ? "online" : "offline"}`}>
              <span className="status-dot" />
              {running ? "Model reachable" : "Model offline"}
            </span>
            <button
              className="icon-btn"
              onClick={() => window.location.reload()}
              title="Reload workspace"
              aria-label="Reload workspace"
            >
              <RefreshCw size={16} />
            </button>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
