import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { api } from "./lib/api";
import { Layout, type PageKey } from "./components/Layout";
import { ToastProvider, useToast } from "./components/ui";
import { OverviewPage } from "./pages/Overview";
import { RedTeamPage } from "./pages/RedTeam";
import { BlueTeamPage } from "./pages/BlueTeam";
import { RepairPage } from "./pages/Repair";
import { EvaluationPage } from "./pages/Evaluation";
import { ReportsPage } from "./pages/Reports";
import { AuditPage } from "./pages/Audit";
import type { SandboxStatus } from "./types";

interface Session {
  session_id: string;
  operator: string;
}

const STORAGE_RED = "bayora.red.session";
const STORAGE_BLUE = "bayora.blue.session";
const STORAGE_PAGE = "bayora.page";

function readSession(key: string): Session | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

function AppShell() {
  const toast = useToast();
  const [page, setPage] = useState<PageKey>(() => {
    const stored = localStorage.getItem(STORAGE_PAGE) as PageKey | null;
    return stored || "overview";
  });
  const [redSession, setRedSession] = useState<Session | null>(() => readSession(STORAGE_RED));
  const [blueSession, setBlueSession] = useState<Session | null>(() => readSession(STORAGE_BLUE));
  const [sandbox, setSandbox] = useState<SandboxStatus | null>(null);
  const [healthScore, setHealthScore] = useState<number | null>(null);
  const [sandboxBusy, setSandboxBusy] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const navigate = useCallback((next: PageKey) => {
    setPage(next);
    localStorage.setItem(STORAGE_PAGE, next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const loadSandbox = useCallback(async () => {
    try {
      const status = await api.sandboxStatus();
      setSandbox(status);
      setConnectionError(null);
    } catch (err) {
      setConnectionError(err instanceof Error ? err.message : "API unavailable");
    }
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      const health = await api.sandboxHealth();
      setHealthScore(health?.score ?? null);
    } catch {
      setHealthScore(null);
    }
  }, []);

  useEffect(() => {
    loadSandbox();
    loadHealth();
    const statusTimer = window.setInterval(loadSandbox, 15000);
    const healthTimer = window.setInterval(loadHealth, 45000);
    return () => {
      window.clearInterval(statusTimer);
      window.clearInterval(healthTimer);
    };
  }, [loadSandbox, loadHealth]);

  const startSandbox = async () => {
    setSandboxBusy(true);
    try {
      const status = await api.sandboxStart();
      setSandbox(status);
      toast.push("success", "Sandbox started", `${status.backend || "process"} backend is ready.`);
      await loadHealth();
    } catch (err) {
      toast.push(
        "error",
        "Could not start sandbox",
        err instanceof Error ? err.message : "Check that Ollama or Docker is available.",
      );
    } finally {
      setSandboxBusy(false);
    }
  };

  const stopSandbox = async () => {
    setSandboxBusy(true);
    try {
      const status = await api.sandboxStop();
      setSandbox(status);
      toast.push("info", "Sandbox stopped");
      await loadHealth();
    } catch (err) {
      toast.push("error", "Could not stop sandbox", err instanceof Error ? err.message : undefined);
    } finally {
      setSandboxBusy(false);
    }
  };

  const joinRed = async (operator: string) => {
    const session = await api.createRedSession(operator);
    setRedSession(session);
    localStorage.setItem(STORAGE_RED, JSON.stringify(session));
  };

  const joinBlue = async (operator: string) => {
    const session = await api.createBlueSession(operator);
    setBlueSession(session);
    localStorage.setItem(STORAGE_BLUE, JSON.stringify(session));
  };

  return (
    <Layout
      page={page}
      onNavigate={navigate}
      sandbox={sandbox}
      healthScore={healthScore}
      busy={sandboxBusy}
      onStartSandbox={startSandbox}
      onStopSandbox={stopSandbox}
    >
      {connectionError && (
        <div className="connection-banner">
          <AlertTriangle size={16} />
          <div>
            <strong>Backend not reachable.</strong>
            <span> {connectionError}. Start it with `./scripts/start.sh` or `uvicorn src.api.server:app`.</span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={() => { loadSandbox(); loadHealth(); }}>
            <RefreshCw size={13} /> Retry
          </button>
        </div>
      )}
      {page === "overview" && (
        <OverviewPage onNavigate={navigate} onStartSandbox={startSandbox} sandboxBusy={sandboxBusy} />
      )}
      {page === "red" && (
        <RedTeamPage
          session={redSession}
          onJoin={joinRed}
          onClearSession={() => {
            setRedSession(null);
            localStorage.removeItem(STORAGE_RED);
          }}
        />
      )}
      {page === "blue" && (
        <BlueTeamPage
          session={blueSession}
          onJoin={joinBlue}
          onClearSession={() => {
            setBlueSession(null);
            localStorage.removeItem(STORAGE_BLUE);
          }}
        />
      )}
      {page === "repair" && <RepairPage />}
      {page === "evaluation" && <EvaluationPage redSession={redSession} />}
      {page === "reports" && <ReportsPage redSession={redSession} />}
      {page === "audit" && <AuditPage />}
    </Layout>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AppShell />
    </ToastProvider>
  );
}
