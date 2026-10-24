import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Filter,
  Hash,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";
import { api } from "../lib/api";
import { formatLocal, relativeTime } from "../lib/format";
import type { AuditEvent } from "../types";
import {
  Badge,
  EmptyState,
  MetricCard,
  Modal,
  Panel,
  Spinner,
  useToast,
} from "../components/ui";

const EVENT_COLORS: Record<string, string> = {
  attack_submitted: "#67e8f9",
  defense_blocked: "#38bdf8",
  defense_passed: "#94a3b8",
  output_filtered: "#a78bfa",
  response_assessed: "#34d399",
  layer_breach: "#fb7185",
  condition_snapshot: "#fbbf24",
  blue_team_update: "#fbbf24",
  evidence_released: "#fb923c",
  evidence_retired: "#fbbf24",
  sandbox_start: "#34d399",
  sandbox_stop: "#94a3b8",
  sandbox_integrity: "#67e8f9",
  sandbox_repair: "#a78bfa",
  report_generated: "#34d399",
  auth_success: "#34d399",
  auth_failure: "#fb7185",
  violation_detected: "#fb7185",
  llm_query: "#64748b",
  llm_response: "#64748b",
};

export function AuditPage() {
  const toast = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const [audit, setAudit] = useState<{ valid: boolean; broken_at: number | null } | null>(null);
  const [eventType, setEventType] = useState("all");
  const [actor, setActor] = useState("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.auditEvents({ event_type: eventType, actor, limit: 400 });
      setEvents(payload.events || []);
      setTotal(payload.total || 0);
      setAudit(payload.audit || null);
      setEventTypes(payload.event_types || []);
    } catch (err) {
      toast.push("error", "Could not load audit log", err instanceof Error ? err.message : undefined);
    } finally {
      setLoading(false);
    }
  }, [eventType, actor, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return events;
    return events.filter((event) => {
      const haystack = `${event.event_type} ${event.actor} ${event.session_id || ""} ${JSON.stringify(event.details)}`.toLowerCase();
      return haystack.includes(needle);
    });
  }, [events, query]);

  const actors = ["all", "red_team", "blue_team", "system"];
  const breaches = events.filter((event) => event.event_type === "layer_breach").length;
  const violations = events.filter((event) => event.event_type === "violation_detected").length;

  return (
    <div className="page-stack">
      <section className={`chain-banner ${audit?.valid ? "good" : "bad"}`}>
        <div className="chain-icon">
          {audit?.valid ? <CheckCircle2 size={24} /> : <AlertTriangle size={24} />}
        </div>
        <div>
          <span className="eyebrow">SHA-256 hash chain</span>
          <h2>{audit?.valid ? "Audit log intact" : "Chain integrity failure"}</h2>
          <p>
            {audit?.valid
              ? "Every entry links to the previous hash. No tampering detected."
              : `The chain breaks at line ${audit?.broken_at}. Preserve the file for forensics before rotating.`}
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? "spin" : ""} /> Verify again
        </button>
      </section>

      <section className="metric-grid four">
        <MetricCard label="Total events" value={total} sub="security-relevant actions" accent="#67e8f9" icon={<Hash size={17} />} />
        <MetricCard label="Events loaded" value={events.length} sub="most recent first" accent="#a78bfa" icon={<Clock3 size={17} />} />
        <MetricCard label="Layer breaches" value={breaches} sub="confirmed bypass paths" accent="#fb7185" icon={<AlertTriangle size={17} />} />
        <MetricCard label="Violations" value={violations} sub="gateway / control-char events" accent="#fbbf24" icon={<ShieldCheck size={17} />} />
      </section>

      <Panel
        title="Event explorer"
        subtitle="Times are rendered in your local timezone; the canonical UTC timestamp is preserved on every entry"
        actions={
          <div className="audit-filters">
            <div className="search-box">
              <Search size={14} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search details, sessions, hashes…" />
            </div>
          </div>
        }
      >
        <div className="filter-row">
          <label className="inline-select">
            <Filter size={13} />
            <select className="select" value={eventType} onChange={(event) => setEventType(event.target.value)}>
              <option value="all">All event types</option>
              {eventTypes.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}
            </select>
          </label>
          <label className="inline-select">
            <ShieldCheck size={13} />
            <select className="select" value={actor} onChange={(event) => setActor(event.target.value)}>
              {actors.map((value) => <option key={value} value={value}>{value === "all" ? "All actors" : value}</option>)}
            </select>
          </label>
          <span className="muted small">{filtered.length} event(s) shown</span>
        </div>

        {loading ? (
          <Spinner label="Reading hash-chained log…" />
        ) : filtered.length === 0 ? (
          <EmptyState icon={<Search size={22} />} title="No events match" message="Adjust the event type, actor or search query." />
        ) : (
          <div className="event-table">
            <div className="event-row event-head">
              <span>Time</span>
              <span>Event</span>
              <span>Actor</span>
              <span>Session</span>
              <span>Details</span>
              <span>Hash</span>
            </div>
            {filtered.map((event) => (
              <button
                key={`${event.timestamp}-${event.hash}`}
                className="event-row"
                onClick={() => setSelected(event)}
              >
                <span title={event.timestamp_iso}>{formatLocal(event.timestamp)}</span>
                <span>
                  <Badge color={EVENT_COLORS[event.event_type] || "#94a3b8"}>
                    {event.event_type.replaceAll("_", " ")}
                  </Badge>
                </span>
                <span className="mono small">{event.actor}</span>
                <span className="mono small">{event.session_id ? event.session_id.slice(0, 8) : "—"}</span>
                <span className="event-detail">{summarise(event.details)}</span>
                <span className="mono small">{event.hash.slice(0, 10)}…</span>
              </button>
            ))}
          </div>
        )}
      </Panel>

      <Modal open={Boolean(selected)} title={selected ? selected.event_type.replaceAll("_", " ") : "Event"} onClose={() => setSelected(null)}>
        {selected && (
          <div className="event-detail-view">
            <div className="detail-grid">
              <div><span className="block-label">Local time</span><strong>{formatLocal(selected.timestamp)}</strong></div>
              <div><span className="block-label">UTC</span><strong className="mono small">{selected.timestamp_iso}</strong></div>
              <div><span className="block-label">Actor</span><strong>{selected.actor}</strong></div>
              <div><span className="block-label">Session</span><strong className="mono small">{selected.session_id || "—"}</strong></div>
              <div><span className="block-label">Relative</span><strong>{relativeTime(selected.timestamp)}</strong></div>
              <div><span className="block-label">Event type</span><Badge color={EVENT_COLORS[selected.event_type] || "#94a3b8"}>{selected.event_type}</Badge></div>
            </div>
            <span className="block-label">Details</span>
            <pre className="json-block">{JSON.stringify(selected.details, null, 2)}</pre>
            <span className="block-label">Chain</span>
            <div className="hash-row">
              <span>previous</span>
              <code>{selected.previous_hash}</code>
            </div>
            <div className="hash-row">
              <span>hash</span>
              <code>{selected.hash}</code>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

function summarise(details: Record<string, any>): string {
  if (!details) return "—";
  const parts: string[] = [];
  if (details.reason) parts.push(String(details.reason));
  if (details.outcome) parts.push(`outcome=${details.outcome}`);
  if (details.layer) parts.push(`layer=${details.layer}`);
  if (details.action) parts.push(String(details.action));
  if (details.report_id) parts.push(String(details.report_id));
  if (details.evidence_id) parts.push(`evidence=${details.evidence_id}`);
  if (details.fixed !== undefined) parts.push(`fixed=${details.fixed}`);
  if (parts.length === 0) {
    const text = JSON.stringify(details);
    return text.length > 90 ? `${text.slice(0, 90)}…` : text;
  }
  return parts.join(" · ");
}
