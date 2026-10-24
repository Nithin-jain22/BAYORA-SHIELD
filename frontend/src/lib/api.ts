const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let payload: any = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  if (!response.ok) {
    const detail =
      (payload && typeof payload === "object" && (payload.detail || payload.message)) ||
      (typeof payload === "string" && payload) ||
      `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}

export const api = {
  health: () => request<any>("/api/health"),
  overview: () => request<any>("/api/overview"),

  sandboxStatus: () => request<any>("/api/sandbox/status"),
  sandboxStart: () => request<any>("/api/sandbox/start", { method: "POST" }),
  sandboxStop: () => request<any>("/api/sandbox/stop", { method: "POST" }),
  sandboxHealth: () => request<any>("/api/sandbox/health?audit=false"),
  sandboxActions: () => request<any>("/api/sandbox/actions"),
  sandboxRepair: (body: { action: string; confirm?: boolean; note?: string; operator?: string }) =>
    request<any>("/api/sandbox/repair", { method: "POST", body: JSON.stringify(body) }),

  createRedSession: (operator: string) =>
    request<any>("/api/red/session", { method: "POST", body: JSON.stringify({ operator }) }),
  redExamples: () => request<any>("/api/red/examples"),
  redHistory: (sessionId: string) =>
    request<any>(`/api/red/history?session_id=${encodeURIComponent(sessionId)}`),
  redAttack: (body: { session_id: string; prompt: string; attack_name: string; attack_type: string }) =>
    request<any>("/api/red/attack", { method: "POST", body: JSON.stringify(body) }),
  redClear: (sessionId: string) =>
    request<any>("/api/red/clear", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId }),
    }),

  createBlueSession: (operator: string) =>
    request<any>("/api/blue/session", { method: "POST", body: JSON.stringify({ operator }) }),
  blueEvidence: (sessionId: string, status?: string) =>
    request<any>(
      `/api/blue/evidence?session_id=${encodeURIComponent(sessionId)}${
        status ? `&status=${encodeURIComponent(status)}` : ""
      }`,
    ),
  blueAnalyze: (body: {
    session_id: string;
    evidence_id: string;
    root_cause: string;
    severity: string;
    recommended_fix: string;
  }) => request<any>("/api/blue/analyze", { method: "POST", body: JSON.stringify(body) }),
  blueFix: (body: {
    session_id: string;
    evidence_id: string;
    update_type: string;
    description: string;
  }) => request<any>("/api/blue/fix", { method: "POST", body: JSON.stringify(body) }),
  blueRetest: (body: { session_id: string; evidence_id: string }) =>
    request<any>("/api/blue/retest", { method: "POST", body: JSON.stringify(body) }),
  blueDefense: () => request<any>("/api/blue/defense"),

  evaluation: () => request<any>("/api/evaluation"),
  snapshot: (body: { session_id?: string; defense_version?: string }) =>
    request<any>("/api/evaluation/snapshot", { method: "POST", body: JSON.stringify(body) }),

  auditEvents: (params: { event_type?: string; actor?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.event_type) query.set("event_type", params.event_type);
    if (params.actor) query.set("actor", params.actor);
    query.set("limit", String(params.limit ?? 250));
    return request<any>(`/api/audit/events?${query.toString()}`);
  },

  journalSummary: () => request<any>("/api/journal/summary"),
  journalConditions: () => request<any>("/api/journal/conditions"),

  reports: () => request<any>("/api/reports"),
  generateReport: (body: {
    scope: string;
    session_id?: string;
    evidence_id?: string;
    generated_by?: string;
  }) => request<any>("/api/reports/generate", { method: "POST", body: JSON.stringify(body) }),
  reportMeta: (id: string) => request<any>(`/api/reports/${encodeURIComponent(id)}`),
  reportDownloadUrl: (id: string, format: string) =>
    `${API_BASE}/api/reports/${encodeURIComponent(id)}/download/${format}`,
};
