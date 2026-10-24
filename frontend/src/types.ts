export type Outcome =
  | "blocked"
  | "filtered"
  | "refused"
  | "complied"
  | "uncertain"
  | "empty"
  | "safe_completion"
  | "error"
  | "bypassed";

export interface Assessment {
  outcome: string;
  reason: string;
  refusal_score: number;
  compliance_score: number;
  leaked_prompt: boolean;
  harmful_compliance: boolean;
  persona_adopted: boolean;
  signals: string[];
  excerpt: string;
  review_required?: boolean;
}

export interface Conditions {
  flags: string[];
  labels: string[];
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  length: number;
  word_count: number;
  lines: number;
  special_char_ratio: number;
  language: string;
  summary: string;
}

export interface LayerTrace {
  layer: number;
  name: string;
  outcome: string;
  detail: string;
}

export interface Attack {
  id: string;
  timestamp: number;
  timestamp_iso?: string;
  timestamp_local?: string;
  attack_name: string;
  attack_type: string;
  prompt: string;
  blocked: boolean;
  blocked_by?: string | null;
  llm_response?: string | null;
  raw_response?: string | null;
  layers_bypassed: string[];
  layer_trace: LayerTrace[];
  ml_confidence: number;
  outcome: Outcome;
  assessment?: Assessment | null;
  conditions?: Conditions | null;
  defended: boolean;
  bypassed: boolean;
  inconclusive: boolean;
  containment_layer?: string | null;
  journal_id?: string | null;
  evidence_id?: string | null;
  first_failed_layer?: number | null;
  breach_path?: string;
}

export interface RedStats {
  operator: string;
  session_id: string;
  total_attacks: number;
  blocked: number;
  refused: number;
  defended: number;
  bypassed: number;
  inconclusive: number;
  no_signal?: number;
  bypass_rate: number;
  defense_rate: number;
}

export interface Evidence {
  evidence_id: string;
  timestamp: number;
  timestamp_iso: string;
  timestamp_local: string;
  attack_name: string;
  attack_type: string;
  status: string;
  severity?: string | null;
  outcome: string;
  assessment?: Assessment | null;
  conditions?: Conditions | null;
  journal_id?: string | null;
  operator?: string | null;
  prompt_hash: string;
  prompt_length: number;
  word_count: number;
  redacted_prompt: string;
  signals: string[];
  signal_labels: string[];
  defence_hints: string[];
  layers_bypassed: string[];
  layer_labels: string[];
  response_excerpt: string;
  root_cause?: string | null;
  recommended_fix?: string | null;
  defense_update?: string | null;
  retest_result?: Record<string, any> | null;
  retest_at?: number | null;
  analysis_at?: number | null;
}

export interface BlueStats {
  operator: string;
  session_id: string;
  total_evidence: number;
  pending: number;
  fixed: number;
  still_vulnerable: number;
  inconclusive: number;
  evidence_analyzed: number;
}

export interface HealthLayer {
  id: string;
  name: string;
  status: "healthy" | "degraded" | "breached" | "unknown";
  detail: string;
  recommendation: string;
  critical: boolean;
}

export interface SandboxHealth {
  timestamp: number;
  timestamp_iso: string;
  timestamp_local: string;
  score: number;
  damage_score: number;
  max_damage: number;
  status: "healthy" | "warning" | "critical";
  breached_layers: string[];
  degraded_layers: string[];
  layers: HealthLayer[];
  sandbox: Record<string, any>;
  port: { listening: boolean; addresses: string[]; detail: string };
  audit_chain: { valid: boolean; broken_at: number | null };
  defence_store: { valid: boolean; detail: string; invalid: string[] };
}

export interface SandboxStatus {
  running: boolean;
  backend?: string | null;
  model: string;
  port: number;
  docker_available?: boolean;
  docker_message?: string;
  fallback_reason?: string | null;
  listening?: boolean;
}

export interface JournalSummary {
  total: number;
  outcomes: Record<string, number>;
  attack_types: Record<string, number>;
  layer_breaches: Record<string, number>;
  by_type: Record<string, { total: number; bypassed: number; defended: number; inconclusive: number }>;
  conditions: { counts: Record<string, number>; bypass_counts: Record<string, number> };
  timeline: Array<{ date: string; total: number; bypassed: number; defended: number; inconclusive: number }>;
  bypass_rate: number;
}

export interface EvaluationRun {
  run_id: string;
  timestamp: string;
  model: string;
  total_attacks: number;
  blocked: number;
  bypassed: number;
  block_rate: number;
  bypass_rate: number;
  refused: number;
  inconclusive: number;
  outcome_breakdown: Record<string, number>;
  per_type_breakdown: Record<
    string,
    { total: number; blocked: number; refused?: number; bypassed: number; inconclusive?: number }
  >;
  defense_version: string;
  session_id?: string | null;
}

export interface AuditEvent {
  timestamp: number;
  timestamp_iso: string;
  timestamp_local?: string;
  event_type: string;
  actor: string;
  session_id?: string | null;
  details: Record<string, any>;
  previous_hash: string;
  hash: string;
}

export interface ReportMeta {
  report_id: string;
  generated_at: number;
  generated_at_iso: string;
  generated_at_local: string;
  scope: string;
  session_id?: string | null;
  evidence_id?: string | null;
  generated_by: string;
  summary: {
    total_attacks: number;
    confirmed_bypasses: number;
    defended: number;
    inconclusive: number;
    bypass_rate: number;
    defence_rate: number;
    retests: number;
    findings_released: number;
    findings_fixed: number;
    findings_still_vulnerable: number;
  };
  pdf_error?: string | null;
  formats: string[];
}

export interface OverviewData {
  summary: JournalSummary;
  journal_total: number;
  recent_attacks: Attack[];
  evidence: { total: number; pending: number; fixed: number; vulnerable: number };
  sandbox: SandboxStatus;
  defense: Record<string, number>;
  audit: { valid: boolean; broken_at: number | null };
  evaluation: Array<Record<string, any>>;
}
