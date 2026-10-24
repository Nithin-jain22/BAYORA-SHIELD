import type { Outcome } from "../types";

export function formatLocal(timestamp?: number | string | null): string {
  if (timestamp === undefined || timestamp === null || timestamp === "") return "—";
  let date: Date;
  if (typeof timestamp === "number") {
    date = new Date(timestamp * 1000);
  } else if (/^\d+(\.\d+)?$/.test(timestamp)) {
    date = new Date(Number(timestamp) * 1000);
  } else {
    date = new Date(timestamp);
  }
  if (Number.isNaN(date.getTime())) return String(timestamp);
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

export function relativeTime(timestamp?: number | null): string {
  if (!timestamp) return "—";
  const seconds = Math.round(Date.now() / 1000 - timestamp);
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

export const OUTCOME_META: Record<
  Outcome | string,
  { label: string; short: string; color: string; tone: string }
> = {
  blocked: { label: "Blocked by layer", short: "BLOCKED", color: "#38bdf8", tone: "info" },
  filtered: { label: "Output filtered", short: "FILTERED", color: "#a78bfa", tone: "info" },
  refused: { label: "Model refused", short: "REFUSED", color: "#34d399", tone: "good" },
  complied: { label: "Confirmed bypass", short: "BYPASSED", color: "#fb7185", tone: "bad" },
  bypassed: { label: "Confirmed bypass", short: "BYPASSED", color: "#fb7185", tone: "bad" },
  uncertain: { label: "Inconclusive", short: "REVIEW", color: "#fbbf24", tone: "warn" },
  empty: { label: "Empty response", short: "EMPTY", color: "#94a3b8", tone: "muted" },
  safe_completion: { label: "No attack signal", short: "NO SIGNAL", color: "#94a3b8", tone: "muted" },
  error: { label: "Pipeline error", short: "ERROR", color: "#f97316", tone: "warn" },
};

export function outcomeMeta(outcome?: string | null) {
  return OUTCOME_META[outcome || ""] || OUTCOME_META.uncertain;
}

export const LAYER_LABELS: Record<string, string> = {
  layer_1_rules: "L1 · Rule filter",
  layer_2_ml: "L2 · ML classifier",
  layer_3_hardened_prompt: "L3 · Hardened prompt",
  layer_4_output_filter: "L4 · Output filter",
};

export const CONDITION_LABELS: Record<string, string> = {
  instruction_override: "Instruction override",
  prompt_extraction: "Prompt extraction",
  role_play: "Role / persona",
  policy_bypass: "Policy bypass",
  indirect_injection: "Indirect injection",
  authority_framing: "Authority framing",
  urgency_pressure: "Urgency pressure",
  hypothetical_framing: "Hypothetical framing",
  harmful_request: "Harmful intent",
  delimiter_injection: "Delimiter injection",
  encoding_obfuscation: "Encoding / obfuscation",
  unicode_trickery: "Unicode trickery",
  excessive_length: "Excessive length",
  repetition: "Repetition",
  non_ascii: "Non-ASCII",
  base64_like: "Base64-like",
};

export const STATUS_META: Record<string, { label: string; color: string }> = {
  new: { label: "NEW", color: "#a78bfa" },
  analyzed: { label: "ANALYZED", color: "#38bdf8" },
  fix_applied: { label: "FIX APPLIED", color: "#fbbf24" },
  retested_fixed: { label: "FIXED", color: "#34d399" },
  retested_vulnerable: { label: "STILL VULNERABLE", color: "#fb7185" },
  retested_inconclusive: { label: "INCONCLUSIVE", color: "#fbbf24" },
};

export function severityColor(severity?: string | null): string {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "#fb7185";
    case "high":
      return "#fb923c";
    case "medium":
      return "#fbbf24";
    case "low":
      return "#34d399";
    default:
      return "#94a3b8";
  }
}

export function riskColor(risk?: string | null): string {
  switch ((risk || "").toLowerCase()) {
    case "critical":
      return "#fb7185";
    case "high":
      return "#fb923c";
    case "medium":
      return "#fbbf24";
    default:
      return "#34d399";
  }
}

export function truncate(text?: string | null, limit = 220): string {
  if (!text) return "—";
  return text.length > limit ? `${text.slice(0, limit).trim()} …` : text;
}

export function hasText(value?: string | null): boolean {
  return Boolean(value && value.trim() && value.trim() !== "—");
}
