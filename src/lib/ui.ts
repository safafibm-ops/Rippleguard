import type { NodeMetrics } from "../types";

export const RISK_COLORS: Record<NodeMetrics["riskLevel"], { bg: string; text: string; ring: string; dot: string; bar: string; border: string }> = {
  Critical: { 
    bg: "bg-rose-500/15", 
    text: "text-rose-400", 
    ring: "ring-rose-500/40", 
    dot: "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]", 
    bar: "bg-gradient-to-r from-rose-600 to-rose-400",
    border: "border-rose-500/30"
  },
  High: { 
    bg: "bg-orange-500/15", 
    text: "text-orange-400", 
    ring: "ring-orange-500/40", 
    dot: "bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]", 
    bar: "bg-gradient-to-r from-orange-600 to-orange-400",
    border: "border-orange-500/30"
  },
  Medium: { 
    bg: "bg-amber-400/15", 
    text: "text-amber-300", 
    ring: "ring-amber-400/40", 
    dot: "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]", 
    bar: "bg-gradient-to-r from-amber-600 to-amber-400",
    border: "border-amber-400/30"
  },
  Low: { 
    bg: "bg-emerald-500/15", 
    text: "text-emerald-400", 
    ring: "ring-emerald-500/40", 
    dot: "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]", 
    bar: "bg-gradient-to-r from-emerald-600 to-emerald-400",
    border: "border-emerald-500/30"
  },
};

export const ECOSYSTEM_COLORS: Record<string, string> = {
  npm: "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]",
  pypi: "bg-sky-500 shadow-[0_0_6px_rgba(14,165,233,0.5)]",
  maven: "bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.5)]",
  cargo: "bg-orange-600 shadow-[0_0_6px_rgba(234,88,12,0.5)]",
  go: "bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.5)]",
  docker: "bg-indigo-400 shadow-[0_0_6px_rgba(129,140,248,0.5)]",
};

export function formatCompact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${n}`;
}

export function formatPercent(v: number): string {
  return `${Math.round(v)}%`;
}

export function riskFromScore(score: number): NodeMetrics["riskLevel"] {
  return score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";
}

