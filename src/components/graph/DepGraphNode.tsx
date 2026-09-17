import { Handle, Position } from "@xyflow/react";
import type { DepNode, NodeMetrics } from "../../types";
import { ECOSYSTEM_COLORS, RISK_COLORS } from "../../lib/ui";

export interface DepGraphNodeData {
  node: DepNode;
  metrics: NodeMetrics | undefined;
  visualState: "normal" | "compromised" | "affected" | "dim" | "selected" | "path";
  infectionProbability?: number;
  [key: string]: unknown;
}

const TIER_LABEL: Record<number, string> = {
  0: "Application",
  1: "Framework / SDK",
  2: "Shared Utility",
  3: "Deep Dependency",
  4: "Root Dependency",
};

export default function DepGraphNode({ data }: { data: DepGraphNodeData }) {
  const { node, metrics, visualState, infectionProbability } = data;
  const risk = metrics ? RISK_COLORS[metrics.riskLevel] : RISK_COLORS.Low;
  const dimmed = visualState === "dim";

  const ring =
    visualState === "compromised"
      ? "ring-2 ring-rose-500 shadow-[0_0_20px_rgba(244,63,94,0.4)] animate-pulse border-rose-500/80 bg-rose-950/40"
      : visualState === "affected"
        ? "ring-2 ring-orange-500/70 shadow-[0_0_14px_rgba(249,115,22,0.3)] border-orange-500/50 bg-orange-950/30"
        : visualState === "path"
          ? "ring-2 ring-indigo-500/70 border-indigo-500/60 bg-indigo-950/30"
          : visualState === "selected"
            ? "ring-2 ring-indigo-500 shadow-[0_0_12px_rgba(99,102,241,0.3)] border-indigo-400 bg-[#1e2230]"
            : "border-white/[0.08] bg-[#161820] hover:border-white/20";

  return (
    <div
      className={`group relative w-[172px] rounded-xl border px-3 py-2.5 shadow-md backdrop-blur-sm transition-all duration-200 ${ring} ${dimmed ? "opacity-25" : "opacity-100"}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-zinc-500 !h-2 !w-2 !border-0" />
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 shrink-0 rounded-full ${ECOSYSTEM_COLORS[node.ecosystem]}`} />
        <span className="truncate text-xs font-semibold text-zinc-100">{node.name}</span>
      </div>
      <div className="mt-1 text-[9px] font-semibold uppercase tracking-wider text-zinc-400">{TIER_LABEL[node.tier]}</div>
      <div className="mt-2 flex items-center justify-between">
        {node.kind === "package" && metrics ? (
          <span className={`rounded-md px-1.5 py-0.5 font-mono text-[9.5px] font-bold border border-white/5 ${risk.bg} ${risk.text}`}>
            {metrics.riskLevel} · {Math.round(metrics.criticality)}
          </span>
        ) : (
          <span className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[9.5px] font-bold text-indigo-300">
            App
          </span>
        )}
        {typeof infectionProbability === "number" && (
          <span className="font-mono text-[10px] font-bold text-rose-400">{Math.round(infectionProbability * 100)}%</span>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-zinc-500 !h-2 !w-2 !border-0" />
    </div>
  );
}

