import { useMemo, useState } from "react";
import type { DepEdge, DepNode } from "../types";
import type { EcosystemMetrics } from "../lib/graph";
import DependencyGraph, { type GraphFilters } from "./graph/DependencyGraph";
import NodeDetailPanel from "./NodeDetailPanel";
import { ECOSYSTEM_COLORS, RISK_COLORS } from "../lib/ui";

interface Props {
  nodes: DepNode[];
  edges: DepEdge[];
  nodeById: Map<string, DepNode>;
  metrics: EcosystemMetrics;
  selectedNodeId: string | null;
  setSelectedNodeId: (id: string | null) => void;
  onSimulate: (id: string) => void;
}

const ECOSYSTEMS = ["all", "npm", "pypi", "maven", "cargo", "go", "docker"];
const RISK_LEVELS = ["all", "Critical", "High", "Medium", "Low"];

export default function GraphTab({ nodes, edges, nodeById, metrics, selectedNodeId, setSelectedNodeId, onSimulate }: Props) {
  const [filters, setFilters] = useState<GraphFilters>({ text: "", ecosystem: "all", risk: "all" });

  const selected = selectedNodeId ? nodeById.get(selectedNodeId) : undefined;
  const selectedMetrics = selectedNodeId ? metrics.byId.get(selectedNodeId) : undefined;

  const counts = useMemo(() => {
    const c: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const n of nodes) {
      if (n.kind !== "package") continue;
      const m = metrics.byId.get(n.id);
      if (m) c[m.riskLevel]++;
    }
    return c;
  }, [nodes, metrics]);

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_360px]">
      <div className="space-y-3.5">
        <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-white/[0.08] bg-[#14161d] p-3.5 shadow-sm">
          <div className="relative min-w-[220px] flex-1">
            <svg className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              value={filters.text}
              onChange={(e) => setFilters((f) => ({ ...f, text: e.target.value }))}
              placeholder="Filter packages or applications…"
              className="w-full rounded-xl border border-white/10 bg-[#0d0e12] pl-9 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 outline-none transition-all focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            />
          </div>
          <select
            value={filters.ecosystem}
            onChange={(e) => setFilters((f) => ({ ...f, ecosystem: e.target.value }))}
            className="rounded-xl border border-white/10 bg-[#0d0e12] px-3 py-1.5 text-xs text-zinc-300 outline-none transition-all focus:border-indigo-500"
          >
            {ECOSYSTEMS.map((e) => (
              <option key={e} value={e} className="bg-[#14161d] text-zinc-200">
                {e === "all" ? "All Ecosystems" : e}
              </option>
            ))}
          </select>
          <select
            value={filters.risk}
            onChange={(e) => setFilters((f) => ({ ...f, risk: e.target.value }))}
            className="rounded-xl border border-white/10 bg-[#0d0e12] px-3 py-1.5 text-xs text-zinc-300 outline-none transition-all focus:border-indigo-500"
          >
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r} className="bg-[#14161d] text-zinc-200">
                {r === "all" ? "All Risk Levels" : `${r} Risk`}
              </option>
            ))}
          </select>
          <div className="ml-auto flex flex-wrap items-center gap-3 text-[11px] font-medium text-zinc-400">
            {(["Critical", "High", "Medium", "Low"] as const).map((r) => (
              <span key={r} className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${RISK_COLORS[r].dot}`} />
                {r} <span className="font-mono text-zinc-500">({counts[r]})</span>
              </span>
            ))}
          </div>
        </div>

        <DependencyGraph
          nodes={nodes}
          edges={edges}
          metrics={metrics}
          selectedNodeId={selectedNodeId}
          onSelect={setSelectedNodeId}
          mode="risk"
          filters={filters}
          height="620px"
        />

        <div className="flex flex-wrap items-center gap-4 rounded-2xl border border-white/[0.06] bg-[#14161d] px-4 py-3 text-[11px] text-zinc-400">
          <span className="font-bold uppercase tracking-wider text-zinc-300">Ecosystem:</span>
          {Object.entries(ECOSYSTEM_COLORS).map(([eco, color]) => (
            <span key={eco} className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${color}`} />
              <span className="capitalize">{eco}</span>
            </span>
          ))}
          <span className="ml-auto text-zinc-500">Node depth: Applications (top) → Root libraries (bottom)</span>
        </div>
      </div>

      <div className="glass-card rounded-2xl overflow-hidden">
        {selected && selectedMetrics ? (
          <NodeDetailPanel
            node={selected}
            metrics={selectedMetrics}
            nodeById={nodeById}
            onSimulate={onSimulate}
            onSelect={setSelectedNodeId}
            onClose={() => setSelectedNodeId(null)}
          />
        ) : (
          <div className="flex h-full min-h-[340px] flex-col items-center justify-center gap-3 p-6 text-center text-zinc-500">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/[0.04] border border-white/[0.06] text-zinc-400">
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 15l-2 2L9 9m-2 4l-4 4m0 0l-2-2m2 2l2 2m14-14a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-zinc-300">Select a graph node</p>
              <p className="mt-1 text-xs text-zinc-500 max-w-[220px] mx-auto">Click any component or package in the diagram to inspect risk telemetry.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

