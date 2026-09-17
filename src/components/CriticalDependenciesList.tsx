import type { DepNode, NodeMetrics } from "../types";
import { ECOSYSTEM_COLORS, RISK_COLORS, formatCompact } from "../lib/ui";

interface Row {
  node: DepNode;
  metrics: NodeMetrics;
}

interface Props {
  rows: Row[];
  onSelect: (id: string) => void;
  onSimulate: (id: string) => void;
}

export default function CriticalDependenciesList({ rows, onSelect, onSimulate }: Props) {
  return (
    <div className="divide-y divide-white/[0.06]">
      {rows.map(({ node, metrics }, i) => {
        const risk = RISK_COLORS[metrics.riskLevel];
        return (
          <div key={node.id} className="group flex items-center gap-3.5 py-3 transition-colors hover:bg-white/[0.02] px-2 rounded-xl">
            <span className="w-5 shrink-0 text-center font-mono text-xs font-bold text-zinc-600">{i + 1}</span>
            <div className="min-w-0 flex-1 cursor-pointer" onClick={() => onSelect(node.id)}>
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 shrink-0 rounded-full ${ECOSYSTEM_COLORS[node.ecosystem]}`} />
                <span className="truncate text-sm font-semibold text-zinc-100 transition-colors group-hover:text-indigo-400">{node.name}</span>
                {node.hasKnownCve && (
                  <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-rose-400">
                    {node.cveId}
                  </span>
                )}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-400">
                <span>{formatCompact(node.weeklyDownloads)}/wk</span>
                <span>•</span>
                <span>{metrics.directDependents.length} direct deps</span>
                <span>•</span>
                <span>{metrics.affectedApps.length} apps at risk</span>
              </div>
              <div className="mt-2 h-1.5 w-full max-w-[240px] overflow-hidden rounded-full bg-zinc-800">
                <div className={`h-full rounded-full ${risk.bar}`} style={{ width: `${metrics.criticality}%` }} />
              </div>
            </div>
            <span className={`shrink-0 rounded-full border border-white/5 px-3 py-1 text-xs font-bold font-mono ${risk.bg} ${risk.text}`}>
              {Math.round(metrics.criticality)}
            </span>
            <button
              onClick={() => onSimulate(node.id)}
              className="shrink-0 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-zinc-300 transition-all hover:border-rose-500/40 hover:bg-rose-500/10 hover:text-rose-400"
            >
              Simulate
            </button>
          </div>
        );
      })}
    </div>
  );
}

