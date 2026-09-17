import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DepNode, NodeMetrics } from "../types";
import { ECOSYSTEM_COLORS, RISK_COLORS, formatCompact } from "../lib/ui";

interface Props {
  node: DepNode;
  metrics: NodeMetrics;
  nodeById: Map<string, DepNode>;
  onSimulate: (id: string) => void;
  onSelect: (id: string) => void;
  onClose?: () => void;
}

const FACTOR_INFO: { key: keyof NodeMetrics["factors"]; label: string; weight: number; help: string }[] = [
  { key: "blastRadius", label: "Blast radius", weight: 0.35, help: "Share of applications reachable transitively if compromised." },
  { key: "fanIn", label: "Fan-in", weight: 0.2, help: "How many other components directly depend on it." },
  { key: "vulnerability", label: "Vulnerability", weight: 0.2, help: "Intrinsic severity of known or simulated vulnerabilities." },
  { key: "maintenance", label: "Maintenance", weight: 0.15, help: "Bus-factor (maintainer count) & commit freshness." },
  { key: "exposure", label: "Exposure depth", weight: 0.1, help: "Proximity to application code layers." },
];

export default function NodeDetailPanel({ node, metrics, nodeById, onSimulate, onSelect, onClose }: Props) {
  const risk = RISK_COLORS[metrics.riskLevel];
  const chartData = FACTOR_INFO.map((f) => ({ name: f.label, value: Math.round(metrics.factors[f.key]) }));

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[#14161d] text-zinc-100">
      <div className="flex items-start justify-between gap-2 border-b border-white/[0.08] p-4">
        <div>
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${ECOSYSTEM_COLORS[node.ecosystem]}`} />
            <h3 className="text-base font-bold text-white tracking-tight">{node.name}</h3>
          </div>
          <p className="mt-0.5 font-mono text-[11px] text-zinc-400">
            {node.ecosystem} · v{node.version} · {node.kind === "application" ? "Application" : `Tier ${node.tier}`}
          </p>
        </div>
        {onClose && (
          <button onClick={onClose} className="rounded-lg p-1.5 text-zinc-400 hover:bg-white/[0.08] hover:text-white">
            ✕
          </button>
        )}
      </div>

      <div className="space-y-5 p-4">
        <p className="text-xs leading-relaxed text-zinc-300">{node.description}</p>

        {node.kind === "package" && (
          <div className="flex items-center justify-between rounded-xl border border-white/10 bg-[#0d0e12] p-3.5">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Criticality Index</div>
              <div className="mt-0.5 text-2xl font-bold font-mono text-white">
                {Math.round(metrics.criticality)}
                <span className="text-xs font-normal text-zinc-500">/100</span>
              </div>
            </div>
            <span className={`rounded-full border border-white/10 px-3 py-1 text-xs font-bold font-mono ring-1 ${risk.bg} ${risk.text} ${risk.ring}`}>
              {metrics.riskLevel} Risk
            </span>
          </div>
        )}

        <div className="grid grid-cols-2 gap-2.5">
          <Stat label="Maintainers" value={`${node.maintainers}`} warn={node.maintainers <= 1} />
          <Stat label="Last Commit" value={`${node.lastCommitDaysAgo}d ago`} warn={node.lastCommitDaysAgo > 300} />
          <Stat label="Weekly Downloads" value={formatCompact(node.weeklyDownloads)} />
          <Stat label="Known CVE" value={node.hasKnownCve ? node.cveId ?? "Yes" : "None"} warn={node.hasKnownCve} />
        </div>

        {node.kind === "package" && (
          <>
            <div>
              <h4 className="mb-2 text-[11px] font-bold uppercase tracking-wider text-zinc-400">Criticality Factor Breakdown</h4>
              <div style={{ width: "100%", height: 180 }}>
                <ResponsiveContainer>
                  <BarChart data={chartData} layout="vertical" margin={{ left: 5, right: 15, top: 4, bottom: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#272a36" />
                    <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: "#94a3b8" }} stroke="#333745" />
                    <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 10, fill: "#94a3b8" }} stroke="#333745" />
                    <Tooltip
                      formatter={(v) => [`${v}/100`, "Score"]}
                      contentStyle={{ backgroundColor: "#181a22", borderColor: "#2e3240", borderRadius: 8, color: "#fff" }}
                    />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {chartData.map((_, i) => (
                        <Cell key={i} fill={["#818cf8", "#38bdf8", "#f43f5e", "#fbbf24", "#34d399"][i % 5]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <ul className="mt-2 space-y-1 text-[11px] text-zinc-400">
                {FACTOR_INFO.map((f) => (
                  <li key={f.key}>
                    <span className="font-semibold text-zinc-200">{f.label}</span> ({Math.round(f.weight * 100)}%) — {f.help}
                  </li>
                ))}
              </ul>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center">
              <MiniStat label="Direct Deps" value={metrics.directDependents.length} />
              <MiniStat label="Transitive" value={metrics.transitiveDependents.length} />
              <MiniStat label="Apps Affected" value={metrics.affectedApps.length} />
            </div>

            {metrics.directDependents.length > 0 && (
              <div>
                <h4 className="mb-2 text-[11px] font-bold uppercase tracking-wider text-zinc-400">Direct Dependents</h4>
                <div className="flex flex-wrap gap-1.5">
                  {metrics.directDependents.map((id) => (
                    <button
                      key={id}
                      onClick={() => onSelect(id)}
                      className="rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-zinc-300 transition-all hover:border-indigo-500/50 hover:bg-indigo-500/10 hover:text-indigo-300"
                    >
                      {nodeById.get(id)?.name ?? id}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <button
              onClick={() => onSimulate(node.id)}
              className="w-full rounded-xl bg-gradient-to-r from-rose-600 to-rose-700 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-rose-600/20 transition-all hover:from-rose-500 hover:to-rose-600"
            >
              Simulate Compromise of {node.name}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="rounded-xl border border-white/10 bg-[#0d0e12] p-2.5">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div className={`mt-0.5 text-xs font-bold font-mono ${warn ? "text-rose-400" : "text-zinc-200"}`}>{value}</div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-white/5 bg-[#0d0e12] p-2">
      <div className="text-sm font-bold font-mono text-zinc-100">{value}</div>
      <div className="text-[9px] uppercase tracking-wider text-zinc-500">{label}</div>
    </div>
  );
}

