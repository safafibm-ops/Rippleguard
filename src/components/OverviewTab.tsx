import { useMemo } from "react";
import { Bar as ReBar, BarChart as ReBarChart, CartesianGrid as ReCartesianGrid, Cell as ReCell, ResponsiveContainer as ReResponsiveContainer, Tooltip as ReTooltip, XAxis as ReXAxis, YAxis as ReYAxis } from "recharts";
import type { DepNode } from "../types";
import type { EcosystemMetrics } from "../lib/graph";
import StatCard from "./StatCard";
import CriticalDependenciesList from "./CriticalDependenciesList";

interface Props {
  nodes: DepNode[];
  metrics: EcosystemMetrics;
  onSelect: (id: string) => void;
  onSimulate: (id: string) => void;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
const RISK_CHART_COLOR: Record<string, string> = { Critical: "#f43f5e", High: "#f97316", Medium: "#fbbf24", Low: "#10b981" };

export default function OverviewTab({ nodes, metrics, onSelect, onSimulate }: Props) {
  const packages = useMemo(() => nodes.filter((n) => n.kind === "package"), [nodes]);
  const apps = useMemo(() => nodes.filter((n) => n.kind === "application"), [nodes]);

  const distribution = useMemo(() => {
    const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const p of packages) {
      const m = metrics.byId.get(p.id);
      if (m) counts[m.riskLevel]++;
    }
    return RISK_ORDER.map((r) => ({ name: r, value: counts[r] }));
  }, [packages, metrics]);

  const avgCriticality = useMemo(() => {
    const sum = packages.reduce((acc, p) => acc + (metrics.byId.get(p.id)?.criticality ?? 0), 0);
    return packages.length ? sum / packages.length : 0;
  }, [packages, metrics]);

  const cveCount = packages.filter((p) => p.hasKnownCve).length;
  const singleMaintainerCount = packages.filter((p) => p.maintainers <= 1).length;
  const criticalCount = packages.filter((p) => metrics.byId.get(p.id)?.riskLevel === "Critical").length;

  const topCritical = useMemo(() => {
    return [...packages]
      .map((node) => ({ node, metrics: metrics.byId.get(node.id)! }))
      .sort((a, b) => b.metrics.criticality - a.metrics.criticality)
      .slice(0, 8);
  }, [packages, metrics]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard
          label="Applications"
          value={`${apps.length}`}
          icon={
            <svg className="h-4 w-4 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
            </svg>
          }
        />
        <StatCard
          label="Tracked Packages"
          value={`${packages.length}`}
          icon={
            <svg className="h-4 w-4 text-sky-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
            </svg>
          }
        />
        <StatCard
          label="Critical Deps"
          value={`${criticalCount}`}
          accent="text-rose-400"
          icon={
            <svg className="h-4 w-4 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
            </svg>
          }
        />
        <StatCard
          label="Avg. Criticality"
          value={avgCriticality.toFixed(1)}
          icon={
            <svg className="h-4 w-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" />
            </svg>
          }
        />
        <StatCard
          label="Open CVEs"
          value={`${cveCount}`}
          accent={cveCount ? "text-rose-400" : "text-zinc-100"}
          icon={
            <svg className="h-4 w-4 text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          }
        />
        <StatCard
          label="Single Maintainer"
          value={`${singleMaintainerCount}`}
          accent="text-amber-400"
          icon={
            <svg className="h-4 w-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
        <div className="glass-card rounded-2xl p-5 lg:col-span-3">
          <div className="mb-4 flex items-center justify-between border-b border-white/[0.06] pb-3">
            <div>
              <h3 className="text-sm font-bold text-zinc-100">Most Critical Dependencies</h3>
              <p className="text-xs text-zinc-400">Ranked by composite multi-factor criticality index</p>
            </div>
            <span className="rounded-full border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 text-[11px] font-semibold text-indigo-400">
              Composite Index
            </span>
          </div>
          <CriticalDependenciesList rows={topCritical} onSelect={onSelect} onSimulate={onSimulate} />
        </div>

        <div className="flex flex-col gap-5 lg:col-span-2">
          <div className="glass-card rounded-2xl p-5">
            <h3 className="mb-1 text-sm font-bold text-zinc-100">Risk Distribution</h3>
            <p className="mb-4 text-xs text-zinc-400">Breakdown of packages by threat tier</p>
            <div style={{ width: "100%", height: 200 }}>
              <ReResponsiveContainer>
                <ReBarChart data={distribution} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <ReCartesianGrid strokeDasharray="3 3" vertical={false} stroke="#272a36" />
                  <ReXAxis dataKey="name" tick={{ fontSize: 11, fill: "#94a3b8" }} stroke="#333745" />
                  <ReYAxis tick={{ fontSize: 11, fill: "#94a3b8" }} stroke="#333745" allowDecimals={false} />
                  <ReTooltip
                    contentStyle={{ backgroundColor: "#181a22", borderColor: "#2e3240", borderRadius: 10, color: "#fff" }}
                    itemStyle={{ color: "#e2e8f0" }}
                  />
                  <ReBar dataKey="value" radius={[6, 6, 0, 0]}>
                    {distribution.map((d) => (
                      <ReCell key={d.name} fill={RISK_CHART_COLOR[d.name]} />
                    ))}
                  </ReBar>
                </ReBarChart>
              </ReResponsiveContainer>
            </div>
          </div>

          <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/5 p-5 backdrop-blur-sm">
            <div className="flex items-center gap-2 mb-2 text-indigo-400">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h3 className="text-xs font-bold uppercase tracking-wider">How Risk is Calculated</h3>
            </div>
            <p className="text-xs leading-relaxed text-zinc-300">
              Packages receive a <b>0–100 criticality score</b> synthesizing blast radius, transitive fan-in, vulnerability severity, maintainer health, and depth of application exposure. Transparency is paramount—every parameter weighting is inspectable on the detail panel.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

