import { useEffect, useMemo, useState } from "react";
import type { DepEdge, DepNode, PropagationResult, Scenario } from "../types";
import type { EcosystemMetrics } from "../lib/graph";
import { reconstructPath } from "../lib/graph";
import DependencyGraph from "./graph/DependencyGraph";
import StatCard from "./StatCard";
import { RISK_COLORS, formatCompact } from "../lib/ui";

interface Props {
  nodes: DepNode[];
  edges: DepEdge[];
  nodeById: Map<string, DepNode>;
  metrics: EcosystemMetrics;
  scenarios: Scenario[];
  activeScenario: Scenario | null;
  compromisedId: string | null;
  propagation: PropagationResult | null;
  hopFilter: number;
  setHopFilter: (n: number) => void;
  onSelectScenario: (id: string) => void;
  onSelectCustom: (id: string) => void;
  onGoToMitigation: () => void;
}

const SEVERITY_BADGE: Record<Scenario["severity"], string> = {
  Critical: "border border-rose-500/30 bg-rose-500/10 text-rose-400",
  High: "border border-orange-500/30 bg-orange-500/10 text-orange-400",
  Medium: "border border-amber-500/30 bg-amber-500/10 text-amber-300",
};

export default function SimulationTab({
  nodes,
  edges,
  nodeById,
  metrics,
  scenarios,
  activeScenario,
  compromisedId,
  propagation,
  hopFilter,
  setHopFilter,
  onSelectScenario,
  onSelectCustom,
  onGoToMitigation,
}: Props) {
  const [playing, setPlaying] = useState(false);
  const [expandedApp, setExpandedApp] = useState<string | null>(null);
  const packages = useMemo(() => nodes.filter((n) => n.kind === "package"), [nodes]);
  const compromisedNode = compromisedId ? nodeById.get(compromisedId) : undefined;
  const maxHop = propagation?.maxHop ?? 0;

  useEffect(() => {
    if (!playing || !propagation) return;
    if (hopFilter >= maxHop) {
      setPlaying(false);
      return;
    }
    const t = setTimeout(() => setHopFilter(Math.min(maxHop, hopFilter + 1)), 900);
    return () => clearTimeout(t);
  }, [playing, hopFilter, maxHop, propagation, setHopFilter]);

  const affectedApps = useMemo(() => {
    if (!propagation) return [];
    return nodes
      .filter((n) => n.kind === "application" && propagation.hop[n.id] !== undefined)
      .map((n) => ({
        node: n,
        hop: propagation.hop[n.id],
        probability: propagation.probability[n.id],
        eta: propagation.etaDays[n.id],
      }))
      .sort((a, b) => b.probability - a.probability);
  }, [nodes, propagation]);

  const visibleAffectedApps = affectedApps.filter((a) => a.hop <= hopFilter);
  const avgProbability = visibleAffectedApps.length
    ? visibleAffectedApps.reduce((s, a) => s + a.probability, 0) / visibleAffectedApps.length
    : 0;
  const fastestEta = visibleAffectedApps.length ? Math.min(...visibleAffectedApps.map((a) => a.eta)) : 0;

  return (
    <div className="space-y-6">
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-bold text-zinc-100">1. Select Threat Vector Scenario</h3>
          <span className="text-xs text-zinc-400">Choose a preset supply-chain attack or pick a custom package</span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {scenarios.map((s) => {
            const isSelected = activeScenario?.id === s.id;
            return (
              <button
                key={s.id}
                onClick={() => onSelectScenario(s.id)}
                className={`group rounded-2xl border p-3.5 text-left transition-all duration-200 ${
                  isSelected
                    ? "border-rose-500/60 bg-rose-950/20 ring-1 ring-rose-500/40 shadow-lg shadow-rose-500/10"
                    : "border-white/[0.08] bg-[#14161d] hover:border-white/20 hover:bg-[#181a22]"
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${SEVERITY_BADGE[s.severity]}`}>{s.severity}</span>
                  <span className="font-mono text-[10px] font-semibold text-zinc-400">{s.cveId}</span>
                </div>
                <div className="mt-2 text-xs font-bold text-zinc-100 group-hover:text-rose-300 transition-colors">{s.title}</div>
                <div className="mt-1 font-mono text-[11px] text-zinc-400">{nodeById.get(s.packageId)?.name}</div>
              </button>
            );
          })}
        </div>

        <div className="mt-3.5 flex flex-wrap items-center gap-3 rounded-2xl border border-dashed border-white/10 bg-[#12141a] p-3.5">
          <span className="text-xs font-semibold text-zinc-300">Or simulate custom package compromise:</span>
          <select
            value={activeScenario ? "" : compromisedId ?? ""}
            onChange={(e) => onSelectCustom(e.target.value)}
            className="rounded-xl border border-white/10 bg-[#0b0c10] px-3 py-1.5 text-xs text-zinc-200 outline-none transition-all focus:border-indigo-500"
          >
            <option value="" disabled className="text-zinc-500">
              Select any ecosystem package…
            </option>
            {packages.map((p) => (
              <option key={p.id} value={p.id} className="bg-[#14161d] text-zinc-200">
                {p.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {compromisedNode && propagation && (
        <>
          {activeScenario && (
            <div className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4 backdrop-blur-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-rose-500/20 text-rose-400">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </span>
                <h4 className="text-sm font-bold text-rose-300">{activeScenario.title}</h4>
                <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${SEVERITY_BADGE[activeScenario.severity]}`}>
                  {activeScenario.severity}
                </span>
                <span className="font-mono text-xs text-rose-400">{activeScenario.cveId}</span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-zinc-300">{activeScenario.narrative}</p>
              <p className="mt-1.5 text-[11px] font-medium text-rose-400">Vector: {activeScenario.attackVector}</p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatCard label="Target Package" value={compromisedNode.name} />
            <StatCard label="Apps at Risk" value={`${affectedApps.length} / ${nodes.filter((n) => n.kind === "application").length}`} accent="text-rose-400" />
            <StatCard label="Avg. Infection Prob" value={`${Math.round(avgProbability * 100)}%`} />
            <StatCard label="Fastest Reach ETA" value={`${fastestEta.toFixed(1)}d`} />
          </div>

          <div className="glass-card rounded-2xl p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="text-sm font-bold text-zinc-100">Propagation Wave Simulation</h4>
                <p className="text-xs text-zinc-400">
                  Step through dependency hops from source compromise node <b>{compromisedNode.name}</b>
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    if (hopFilter >= maxHop) setHopFilter(0);
                    setPlaying((p) => !p);
                  }}
                  className="flex items-center gap-1.5 rounded-xl bg-indigo-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-indigo-600/20 transition-all hover:bg-indigo-500"
                >
                  {playing ? (
                    <>
                      <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
                      </svg>
                      Pause
                    </>
                  ) : (
                    <>
                      <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M8 5v14l11-7z" />
                      </svg>
                      Play Animation
                    </>
                  )}
                </button>
                <button
                  onClick={() => {
                    setPlaying(false);
                    setHopFilter(0);
                  }}
                  className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-semibold text-zinc-400 transition-all hover:border-white/20 hover:text-zinc-200"
                >
                  Reset
                </button>
              </div>
            </div>
            <input
              type="range"
              min={0}
              max={maxHop}
              value={Math.min(hopFilter, maxHop)}
              onChange={(e) => {
                setPlaying(false);
                setHopFilter(Number(e.target.value));
              }}
              className="mt-4 w-full accent-rose-500"
            />
            <div className="mt-1 flex justify-between font-mono text-[10px] text-zinc-500">
              <span>Hop 0 (Source)</span>
              <span className="text-rose-400 font-semibold">
                Viewing Hop ≤ {Math.min(hopFilter, maxHop)} of {maxHop}
              </span>
              <span>Hop {maxHop} (Maximum Depth)</span>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_380px]">
            <DependencyGraph
              nodes={nodes}
              edges={edges}
              metrics={metrics}
              selectedNodeId={null}
              onSelect={() => {}}
              mode="propagation"
              compromisedId={compromisedId}
              propagation={propagation}
              hopFilter={hopFilter}
              height="600px"
            />

            <div className="glass-card flex flex-col rounded-2xl">
              <div className="border-b border-white/[0.06] p-4">
                <h4 className="text-sm font-bold text-zinc-100">Affected Applications</h4>
                <p className="text-xs text-zinc-400">Ranked by infection likelihood for active hop window</p>
              </div>
              <div className="max-h-[540px] flex-1 overflow-y-auto divide-y divide-white/[0.06]">
                {visibleAffectedApps.length === 0 && (
                  <p className="p-6 text-center text-xs text-zinc-500">No applications reached yet at this hop level. Drag the slider to advance.</p>
                )}
                {visibleAffectedApps.map(({ node, hop, probability, eta }) => {
                  const path = reconstructPath(propagation, node.id);
                  const expanded = expandedApp === node.id;
                  return (
                    <div key={node.id} className="p-3.5">
                      <button className="flex w-full items-center justify-between gap-2" onClick={() => setExpandedApp(expanded ? null : node.id)}>
                        <div className="min-w-0 text-left">
                          <div className="truncate text-xs font-bold text-zinc-200">{node.name}</div>
                          <div className="mt-0.5 font-mono text-[10px] text-zinc-400">
                            Hop {hop} · ETA {eta.toFixed(1)}d · {formatCompact(node.weeklyDownloads)} users
                          </div>
                        </div>
                        <span
                          className={`shrink-0 rounded-full border border-white/5 px-2.5 py-1 font-mono text-[11px] font-bold ${
                            probability > 0.6 ? RISK_COLORS.Critical.bg + " " + RISK_COLORS.Critical.text : probability > 0.3 ? RISK_COLORS.High.bg + " " + RISK_COLORS.High.text : RISK_COLORS.Medium.bg + " " + RISK_COLORS.Medium.text
                          }`}
                        >
                          {Math.round(probability * 100)}%
                        </span>
                      </button>
                      {expanded && (
                        <div className="mt-2.5 flex flex-wrap items-center gap-1 rounded-xl border border-white/10 bg-[#0d0e12] p-2.5 font-mono text-[10px] text-zinc-400">
                          {path.map((id, i) => (
                            <span key={id} className="flex items-center gap-1">
                              <span className="rounded bg-white/10 px-1.5 py-0.5 font-semibold text-zinc-200">{nodeById.get(id)?.name ?? id}</span>
                              {i < path.length - 1 && <span className="text-zinc-600">→</span>}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              <div className="border-t border-white/[0.06] p-4">
                <button
                  onClick={onGoToMitigation}
                  className="w-full rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-700 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-indigo-600/20 transition-all hover:from-indigo-500 hover:to-indigo-600"
                >
                  View Mitigation Playbook →
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

