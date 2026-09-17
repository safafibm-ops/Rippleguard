import { useMemo } from "react";
import type { DepEdge, DepNode, MitigationAction, PropagationResult } from "../types";
import type { EcosystemMetrics } from "../lib/graph";
import { generateHardeningBacklog, generateScenarioMitigations } from "../lib/mitigations";

interface Props {
  nodes: DepNode[];
  edges: DepEdge[];
  nodeById: Map<string, DepNode>;
  metrics: EcosystemMetrics;
  compromisedId: string | null;
  propagation: PropagationResult | null;
  onSelect: (id: string) => void;
}

const CATEGORY_STYLE: Record<MitigationAction["category"], { bg: string; text: string; label: string }> = {
  Contain: { bg: "border border-rose-500/30 bg-rose-500/10", text: "text-rose-400", label: "Containment" },
  Remediate: { bg: "border border-indigo-500/30 bg-indigo-500/10", text: "text-indigo-400", label: "Remediation" },
  Harden: { bg: "border border-amber-500/30 bg-amber-500/10", text: "text-amber-300", label: "Hardening" },
  Monitor: { bg: "border border-sky-500/30 bg-sky-500/10", text: "text-sky-400", label: "Monitoring" },
};

const EFFORT_STYLE: Record<MitigationAction["effort"], string> = {
  Low: "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  Medium: "border border-amber-500/30 bg-amber-500/10 text-amber-300",
  High: "border border-rose-500/30 bg-rose-500/10 text-rose-400",
};

function ActionCard({ action, nodeById, onSelect, rank }: { action: MitigationAction; nodeById: Map<string, DepNode>; onSelect: (id: string) => void; rank: number }) {
  const style = CATEGORY_STYLE[action.category];
  return (
    <div className="glass-card rounded-2xl p-4.5">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] font-mono text-xs font-bold text-zinc-300">
            {rank}
          </span>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-md px-2 py-0.5 text-[10px] font-bold ${style.bg} ${style.text}`}>
                {style.label}
              </span>
              <span className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold ${EFFORT_STYLE[action.effort]}`}>{action.effort} Effort</span>
              {action.relatedNodeId && (
                <button onClick={() => onSelect(action.relatedNodeId!)} className="font-mono text-[11px] font-semibold text-indigo-400 hover:underline">
                  @{nodeById.get(action.relatedNodeId)?.name}
                </button>
              )}
            </div>
            <h4 className="mt-2 text-sm font-bold text-zinc-100">{action.title}</h4>
            <p className="mt-1 text-xs leading-relaxed text-zinc-300">{action.rationale}</p>
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">Priority Score</div>
          <div className="mt-0.5 text-lg font-bold font-mono text-zinc-100">{action.priority}</div>
        </div>
      </div>
      <div className="mt-3.5 h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
        <div className="h-full rounded-full bg-gradient-to-r from-indigo-500 via-violet-500 to-rose-500" style={{ width: `${Math.min(100, action.impact)}%` }} />
      </div>
    </div>
  );
}

export default function MitigationTab({ nodes, edges, nodeById, metrics, compromisedId, propagation, onSelect }: Props) {
  const scenarioActions = useMemo(() => {
    if (!compromisedId || !propagation) return [];
    const pkg = nodeById.get(compromisedId);
    if (!pkg) return [];
    return generateScenarioMitigations(pkg, nodeById, edges, metrics, propagation);
  }, [compromisedId, propagation, nodeById, edges, metrics]);

  const hardeningBacklog = useMemo(() => generateHardeningBacklog(nodes, edges, metrics, 6), [nodes, edges, metrics]);

  const compromisedNode = compromisedId ? nodeById.get(compromisedId) : undefined;

  return (
    <div className="space-y-8">
      <section>
        <div className="mb-4">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-zinc-100">
              Incident Response Plan {compromisedNode ? `— ${compromisedNode.name}` : ""}
            </h3>
            {compromisedNode && (
              <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold text-rose-400">
                Active Simulation
              </span>
            )}
          </div>
          <p className="mt-0.5 text-xs text-zinc-400">
            {compromisedNode
              ? "Prioritized containment and remediation steps generated for current attack simulation"
              : "Select a compromise scenario in the simulator to generate a targeted incident response playbook."}
          </p>
        </div>
        {scenarioActions.length > 0 ? (
          <div className="space-y-3">
            {scenarioActions.map((a, i) => (
              <ActionCard key={a.id} action={a} nodeById={nodeById} onSelect={onSelect} rank={i + 1} />
            ))}
          </div>
        ) : (
          <div className="rounded-2xl border border-dashed border-white/10 bg-[#14161d] p-8 text-center text-xs text-zinc-500">
            No active incident scenario selected. Switch to the Compromise Simulator tab to run an attack simulation.
          </div>
        )}
      </section>

      <section>
        <div className="mb-4">
          <h3 className="text-sm font-bold text-zinc-100">Proactive Hardening Backlog</h3>
          <p className="mt-0.5 text-xs text-zinc-400">
            Ecosystem-wide preventative security tasks for top critical dependencies.
          </p>
        </div>
        <div className="space-y-3">
          {hardeningBacklog.map((a, i) => (
            <ActionCard key={a.id} action={a} nodeById={nodeById} onSelect={onSelect} rank={i + 1} />
          ))}
        </div>
      </section>
    </div>
  );
}

