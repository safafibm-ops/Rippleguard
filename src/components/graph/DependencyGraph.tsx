import { useMemo } from "react";
import { Background, BackgroundVariant, Controls, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { DepEdge, DepNode, PropagationResult } from "../../types";
import type { EcosystemMetrics } from "../../lib/graph";
import { layoutPositions } from "../../lib/staticLayout";
import DepGraphNode, { type DepGraphNodeData } from "./DepGraphNode";
import { RISK_COLORS } from "../../lib/ui";

const nodeTypes = { dep: DepGraphNode };

export interface GraphFilters {
  text: string;
  ecosystem: string;
  risk: string;
}

interface Props {
  nodes: DepNode[];
  edges: DepEdge[];
  metrics: EcosystemMetrics;
  selectedNodeId: string | null;
  onSelect: (id: string) => void;
  mode: "risk" | "propagation";
  compromisedId?: string | null;
  propagation?: PropagationResult | null;
  hopFilter?: number;
  filters?: GraphFilters;
  height?: string;
}

function matchesFilter(node: DepNode, filters: GraphFilters | undefined): boolean {
  if (!filters) return true;
  const text = filters.text.trim().toLowerCase();
  if (text && !node.name.toLowerCase().includes(text) && !node.description.toLowerCase().includes(text)) return false;
  if (filters.ecosystem !== "all" && node.ecosystem !== filters.ecosystem) return false;
  return true;
}

export default function DependencyGraph({
  nodes,
  edges,
  metrics,
  selectedNodeId,
  onSelect,
  mode,
  compromisedId,
  propagation,
  hopFilter = 99,
  filters,
  height = "560px",
}: Props) {
  const rfNodes: Node[] = useMemo(() => {
    return nodes.map((n) => {
      const pos = layoutPositions.get(n.id) ?? { x: 0, y: 0 };
      const m = metrics.byId.get(n.id);
      let visualState: DepGraphNodeData["visualState"] = "normal";
      let infectionProbability: number | undefined;

      if (mode === "propagation" && compromisedId && propagation) {
        if (n.id === compromisedId) {
          visualState = "compromised";
        } else if (propagation.hop[n.id] !== undefined && propagation.hop[n.id] <= hopFilter) {
          visualState = "affected";
          infectionProbability = propagation.probability[n.id];
        } else {
          visualState = "dim";
        }
      } else {
        if (!matchesFilter(n, filters)) {
          visualState = "dim";
        } else if (n.id === selectedNodeId) {
          visualState = "selected";
        } else if (filters?.risk && filters.risk !== "all") {
          visualState = m?.riskLevel === filters.risk ? "normal" : "dim";
        }
      }

      return {
        id: n.id,
        type: "dep",
        position: pos,
        data: { node: n, metrics: m, visualState, infectionProbability } satisfies DepGraphNodeData,
        draggable: true,
      };
    });
  }, [nodes, metrics, mode, compromisedId, propagation, hopFilter, filters, selectedNodeId]);

  const rfEdges: Edge[] = useMemo(() => {
    return edges.map((e, i) => {
      let stroke = "#333848";
      let strokeWidth = 1.2;
      let animated = false;
      let opacity = 0.6;

      if (mode === "propagation" && propagation) {
        const sourceHop = propagation.hop[e.source];
        const targetHop = propagation.hop[e.target];
        const isTreeEdge = propagation.parent[e.source] === e.target;
        const reached = sourceHop !== undefined && sourceHop <= hopFilter && targetHop !== undefined && targetHop <= hopFilter;
        if (isTreeEdge && reached) {
          stroke = "#f43f5e";
          strokeWidth = 2.4;
          animated = true;
          opacity = 0.95;
        } else if (reached) {
          stroke = "#fb923c";
          strokeWidth = 1.4;
          opacity = 0.6;
        } else {
          opacity = 0.08;
        }
      } else if (selectedNodeId && (e.source === selectedNodeId || e.target === selectedNodeId)) {
        stroke = "#818cf8";
        strokeWidth = 2;
        opacity = 0.95;
      } else if (filters && (filters.text || filters.ecosystem !== "all" || filters.risk !== "all")) {
        opacity = 0.12;
      }

      return {
        id: `e-${i}`,
        source: e.source,
        target: e.target,
        animated,
        style: { stroke, strokeWidth, opacity },
      };
    });
  }, [edges, mode, propagation, hopFilter, selectedNodeId, filters]);

  return (
    <div style={{ height }} className="relative w-full overflow-hidden rounded-2xl border border-white/[0.08] bg-[#0e1015]">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => onSelect(node.id)}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.25}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#252936" />
        <Controls showInteractive={false} className="!bg-[#161820] !border-white/10 !text-zinc-300" />
        <MiniMap
          pannable
          zoomable
          style={{ backgroundColor: "#12141a", border: "1px solid rgba(255,255,255,0.08)" }}
          nodeColor={(n) => {
            const data = n.data as unknown as DepGraphNodeData;
            const risk = data.metrics ? RISK_COLORS[data.metrics.riskLevel] : null;
            if (data.node.kind === "application") return "#818cf8";
            if (!risk) return "#64748b";
            return risk.dot.includes("rose")
              ? "#f43f5e"
              : risk.dot.includes("orange")
                ? "#f97316"
                : risk.dot.includes("amber")
                  ? "#fbbf24"
                  : "#10b981";
          }}
        />
      </ReactFlow>
    </div>
  );
}

