import { useMemo, useState } from "react";
import { edges, nodeById, nodes } from "../data/ecosystem";
import { scenarios } from "../data/scenarios";
import { computeEcosystemMetrics, simulatePropagation } from "../lib/graph";

export function useEcosystem() {
  const metrics = useMemo(() => computeEcosystemMetrics(nodes, edges), []);

  const [compromisedId, setCompromisedId] = useState<string | null>(scenarios[0].packageId);
  const [activeScenarioId, setActiveScenarioId] = useState<string | null>(scenarios[0].id);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hopFilter, setHopFilter] = useState<number>(99);

  const propagation = useMemo(() => {
    if (!compromisedId) return null;
    return simulatePropagation(compromisedId, edges);
  }, [compromisedId]);

  const activeScenario = useMemo(() => scenarios.find((s) => s.id === activeScenarioId) ?? null, [activeScenarioId]);

  function selectScenario(scenarioId: string) {
    const scenario = scenarios.find((s) => s.id === scenarioId);
    if (!scenario) return;
    setActiveScenarioId(scenarioId);
    setCompromisedId(scenario.packageId);
    setHopFilter(99);
  }

  function selectCustomPackage(pkgId: string) {
    setActiveScenarioId(null);
    setCompromisedId(pkgId);
    setHopFilter(99);
  }

  return {
    nodes,
    edges,
    nodeById,
    metrics,
    scenarios,
    activeScenario,
    compromisedId,
    propagation,
    selectedNodeId,
    setSelectedNodeId,
    hopFilter,
    setHopFilter,
    selectScenario,
    selectCustomPackage,
  };
}

export type EcosystemState = ReturnType<typeof useEcosystem>;
