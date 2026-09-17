import type {
  DepEdge,
  DepNode,
  NodeMetrics,
  PinningMode,
  PropagationResult,
  RiskFactors,
} from "../types";

export function buildForwardAdjacency(edges: DepEdge[]): Map<string, DepEdge[]> {
  const map = new Map<string, DepEdge[]>();
  for (const e of edges) {
    if (!map.has(e.source)) map.set(e.source, []);
    map.get(e.source)!.push(e);
  }
  return map;
}

export function buildReverseAdjacency(edges: DepEdge[]): Map<string, DepEdge[]> {
  const map = new Map<string, DepEdge[]>();
  for (const e of edges) {
    if (!map.has(e.target)) map.set(e.target, []);
    map.get(e.target)!.push(e);
  }
  return map;
}

/** BFS over the reverse graph: who (transitively) depends on `startId`. */
export function reachableDependents(startId: string, reverseAdj: Map<string, DepEdge[]>): string[] {
  const visited = new Set<string>([startId]);
  const queue = [startId];
  const out: string[] = [];
  while (queue.length) {
    const cur = queue.shift()!;
    const incoming = reverseAdj.get(cur) ?? [];
    for (const e of incoming) {
      if (!visited.has(e.source)) {
        visited.add(e.source);
        out.push(e.source);
        queue.push(e.source);
      }
    }
  }
  return out;
}

/** Shortest hop distance from any application node to every other node, via forward deps. */
export function minDepthFromApplications(nodes: DepNode[], forwardAdj: Map<string, DepEdge[]>): Map<string, number> {
  const dist = new Map<string, number>();
  const apps = nodes.filter((n) => n.kind === "application");
  const queue: string[] = [];
  for (const a of apps) {
    dist.set(a.id, 0);
    queue.push(a.id);
  }
  let i = 0;
  while (i < queue.length) {
    const cur = queue[i++];
    const d = dist.get(cur)!;
    for (const e of forwardAdj.get(cur) ?? []) {
      if (!dist.has(e.target)) {
        dist.set(e.target, d + 1);
        queue.push(e.target);
      }
    }
  }
  return dist;
}

const PINNING_WEIGHT: Record<PinningMode, number> = {
  pinned: 0.32,
  caret: 0.82,
  latest: 1.0,
};

const PINNING_DELAY_DAYS: Record<PinningMode, number> = {
  pinned: 21,
  caret: 3,
  latest: 0.5,
};

export interface EcosystemMetrics {
  byId: Map<string, NodeMetrics>;
  totalApps: number;
  maxDirectDependents: number;
}

export function computeEcosystemMetrics(nodes: DepNode[], edges: DepEdge[]): EcosystemMetrics {
  const forwardAdj = buildForwardAdjacency(edges);
  const reverseAdj = buildReverseAdjacency(edges);
  const depth = minDepthFromApplications(nodes, forwardAdj);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const totalApps = nodes.filter((n) => n.kind === "application").length;

  const raw = nodes.map((n) => {
    const directDependents = (reverseAdj.get(n.id) ?? []).map((e) => e.source);
    const transitiveDependents = reachableDependents(n.id, reverseAdj);
    const affectedApps = transitiveDependents.filter((id) => nodeById.get(id)?.kind === "application");
    return { id: n.id, directDependents, transitiveDependents, affectedApps };
  });

  const maxDirectDependents = Math.max(1, ...raw.map((r) => r.directDependents.length));

  const byId = new Map<string, NodeMetrics>();
  for (const r of raw) {
    const node = nodeById.get(r.id)!;
    const minDepthFromApp = node.kind === "application" ? 0 : depth.get(r.id) ?? 6;

    const blastRadius = node.kind === "application" ? 0 : Math.min(100, (r.affectedApps.length / Math.max(1, totalApps)) * 100);
    const fanIn = Math.min(100, (r.directDependents.length / maxDirectDependents) * 100);
    const vulnerability = Math.min(100, node.vulnerabilityScore * 10);

    const maintainerRisk = node.maintainers <= 1 ? 70 : node.maintainers === 2 ? 40 : node.maintainers <= 4 ? 15 : 5;
    const staleness = Math.min(100, (node.lastCommitDaysAgo / 730) * 100);
    const maintenance = Math.min(100, maintainerRisk * 0.6 + staleness * 0.4);

    const exposure = node.kind === "application" ? 0 : Math.min(100, 100 / (1 + minDepthFromApp));

    const factors: RiskFactors = { blastRadius, fanIn, vulnerability, maintenance, exposure };

    let criticality = 0;
    if (node.kind === "package") {
      criticality =
        blastRadius * 0.35 +
        fanIn * 0.2 +
        vulnerability * 0.2 +
        maintenance * 0.15 +
        exposure * 0.1;
    }

    const riskLevel: NodeMetrics["riskLevel"] =
      criticality >= 75 ? "Critical" : criticality >= 50 ? "High" : criticality >= 25 ? "Medium" : "Low";

    byId.set(r.id, {
      id: r.id,
      directDependents: r.directDependents,
      transitiveDependents: r.transitiveDependents,
      affectedApps: r.affectedApps,
      minDepthFromApp,
      factors,
      criticality,
      riskLevel,
    });
  }

  return { byId, totalApps, maxDirectDependents };
}

/**
 * Simulate compromise propagation upstream from `sourceId` through the
 * reverse dependency graph (i.e. towards everything that depends on it).
 * Produces per-node hop distance, infection probability and an estimated
 * time-to-compromise, driven by version-pinning behaviour of each edge.
 */
export function simulatePropagation(sourceId: string, edges: DepEdge[]): PropagationResult {
  const reverseAdj = buildReverseAdjacency(edges);
  const hop: Record<string, number> = { [sourceId]: 0 };
  const probability: Record<string, number> = { [sourceId]: 1 };
  const etaDays: Record<string, number> = { [sourceId]: 0 };
  const parent: Record<string, string> = {};
  const order: string[] = [];

  const queue: string[] = [sourceId];
  let head = 0;
  let maxHop = 0;

  while (head < queue.length) {
    const cur = queue[head++];
    const incoming = reverseAdj.get(cur) ?? [];
    for (const e of incoming) {
      const dependent = e.source;
      const candidateProb = probability[cur] * PINNING_WEIGHT[e.pinning] * 0.97;
      const candidateEta = etaDays[cur] + PINNING_DELAY_DAYS[e.pinning];
      const candidateHop = hop[cur] + 1;

      if (!(dependent in probability) || candidateProb > probability[dependent]) {
        const firstVisit = !(dependent in probability);
        probability[dependent] = candidateProb;
        parent[dependent] = cur;
        if (firstVisit || candidateHop < hop[dependent]) {
          hop[dependent] = candidateHop;
        }
        if (firstVisit || candidateEta < etaDays[dependent]) {
          etaDays[dependent] = candidateEta;
        }
        if (firstVisit) {
          order.push(dependent);
          queue.push(dependent);
        }
        maxHop = Math.max(maxHop, hop[dependent]);
      }
    }
  }

  return { sourceId, order, hop, probability, etaDays, parent, maxHop };
}

export function reconstructPath(result: PropagationResult, targetId: string): string[] {
  const path: string[] = [targetId];
  let cur = targetId;
  while (result.parent[cur]) {
    cur = result.parent[cur];
    path.push(cur);
  }
  return path.reverse();
}
