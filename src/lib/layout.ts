import type { DepEdge, DepNode } from "../types";

export interface LayoutPosition {
  x: number;
  y: number;
}

const SPACING_X = 190;
const SPACING_Y = 160;

/**
 * Deterministic layered ("Sugiyama-style") layout: nodes are grouped by
 * tier (application -> frameworks -> utilities -> leaf packages) and their
 * horizontal order within a tier is refined over a few barycenter passes
 * using neighboring tiers, to reduce edge crossings.
 */
export function computeLayeredLayout(nodes: DepNode[], edges: DepEdge[]): Map<string, LayoutPosition> {
  const tiers = new Map<number, string[]>();
  for (const n of nodes) {
    if (!tiers.has(n.tier)) tiers.set(n.tier, []);
    tiers.get(n.tier)!.push(n.id);
  }
  const tierKeys = [...tiers.keys()].sort((a, b) => a - b);

  const outgoing = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();
  for (const e of edges) {
    if (!outgoing.has(e.source)) outgoing.set(e.source, []);
    outgoing.get(e.source)!.push(e.target);
    if (!incoming.has(e.target)) incoming.set(e.target, []);
    incoming.get(e.target)!.push(e.source);
  }

  const order = new Map<number, string[]>();
  for (const t of tierKeys) order.set(t, [...tiers.get(t)!]);

  const posIndex = () => {
    const idx = new Map<string, number>();
    for (const t of tierKeys) {
      order.get(t)!.forEach((id, i) => idx.set(id, i));
    }
    return idx;
  };

  const barycenterSort = (ids: string[], neighborMap: Map<string, string[]>, idx: Map<string, number>) => {
    const scored = ids.map((id) => {
      const neighbors = neighborMap.get(id) ?? [];
      const positions = neighbors.map((nb) => idx.get(nb)).filter((v): v is number => v !== undefined);
      const score = positions.length ? positions.reduce((a, b) => a + b, 0) / positions.length : idx.get(id) ?? 0;
      return { id, score };
    });
    scored.sort((a, b) => a.score - b.score);
    return scored.map((s) => s.id);
  };

  for (let iter = 0; iter < 4; iter++) {
    let idx = posIndex();
    for (const t of tierKeys.slice(1)) {
      order.set(t, barycenterSort(order.get(t)!, incoming, idx));
      idx = posIndex();
    }
    for (const t of [...tierKeys].reverse().slice(1)) {
      order.set(t, barycenterSort(order.get(t)!, outgoing, idx));
      idx = posIndex();
    }
  }

  const positions = new Map<string, LayoutPosition>();
  const maxWidth = Math.max(...tierKeys.map((t) => order.get(t)!.length));
  for (const t of tierKeys) {
    const ids = order.get(t)!;
    const rowWidth = ids.length * SPACING_X;
    const maxRowWidth = maxWidth * SPACING_X;
    const offsetX = (maxRowWidth - rowWidth) / 2;
    ids.forEach((id, i) => {
      positions.set(id, { x: offsetX + i * SPACING_X, y: t * SPACING_Y });
    });
  }

  return positions;
}
