export type Ecosystem = "npm" | "pypi" | "maven" | "cargo" | "go" | "docker";

export type NodeKind = "application" | "package";

export type PinningMode = "pinned" | "caret" | "latest";

export interface DepNode {
  id: string;
  name: string;
  kind: NodeKind;
  ecosystem: Ecosystem;
  version: string;
  tier: number; // 0 = application, higher = deeper in the dependency stack
  description: string;
  maintainers: number;
  weeklyDownloads: number;
  lastCommitDaysAgo: number;
  vulnerabilityScore: number; // 0-10, CVSS-like intrinsic score
  hasKnownCve: boolean;
  cveId?: string;
  license: string;
  tags: string[];
}

export interface DepEdge {
  source: string; // depends on target
  target: string;
  pinning: PinningMode;
}

export interface RiskFactors {
  blastRadius: number; // 0-100
  fanIn: number; // 0-100
  vulnerability: number; // 0-100
  maintenance: number; // 0-100
  exposure: number; // 0-100
}

export interface NodeMetrics {
  id: string;
  directDependents: string[];
  transitiveDependents: string[]; // packages + apps reachable upstream
  affectedApps: string[];
  minDepthFromApp: number; // shortest hops from any application (0 for apps themselves)
  factors: RiskFactors;
  criticality: number; // 0-100 composite
  riskLevel: "Critical" | "High" | "Medium" | "Low";
}

export interface PropagationResult {
  sourceId: string;
  order: string[]; // node ids in BFS order (excluding source)
  hop: Record<string, number>;
  probability: Record<string, number>; // 0-1
  etaDays: Record<string, number>;
  parent: Record<string, string>; // for path reconstruction
  maxHop: number;
}

export interface Scenario {
  id: string;
  title: string;
  packageId: string;
  narrative: string;
  attackVector: string;
  cveId: string;
  severity: "Critical" | "High" | "Medium";
}

export interface MitigationAction {
  id: string;
  title: string;
  rationale: string;
  effort: "Low" | "Medium" | "High";
  impact: number; // 0-100
  priority: number;
  category: "Contain" | "Remediate" | "Harden" | "Monitor";
  relatedNodeId?: string;
}
