import type { DepEdge, DepNode, MitigationAction, PropagationResult } from "../types";
import type { EcosystemMetrics } from "./graph";

const EFFORT_WEIGHT: Record<MitigationAction["effort"], number> = { Low: 1, Medium: 1.8, High: 2.8 };

function priorityOf(impact: number, effort: MitigationAction["effort"]): number {
  return Math.round((impact / EFFORT_WEIGHT[effort]) * 10) / 10;
}

function floatingShare(pkgId: string, edges: DepEdge[]): number {
  const incoming = edges.filter((e) => e.target === pkgId);
  if (incoming.length === 0) return 0;
  const floating = incoming.filter((e) => e.pinning !== "pinned").length;
  return floating / incoming.length;
}

export function generateScenarioMitigations(
  pkg: DepNode,
  nodeById: Map<string, DepNode>,
  edges: DepEdge[],
  metrics: EcosystemMetrics,
  propagation: PropagationResult,
): MitigationAction[] {
  const m = metrics.byId.get(pkg.id)!;
  const affectedApps = m.affectedApps.map((id) => nodeById.get(id)?.name ?? id);
  const floatShare = floatingShare(pkg.id, edges);
  const actions: MitigationAction[] = [];

  actions.push({
    id: "quarantine",
    title: `Quarantine ${pkg.name}@${pkg.version} in the registry proxy / artifact cache`,
    rationale: `Blocks new installs of the compromised version across all ${metrics.totalApps} applications while a fix is prepared. Immediately halts further spread through ${Math.round(floatShare * 100)}% of edges that auto-resolve to new versions.`,
    effort: "Low",
    impact: 92,
    category: "Contain",
    priority: 0,
    relatedNodeId: pkg.id,
  });

  actions.push({
    id: "patch",
    title: `Publish and fast-track a patched release of ${pkg.name}`,
    rationale: `Removes the root cause. ${m.directDependents.length} direct dependents and ${m.affectedApps.length} downstream applications need the fix to fully close the exposure window.`,
    effort: "Medium",
    impact: 97,
    category: "Remediate",
    priority: 0,
    relatedNodeId: pkg.id,
  });

  actions.push({
    id: "pin-good-version",
    title: `Force-pin all dependents to the last known-good version of ${pkg.name}`,
    rationale: `${Math.round(floatShare * 100)}% of direct dependents use caret/latest ranges and will silently pull the compromised release on their next install unless pinned immediately.`,
    effort: "Medium",
    impact: Math.round(40 + floatShare * 55),
    category: "Contain",
    priority: 0,
    relatedNodeId: pkg.id,
  });

  if (pkg.tags.includes("ci-cd") || pkg.tags.includes("build-tooling")) {
    actions.push({
      id: "rotate-secrets",
      title: "Rotate CI/CD credentials, signing keys and cloud tokens",
      rationale: "The compromised package executes inside build pipelines, so any secret available to those runners must be treated as exposed and rotated.",
      effort: "Medium",
      impact: 90,
      category: "Contain",
      priority: 0,
      relatedNodeId: pkg.id,
    });
  }

  if (pkg.tags.includes("crypto") || pkg.tags.includes("security") || pkg.tags.includes("logging")) {
    actions.push({
      id: "audit-secrets-crypto",
      title: "Audit and re-issue cryptographic material generated during the exposure window",
      rationale: "Keys, tokens, or signatures produced while the vulnerable component was active cannot be trusted and should be re-issued.",
      effort: "High",
      impact: 80,
      category: "Remediate",
      priority: 0,
      relatedNodeId: pkg.id,
    });
  }

  actions.push({
    id: "notify",
    title: `Notify owners of affected applications (${affectedApps.length})`,
    rationale: `Direct notification accelerates remediation for: ${affectedApps.slice(0, 6).join(", ")}${affectedApps.length > 6 ? ", …" : ""}.`,
    effort: "Low",
    impact: Math.min(85, 30 + affectedApps.length * 6),
    category: "Monitor",
    priority: 0,
    relatedNodeId: pkg.id,
  });

  actions.push({
    id: "monitor",
    title: `Enable heightened SBOM monitoring on the ${pkg.name} dependency subtree`,
    rationale: `Tracks re-introduction of the compromised version across ${propagation.order.length} transitively connected components for the next release cycle.`,
    effort: "Low",
    impact: 55,
    category: "Monitor",
    priority: 0,
    relatedNodeId: pkg.id,
  });

  if (m.riskLevel === "Critical" || m.riskLevel === "High") {
    actions.push({
      id: "replace",
      title: `Evaluate a vetted alternative to ${pkg.name} for regulated applications`,
      rationale: `Given a criticality score of ${Math.round(m.criticality)}/100 driven by a single point of maintenance and wide blast radius, long-term risk reduction requires reducing reliance on this component for high-sensitivity apps.`,
      effort: "High",
      impact: 70,
      category: "Harden",
      priority: 0,
      relatedNodeId: pkg.id,
    });
  }

  for (const a of actions) a.priority = priorityOf(a.impact, a.effort);
  return actions.sort((a, b) => b.priority - a.priority);
}

/** Ecosystem-wide, scenario-independent hardening backlog for the riskiest dependencies. */
export function generateHardeningBacklog(
  nodes: DepNode[],
  edges: DepEdge[],
  metrics: EcosystemMetrics,
  topN = 6,
): MitigationAction[] {
  const packages = nodes.filter((n) => n.kind === "package");
  const ranked = [...packages].sort((a, b) => (metrics.byId.get(b.id)?.criticality ?? 0) - (metrics.byId.get(a.id)?.criticality ?? 0));
  const actions: MitigationAction[] = [];

  for (const pkg of ranked.slice(0, topN)) {
    const m = metrics.byId.get(pkg.id)!;
    const floatShare = floatingShare(pkg.id, edges);
    const reasons: string[] = [];
    if (m.factors.blastRadius > 40) reasons.push(`reaches ${m.affectedApps.length} of ${metrics.totalApps} applications transitively`);
    if (pkg.maintainers <= 1) reasons.push("maintained by a single individual");
    if (pkg.lastCommitDaysAgo > 300) reasons.push(`last updated ${pkg.lastCommitDaysAgo} days ago`);
    if (floatShare > 0.5) reasons.push(`${Math.round(floatShare * 100)}% of dependents track floating version ranges`);
    if (pkg.hasKnownCve) reasons.push(`has an open advisory (${pkg.cveId})`);

    let title = `Harden ${pkg.name}`;
    let category: MitigationAction["category"] = "Harden";
    let effort: MitigationAction["effort"] = "Medium";

    if (pkg.hasKnownCve) {
      title = `Patch known vulnerability in ${pkg.name} (${pkg.cveId})`;
      category = "Remediate";
      effort = "Medium";
    } else if (pkg.maintainers <= 1 && floatShare > 0.5) {
      title = `Pin versions and sponsor maintenance for ${pkg.name}`;
      category = "Harden";
      effort = "Low";
    } else if (m.factors.blastRadius > 60) {
      title = `Add contingency fork / vendoring plan for ${pkg.name}`;
      category = "Harden";
      effort = "High";
    }

    const impact = Math.round(m.criticality);
    actions.push({
      id: `harden-${pkg.id}`,
      title,
      rationale: reasons.length ? `Flagged because it ${reasons.join("; ")}.` : `Composite criticality score of ${Math.round(m.criticality)}/100.`,
      effort,
      impact,
      category,
      priority: priorityOf(impact, effort),
      relatedNodeId: pkg.id,
    });
  }

  return actions.sort((a, b) => b.priority - a.priority);
}
