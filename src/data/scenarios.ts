import type { Scenario } from "../types";

export const scenarios: Scenario[] = [
  {
    id: "scn-logging",
    title: "Remote code execution in logging-core",
    packageId: "pkg-logging-core",
    narrative:
      "A maliciously crafted input triggers unsafe remote class/object resolution inside logging-core's appender pipeline, allowing arbitrary remote code execution on any service that logs attacker-controlled strings.",
    attackVector: "Untrusted input reaches a logging call -> remote lookup -> RCE",
    cveId: "CVE-2025-31337",
    severity: "Critical",
  },
  {
    id: "scn-ci-action",
    title: "Compromised maintainer account on ci-pipeline-action",
    packageId: "pkg-ci-action",
    narrative:
      "An attacker gained access to the maintainer's publish token and pushed a patched release that exfiltrates CI secrets (cloud credentials, signing keys) from every pipeline that auto-pulls the latest tag.",
    attackVector: "Stolen publish credentials -> malicious release -> secret exfiltration in CI runners",
    cveId: "CVE-2025-40221",
    severity: "Critical",
  },
  {
    id: "scn-tiny-assert",
    title: "Hijacked micro-package: tiny-assert",
    packageId: "pkg-tiny-assert",
    narrative:
      "A social-engineering attack convinced the sole maintainer to hand over publish rights. The new release adds an obfuscated payload that installs a backdoor at build time on any machine that installs it.",
    attackVector: "Maintainer takeover -> trojanized patch release -> build-time backdoor",
    cveId: "CVE-2025-48810",
    severity: "Critical",
  },
  {
    id: "scn-left-pad",
    title: "Typosquat / unpublish-republish of left-pad-alt",
    packageId: "pkg-left-pad",
    narrative:
      "The abandoned package was unpublished and re-registered by an unrelated party, who shipped a version that silently phones home and tampers with string output used in security-relevant comparisons.",
    attackVector: "Package abandonment -> namespace takeover -> tampered release",
    cveId: "CVE-2025-50302",
    severity: "High",
  },
  {
    id: "scn-crypto",
    title: "Backdoored key-generation in crypto-primitives",
    packageId: "pkg-crypto-primitives",
    narrative:
      "A subtle change weakens the entropy source used for key generation, allowing an attacker who knows the flaw to predict generated keys and forge signatures or decrypt traffic.",
    attackVector: "Weakened RNG in a minor release -> predictable keys -> signature/crypto forgery",
    cveId: "CVE-2025-55190",
    severity: "High",
  },
];
