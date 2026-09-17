import type { DepEdge, DepNode } from "../types";

// -----------------------------------------------------------------------
// Simulated software ecosystem: 10 consumer applications built on top of a
// realistic, multi-tier open-source dependency stack (frameworks -> shared
// utilities -> deep low-level "leaf" packages). Names are fictional but
// modeled after real-world archetypes (logging frameworks, tiny string
// utilities, CI actions, container base images, crypto primitives, etc.)
// -----------------------------------------------------------------------

export const nodes: DepNode[] = [
  // ---------------- Applications (tier 0) ----------------
  { id: "app-checkout", name: "Nimbus Checkout", kind: "application", ecosystem: "npm", version: "3.4.0", tier: 0, description: "Customer-facing e-commerce checkout & payments frontend.", maintainers: 14, weeklyDownloads: 2_400_000, lastCommitDaysAgo: 1, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["ecommerce", "customer-facing"] },
  { id: "app-ledger", name: "Fintrace Ledger", kind: "application", ecosystem: "maven", version: "8.1.2", tier: 0, description: "Double-entry ledger and settlement engine for fintech clients.", maintainers: 9, weeklyDownloads: 310_000, lastCommitDaysAgo: 2, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["fintech", "regulated"] },
  { id: "app-medsync", name: "MedSync Portal", kind: "application", ecosystem: "pypi", version: "5.0.1", tier: 0, description: "Patient records and scheduling portal for clinics.", maintainers: 11, weeklyDownloads: 180_000, lastCommitDaysAgo: 3, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["healthcare", "regulated"] },
  { id: "app-geopulse", name: "GeoPulse Maps", kind: "application", ecosystem: "npm", version: "2.2.0", tier: 0, description: "Realtime mapping and geofencing SDK for logistics apps.", maintainers: 7, weeklyDownloads: 640_000, lastCommitDaysAgo: 4, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["mapping"] },
  { id: "app-streamforge", name: "StreamForge Media", kind: "application", ecosystem: "npm", version: "4.7.3", tier: 0, description: "Live video transcoding and streaming platform.", maintainers: 16, weeklyDownloads: 1_100_000, lastCommitDaysAgo: 1, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["media", "customer-facing"] },
  { id: "app-quantabank", name: "QuantaBank API", kind: "application", ecosystem: "maven", version: "12.0.0", tier: 0, description: "Core banking API gateway for retail banking products.", maintainers: 22, weeklyDownloads: 95_000, lastCommitDaysAgo: 2, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["fintech", "regulated"] },
  { id: "app-civicvote", name: "CivicVote Platform", kind: "application", ecosystem: "go", version: "1.9.4", tier: 0, description: "Municipal e-participation and voting infrastructure.", maintainers: 5, weeklyDownloads: 40_000, lastCommitDaysAgo: 6, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["government", "regulated"] },
  { id: "app-edusphere", name: "EduSphere LMS", kind: "application", ecosystem: "npm", version: "6.3.1", tier: 0, description: "Learning management system used by universities.", maintainers: 10, weeklyDownloads: 520_000, lastCommitDaysAgo: 5, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["education"] },
  { id: "app-logichain", name: "LogiChain Freight", kind: "application", ecosystem: "pypi", version: "3.1.0", tier: 0, description: "Freight tracking and customs documentation platform.", maintainers: 8, weeklyDownloads: 75_000, lastCommitDaysAgo: 3, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["logistics"] },
  { id: "app-pulsecrm", name: "PulseCRM", kind: "application", ecosystem: "npm", version: "9.5.0", tier: 0, description: "Sales and customer relationship management suite.", maintainers: 13, weeklyDownloads: 780_000, lastCommitDaysAgo: 2, vulnerabilityScore: 0, hasKnownCve: false, license: "Proprietary", tags: ["saas", "customer-facing"] },

  // ---------------- Tier 1: frameworks / SDKs ----------------
  { id: "pkg-web-framework", name: "web-framework-core", kind: "package", ecosystem: "npm", version: "14.2.1", tier: 1, description: "Full-stack web application framework (routing, SSR, middleware).", maintainers: 6, weeklyDownloads: 28_000_000, lastCommitDaysAgo: 2, vulnerabilityScore: 3.1, hasKnownCve: false, license: "MIT", tags: ["framework"] },
  { id: "pkg-api-gateway", name: "api-gateway-sdk", kind: "package", ecosystem: "npm", version: "6.0.4", tier: 1, description: "Client SDK for building and consuming API gateway routes.", maintainers: 4, weeklyDownloads: 11_000_000, lastCommitDaysAgo: 9, vulnerabilityScore: 4.4, hasKnownCve: false, license: "Apache-2.0", tags: ["networking"] },
  { id: "pkg-orm-toolkit", name: "orm-toolkit", kind: "package", ecosystem: "maven", version: "5.3.0", tier: 1, description: "Object-relational mapping toolkit for JVM services.", maintainers: 5, weeklyDownloads: 6_200_000, lastCommitDaysAgo: 14, vulnerabilityScore: 3.8, hasKnownCve: false, license: "Apache-2.0", tags: ["database"] },
  { id: "pkg-auth-guard", name: "auth-guard", kind: "package", ecosystem: "npm", version: "3.9.2", tier: 1, description: "Authentication & session middleware (OAuth2/OIDC support).", maintainers: 3, weeklyDownloads: 9_800_000, lastCommitDaysAgo: 4, vulnerabilityScore: 5.6, hasKnownCve: false, license: "MIT", tags: ["auth", "security"] },
  { id: "pkg-payment-connector", name: "payment-connector", kind: "package", ecosystem: "npm", version: "2.4.0", tier: 1, description: "Unified connector for card and bank-transfer payment rails.", maintainers: 4, weeklyDownloads: 3_100_000, lastCommitDaysAgo: 7, vulnerabilityScore: 4.9, hasKnownCve: false, license: "MIT", tags: ["payments", "regulated"] },
  { id: "pkg-ui-kit", name: "ui-component-kit", kind: "package", ecosystem: "npm", version: "18.1.0", tier: 1, description: "Shared design-system component library.", maintainers: 8, weeklyDownloads: 15_500_000, lastCommitDaysAgo: 1, vulnerabilityScore: 1.8, hasKnownCve: false, license: "MIT", tags: ["ui"] },
  { id: "pkg-message-queue", name: "message-queue-client", kind: "package", ecosystem: "go", version: "4.1.6", tier: 1, description: "Client library for distributed message queues and pub/sub.", maintainers: 5, weeklyDownloads: 4_700_000, lastCommitDaysAgo: 11, vulnerabilityScore: 3.4, hasKnownCve: false, license: "Apache-2.0", tags: ["infra"] },
  { id: "pkg-ci-action", name: "ci-pipeline-action", kind: "package", ecosystem: "npm", version: "1.12.0", tier: 1, description: "Reusable CI/CD pipeline action for build, test & deploy steps.", maintainers: 2, weeklyDownloads: 7_400_000, lastCommitDaysAgo: 6, vulnerabilityScore: 8.1, hasKnownCve: true, cveId: "CVE-2025-40221", license: "MIT", tags: ["ci-cd", "build-tooling"] },
  { id: "pkg-container-base", name: "container-base-alpine", kind: "package", ecosystem: "docker", version: "3.19.0", tier: 1, description: "Minimal base container image used across microservices.", maintainers: 4, weeklyDownloads: 19_000_000, lastCommitDaysAgo: 3, vulnerabilityScore: 5.4, hasKnownCve: false, license: "MIT", tags: ["infra", "container"] },
  { id: "pkg-ml-runtime", name: "ml-inference-runtime", kind: "package", ecosystem: "pypi", version: "2.6.3", tier: 1, description: "Runtime for serving machine-learning inference workloads.", maintainers: 6, weeklyDownloads: 2_900_000, lastCommitDaysAgo: 8, vulnerabilityScore: 4.0, hasKnownCve: false, license: "Apache-2.0", tags: ["ml"] },

  // ---------------- Tier 2: shared utilities ----------------
  { id: "pkg-http-fetch", name: "http-fetch-lite", kind: "package", ecosystem: "npm", version: "9.0.1", tier: 2, description: "Lightweight promise-based HTTP client.", maintainers: 3, weeklyDownloads: 33_000_000, lastCommitDaysAgo: 5, vulnerabilityScore: 3.6, hasKnownCve: false, license: "MIT", tags: ["networking"] },
  { id: "pkg-json-schema", name: "json-schema-validate", kind: "package", ecosystem: "npm", version: "7.2.0", tier: 2, description: "JSON Schema validation engine.", maintainers: 2, weeklyDownloads: 21_000_000, lastCommitDaysAgo: 20, vulnerabilityScore: 2.9, hasKnownCve: false, license: "MIT", tags: ["validation"] },
  { id: "pkg-date-util", name: "date-util-plus", kind: "package", ecosystem: "npm", version: "3.3.3", tier: 2, description: "Date parsing, formatting & timezone utilities.", maintainers: 2, weeklyDownloads: 18_000_000, lastCommitDaysAgo: 45, vulnerabilityScore: 1.2, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-logging-core", name: "logging-core", kind: "package", ecosystem: "maven", version: "2.17.9", tier: 2, description: "Ubiquitous structured logging framework with remote appenders.", maintainers: 2, weeklyDownloads: 42_000_000, lastCommitDaysAgo: 5, vulnerabilityScore: 9.8, hasKnownCve: true, cveId: "CVE-2025-31337", license: "Apache-2.0", tags: ["logging", "critical-infra"] },
  { id: "pkg-crypto-primitives", name: "crypto-primitives", kind: "package", ecosystem: "npm", version: "4.5.1", tier: 2, description: "Low-level cryptographic primitives (hashing, signing, KDF).", maintainers: 3, weeklyDownloads: 12_000_000, lastCommitDaysAgo: 15, vulnerabilityScore: 6.5, hasKnownCve: false, license: "MIT", tags: ["crypto", "security"] },
  { id: "pkg-config-loader", name: "config-loader", kind: "package", ecosystem: "pypi", version: "1.8.0", tier: 2, description: "Hierarchical configuration & secrets loader.", maintainers: 1, weeklyDownloads: 8_900_000, lastCommitDaysAgo: 200, vulnerabilityScore: 4.2, hasKnownCve: false, license: "MIT", tags: ["config"] },
  { id: "pkg-template-engine", name: "template-engine-mini", kind: "package", ecosystem: "npm", version: "5.1.4", tier: 2, description: "Minimal server-side templating engine.", maintainers: 2, weeklyDownloads: 9_400_000, lastCommitDaysAgo: 60, vulnerabilityScore: 3.0, hasKnownCve: false, license: "MIT", tags: ["templating"] },
  { id: "pkg-retry-backoff", name: "retry-backoff", kind: "package", ecosystem: "go", version: "2.0.9", tier: 2, description: "Exponential backoff & retry helper for network calls.", maintainers: 2, weeklyDownloads: 7_600_000, lastCommitDaysAgo: 30, vulnerabilityScore: 1.0, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-event-emitter", name: "event-emitter-fast", kind: "package", ecosystem: "npm", version: "3.6.0", tier: 2, description: "High-performance event emitter implementation.", maintainers: 1, weeklyDownloads: 26_000_000, lastCommitDaysAgo: 400, vulnerabilityScore: 2.1, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-string-format", name: "string-format-utils", kind: "package", ecosystem: "npm", version: "6.0.2", tier: 2, description: "String interpolation & formatting helpers.", maintainers: 1, weeklyDownloads: 31_000_000, lastCommitDaysAgo: 250, vulnerabilityScore: 1.4, hasKnownCve: false, license: "MIT", tags: ["utility"] },

  // ---------------- Tier 3: deep low-level packages ----------------
  { id: "pkg-left-pad", name: "left-pad-alt", kind: "package", ecosystem: "npm", version: "1.3.0", tier: 3, description: "Pads the left side of a string. Used almost everywhere.", maintainers: 1, weeklyDownloads: 51_000_000, lastCommitDaysAgo: 900, vulnerabilityScore: 1.0, hasKnownCve: false, license: "WTFPL", tags: ["utility", "micro-package"] },
  { id: "pkg-byte-buffer", name: "byte-buffer-core", kind: "package", ecosystem: "npm", version: "2.9.0", tier: 3, description: "Binary buffer allocation & manipulation primitives.", maintainers: 2, weeklyDownloads: 24_000_000, lastCommitDaysAgo: 150, vulnerabilityScore: 5.1, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-ansi-color", name: "ansi-color-codes", kind: "package", ecosystem: "npm", version: "4.0.0", tier: 3, description: "Terminal ANSI color/style codes helper.", maintainers: 1, weeklyDownloads: 39_000_000, lastCommitDaysAgo: 500, vulnerabilityScore: 0.5, hasKnownCve: false, license: "MIT", tags: ["utility", "micro-package"] },
  { id: "pkg-uuid-gen", name: "uuid-gen-lite", kind: "package", ecosystem: "npm", version: "8.3.1", tier: 3, description: "RFC-4122 UUID generator.", maintainers: 2, weeklyDownloads: 44_000_000, lastCommitDaysAgo: 90, vulnerabilityScore: 2.0, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-semver-parse", name: "semver-parse-lite", kind: "package", ecosystem: "npm", version: "7.5.2", tier: 3, description: "Semantic version parsing & range matching.", maintainers: 2, weeklyDownloads: 46_000_000, lastCommitDaysAgo: 40, vulnerabilityScore: 1.6, hasKnownCve: false, license: "MIT", tags: ["utility"] },
  { id: "pkg-base64-shim", name: "base64-shim", kind: "package", ecosystem: "npm", version: "1.1.0", tier: 3, description: "Cross-runtime base64 encode/decode shim.", maintainers: 1, weeklyDownloads: 28_000_000, lastCommitDaysAgo: 700, vulnerabilityScore: 0.8, hasKnownCve: false, license: "MIT", tags: ["utility", "micro-package"] },

  // ---------------- Tier 4: root-level, maximum fan-in ----------------
  { id: "pkg-core-polyfill", name: "core-polyfill-shim", kind: "package", ecosystem: "npm", version: "3.0.0", tier: 4, description: "Polyfills for core language/runtime features.", maintainers: 1, weeklyDownloads: 60_000_000, lastCommitDaysAgo: 800, vulnerabilityScore: 2.2, hasKnownCve: false, license: "MIT", tags: ["utility", "micro-package"] },
  { id: "pkg-tiny-assert", name: "tiny-assert", kind: "package", ecosystem: "npm", version: "0.4.1", tier: 4, description: "A single-function assertion helper. One of the most depended-upon packages in the registry.", maintainers: 1, weeklyDownloads: 88_000_000, lastCommitDaysAgo: 620, vulnerabilityScore: 3.2, hasKnownCve: false, license: "MIT", tags: ["utility", "micro-package"] },
  { id: "pkg-env-detect", name: "env-detect", kind: "package", ecosystem: "npm", version: "2.1.0", tier: 4, description: "Detects runtime environment (browser/node/edge/worker).", maintainers: 1, weeklyDownloads: 34_000_000, lastCommitDaysAgo: 550, vulnerabilityScore: 1.1, hasKnownCve: false, license: "MIT", tags: ["utility", "micro-package"] },
];

export const edges: DepEdge[] = [
  // Applications -> Tier 1
  { source: "app-checkout", target: "pkg-web-framework", pinning: "pinned" },
  { source: "app-checkout", target: "pkg-api-gateway", pinning: "pinned" },
  { source: "app-checkout", target: "pkg-payment-connector", pinning: "pinned" },
  { source: "app-checkout", target: "pkg-ui-kit", pinning: "caret" },

  { source: "app-ledger", target: "pkg-orm-toolkit", pinning: "pinned" },
  { source: "app-ledger", target: "pkg-api-gateway", pinning: "pinned" },
  { source: "app-ledger", target: "pkg-message-queue", pinning: "pinned" },
  { source: "app-ledger", target: "pkg-auth-guard", pinning: "pinned" },
  { source: "app-ledger", target: "pkg-logging-core", pinning: "caret" },

  { source: "app-medsync", target: "pkg-web-framework", pinning: "caret" },
  { source: "app-medsync", target: "pkg-auth-guard", pinning: "pinned" },
  { source: "app-medsync", target: "pkg-ml-runtime", pinning: "pinned" },
  { source: "app-medsync", target: "pkg-container-base", pinning: "latest" },
  { source: "app-medsync", target: "pkg-logging-core", pinning: "caret" },

  { source: "app-geopulse", target: "pkg-web-framework", pinning: "caret" },
  { source: "app-geopulse", target: "pkg-ui-kit", pinning: "caret" },
  { source: "app-geopulse", target: "pkg-api-gateway", pinning: "pinned" },

  { source: "app-streamforge", target: "pkg-message-queue", pinning: "pinned" },
  { source: "app-streamforge", target: "pkg-ui-kit", pinning: "caret" },
  { source: "app-streamforge", target: "pkg-container-base", pinning: "latest" },
  { source: "app-streamforge", target: "pkg-ci-action", pinning: "latest" },

  { source: "app-quantabank", target: "pkg-orm-toolkit", pinning: "pinned" },
  { source: "app-quantabank", target: "pkg-auth-guard", pinning: "pinned" },
  { source: "app-quantabank", target: "pkg-payment-connector", pinning: "pinned" },
  { source: "app-quantabank", target: "pkg-api-gateway", pinning: "pinned" },
  { source: "app-quantabank", target: "pkg-logging-core", pinning: "pinned" },

  { source: "app-civicvote", target: "pkg-web-framework", pinning: "pinned" },
  { source: "app-civicvote", target: "pkg-auth-guard", pinning: "pinned" },
  { source: "app-civicvote", target: "pkg-message-queue", pinning: "caret" },

  { source: "app-edusphere", target: "pkg-web-framework", pinning: "caret" },
  { source: "app-edusphere", target: "pkg-ui-kit", pinning: "caret" },
  { source: "app-edusphere", target: "pkg-ci-action", pinning: "latest" },

  { source: "app-logichain", target: "pkg-api-gateway", pinning: "caret" },
  { source: "app-logichain", target: "pkg-message-queue", pinning: "pinned" },
  { source: "app-logichain", target: "pkg-orm-toolkit", pinning: "caret" },
  { source: "app-logichain", target: "pkg-container-base", pinning: "latest" },

  { source: "app-pulsecrm", target: "pkg-web-framework", pinning: "caret" },
  { source: "app-pulsecrm", target: "pkg-ui-kit", pinning: "caret" },
  { source: "app-pulsecrm", target: "pkg-auth-guard", pinning: "pinned" },
  { source: "app-pulsecrm", target: "pkg-ci-action", pinning: "latest" },

  // Tier 1 -> Tier 2
  { source: "pkg-web-framework", target: "pkg-http-fetch", pinning: "caret" },
  { source: "pkg-web-framework", target: "pkg-json-schema", pinning: "caret" },
  { source: "pkg-web-framework", target: "pkg-template-engine", pinning: "caret" },
  { source: "pkg-web-framework", target: "pkg-logging-core", pinning: "caret" },
  { source: "pkg-web-framework", target: "pkg-event-emitter", pinning: "latest" },

  { source: "pkg-api-gateway", target: "pkg-http-fetch", pinning: "caret" },
  { source: "pkg-api-gateway", target: "pkg-json-schema", pinning: "caret" },
  { source: "pkg-api-gateway", target: "pkg-retry-backoff", pinning: "caret" },
  { source: "pkg-api-gateway", target: "pkg-logging-core", pinning: "caret" },

  { source: "pkg-orm-toolkit", target: "pkg-date-util", pinning: "caret" },
  { source: "pkg-orm-toolkit", target: "pkg-logging-core", pinning: "pinned" },
  { source: "pkg-orm-toolkit", target: "pkg-config-loader", pinning: "caret" },

  { source: "pkg-auth-guard", target: "pkg-crypto-primitives", pinning: "pinned" },
  { source: "pkg-auth-guard", target: "pkg-logging-core", pinning: "caret" },
  { source: "pkg-auth-guard", target: "pkg-config-loader", pinning: "caret" },

  { source: "pkg-payment-connector", target: "pkg-crypto-primitives", pinning: "pinned" },
  { source: "pkg-payment-connector", target: "pkg-http-fetch", pinning: "caret" },
  { source: "pkg-payment-connector", target: "pkg-logging-core", pinning: "pinned" },

  { source: "pkg-ui-kit", target: "pkg-event-emitter", pinning: "latest" },
  { source: "pkg-ui-kit", target: "pkg-string-format", pinning: "latest" },
  { source: "pkg-ui-kit", target: "pkg-template-engine", pinning: "caret" },

  { source: "pkg-message-queue", target: "pkg-retry-backoff", pinning: "caret" },
  { source: "pkg-message-queue", target: "pkg-logging-core", pinning: "caret" },
  { source: "pkg-message-queue", target: "pkg-byte-buffer", pinning: "caret" },

  { source: "pkg-ci-action", target: "pkg-config-loader", pinning: "latest" },
  { source: "pkg-ci-action", target: "pkg-logging-core", pinning: "latest" },
  { source: "pkg-ci-action", target: "pkg-http-fetch", pinning: "latest" },

  { source: "pkg-container-base", target: "pkg-core-polyfill", pinning: "latest" },
  { source: "pkg-container-base", target: "pkg-env-detect", pinning: "latest" },

  { source: "pkg-ml-runtime", target: "pkg-config-loader", pinning: "caret" },
  { source: "pkg-ml-runtime", target: "pkg-date-util", pinning: "caret" },
  { source: "pkg-ml-runtime", target: "pkg-logging-core", pinning: "caret" },

  // Tier 2 -> Tier 3
  { source: "pkg-http-fetch", target: "pkg-uuid-gen", pinning: "caret" },
  { source: "pkg-http-fetch", target: "pkg-semver-parse", pinning: "caret" },

  { source: "pkg-json-schema", target: "pkg-semver-parse", pinning: "caret" },
  { source: "pkg-json-schema", target: "pkg-left-pad", pinning: "latest" },

  { source: "pkg-date-util", target: "pkg-left-pad", pinning: "caret" },
  { source: "pkg-date-util", target: "pkg-base64-shim", pinning: "latest" },

  { source: "pkg-logging-core", target: "pkg-ansi-color", pinning: "caret" },
  { source: "pkg-logging-core", target: "pkg-byte-buffer", pinning: "caret" },
  { source: "pkg-logging-core", target: "pkg-left-pad", pinning: "latest" },

  { source: "pkg-crypto-primitives", target: "pkg-byte-buffer", pinning: "pinned" },
  { source: "pkg-crypto-primitives", target: "pkg-base64-shim", pinning: "caret" },

  { source: "pkg-config-loader", target: "pkg-semver-parse", pinning: "caret" },
  { source: "pkg-config-loader", target: "pkg-left-pad", pinning: "latest" },

  { source: "pkg-template-engine", target: "pkg-left-pad", pinning: "caret" },
  { source: "pkg-template-engine", target: "pkg-ansi-color", pinning: "latest" },

  { source: "pkg-retry-backoff", target: "pkg-uuid-gen", pinning: "caret" },

  { source: "pkg-event-emitter", target: "pkg-left-pad", pinning: "latest" },

  { source: "pkg-string-format", target: "pkg-left-pad", pinning: "latest" },

  // Tier 3 -> Tier 4
  { source: "pkg-left-pad", target: "pkg-tiny-assert", pinning: "latest" },
  { source: "pkg-byte-buffer", target: "pkg-tiny-assert", pinning: "caret" },
  { source: "pkg-byte-buffer", target: "pkg-env-detect", pinning: "caret" },
  { source: "pkg-ansi-color", target: "pkg-env-detect", pinning: "latest" },
  { source: "pkg-uuid-gen", target: "pkg-tiny-assert", pinning: "caret" },
  { source: "pkg-semver-parse", target: "pkg-tiny-assert", pinning: "caret" },
  { source: "pkg-base64-shim", target: "pkg-tiny-assert", pinning: "latest" },
];

export const nodeById = new Map(nodes.map((n) => [n.id, n]));
