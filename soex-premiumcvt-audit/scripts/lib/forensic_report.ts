/**
 * Unified multi-chain forensic report.
 *
 * The original scaffold emitted Solana-only SARIF/Markdown. A forensic sweep of
 * a BugRap program can now span multiple chains and engines (Solana IDL static
 * analysis, EVM ABI static analysis, economic invariant simulation). This module
 * folds those heterogeneous results into a single normalized finding stream and
 * renders one combined SARIF 2.1.0 file plus a Markdown brief, keyed by program,
 * chain, and bounty type.
 *
 * Pure transforms. No I/O, no network.
 */

import { AnalysisResult, Finding, Severity } from "./analyze";
import { EvmAnalysisResult, EvmFinding } from "./evm_analyze";
import { BytecodeFinding } from "./bytecode_fingerprint";

export type Vm = "evm" | "svm";

/**
 * Engines that can contribute to the unified stream. The two static engines
 * (Solana IDL, EVM ABI) are joined by the auxiliary analyzers (admin/authority,
 * encoding, data-state, economic invariant), the bytecode compiler-fingerprint
 * lane, and by the correlation pass that links findings into exploit chains.
 */
export type UnifiedEngine =
  | "svm-static"
  | "evm-static"
  | "bytecode-static"
  | "admin-static"
  | "encoding-static"
  | "data-static"
  | "invariant-sim"
  | "correlation";

export interface ForensicTarget {
  program: string;
  chain: string;
  vm: Vm;
  /** EVM address or Solana program id, when known. */
  address?: string | null;
  label?: string;
}

export interface UnifiedFinding {
  id: string;
  engine: UnifiedEngine;
  lane: string;
  severity: Severity;
  confidence: string;
  risk: number;
  /** Expected payout weight (USD); 0 for engines that do not weight payout. */
  payoutWeight: number;
  vulnTypeId: string | null;
  /** Function (EVM) or instruction (SVM). */
  locator: string;
  /** Account (SVM) when applicable. */
  subLocator: string | null;
  title: string;
  detail: string;
  recommendation: string;
  /**
   * Chains this finding applies to. Set by the cross-chain collapse pass when
   * the same seam is observed on more than one chain ("same seam, N chains").
   * Absent for ordinary single-chain findings.
   */
  chains?: string[];
  /**
   * Ids of the findings a correlation/exploit-chain finding was composed from.
   * Absent for primary (non-composite) findings.
   */
  components?: string[];
  /**
   * Historical breach-genealogy lineage for this finding: an ordered path of
   * addresses/contracts linking a known-compromised entity to this target (e.g.
   * `["0xBreached2021", "0xRelayWallet", "0xThisTarget"]`). Populated by the
   * Phase-3 historical-tracing pass; absent for findings with no known lineage.
   */
  genealogy?: string[];
}

export interface ForensicEntry {
  target: ForensicTarget;
  findings: UnifiedFinding[];
}

export interface ForensicReport {
  generatedAt: string;
  entries: ForensicEntry[];
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** Normalize a Solana IDL finding into the unified shape. */
export function fromSolanaFinding(f: Finding): UnifiedFinding {
  return {
    id: f.id,
    engine: "svm-static",
    lane: f.lane,
    severity: f.severity,
    confidence: f.confidence,
    risk: f.risk,
    payoutWeight: 0,
    vulnTypeId: null,
    locator: f.instruction,
    subLocator: f.account,
    title: f.title,
    detail: f.detail,
    recommendation: f.recommendation,
  };
}

/** Normalize an EVM ABI finding into the unified shape. */
export function fromEvmFinding(f: EvmFinding): UnifiedFinding {
  return {
    id: f.id,
    engine: "evm-static",
    lane: f.lane,
    severity: f.severity,
    confidence: f.confidence,
    risk: f.risk,
    payoutWeight: f.payoutWeight,
    vulnTypeId: f.vulnTypeId,
    locator: f.function,
    subLocator: null,
    title: f.title,
    detail: f.detail,
    recommendation: f.recommendation,
  };
}

/** Normalize a bytecode compiler-fingerprint finding into the unified shape. */
export function fromBytecodeFinding(f: BytecodeFinding): UnifiedFinding {
  return {
    id: f.id,
    engine: "bytecode-static",
    lane: f.lane,
    severity: f.severity,
    confidence: f.confidence,
    risk: f.risk,
    payoutWeight: f.payoutWeight,
    vulnTypeId: f.vulnTypeId,
    locator: f.locator,
    subLocator: null,
    title: f.title,
    detail: f.detail,
    recommendation: f.recommendation,
  };
}

/** Build a forensic entry from a Solana analysis result. */
export function entryFromSolana(
  target: ForensicTarget,
  result: AnalysisResult,
): ForensicEntry {
  return { target, findings: result.findings.map(fromSolanaFinding) };
}

/** Build a forensic entry from an EVM analysis result. */
export function entryFromEvm(
  target: ForensicTarget,
  result: EvmAnalysisResult,
): ForensicEntry {
  return { target, findings: result.findings.map(fromEvmFinding) };
}

export function assembleReport(entries: ForensicEntry[]): ForensicReport {
  return { generatedAt: new Date().toISOString(), entries };
}

// --- rendering -------------------------------------------------------------

function entryHeading(t: ForensicTarget): string {
  const addr = t.address ? ` \`${t.address}\`` : "";
  const label = t.label ? ` — ${t.label}` : "";
  return `${t.program} · ${t.chain} (${t.vm})${addr}${label}`;
}

function findingsTable(findings: UnifiedFinding[]): string {
  if (findings.length === 0) return "_No candidate findings._\n";
  const lines = [
    "| Risk | $weight | Severity | Conf | Lane | Locator | Type | Title |",
    "|------|---------|----------|------|------|---------|------|-------|",
  ];
  for (const f of findings) {
    const loc = f.subLocator ? `${f.locator}.${f.subLocator}` : f.locator;
    const span =
      f.chains && f.chains.length > 1 ? ` _(same seam, ${f.chains.length} chains: ${f.chains.join(", ")})_` : "";
    lines.push(
      `| ${f.risk} | ${f.payoutWeight} | ${f.severity} | ${f.confidence} | ${f.lane} | ` +
        `\`${loc}\` | ${f.vulnTypeId ?? "—"} | ${f.title}${span} |`,
    );
  }
  return lines.join("\n") + "\n";
}

// --- attack-path graph (machine-readable, Cytoscape/D3-compatible) ----------

export interface GraphNode {
  /** Stable node id (a finding id, or a chain/target/genealogy address). */
  data: { id: string; label: string; type: string; severity?: Severity };
}

export interface GraphEdge {
  data: { id: string; source: string; target: string; relation: string };
}

export interface AttackPathGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Derive an interactive attack-path graph from the report. Nodes are findings;
 * edges encode the two kinds of paths already modelled in the unified stream:
 *   - `enables` — a correlation/exploit-chain finding (`components`) points back
 *     to each finding it was composed from (A → B exploit chains).
 *   - `lineage` — a breach-genealogy path (`genealogy`) is rendered as a chain of
 *     address nodes leading into the finding (historical compromise → target).
 * The shape is Cytoscape.js `elements` (also trivially consumable by D3).
 */
export function attackPathGraph(report: ForensicReport): AttackPathGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const addNode = (n: GraphNode) => {
    if (!nodes.has(n.data.id)) nodes.set(n.data.id, n);
  };

  for (const entry of report.entries) {
    for (const f of entry.findings) {
      addNode({
        data: {
          id: f.id,
          label: f.title,
          type: `finding:${f.engine}`,
          severity: f.severity,
        },
      });

      // Exploit-chain edges: composite finding → each component finding.
      for (const c of f.components ?? []) {
        addNode({ data: { id: c, label: c, type: "finding" } });
        edges.push({
          data: { id: `${f.id}->${c}`, source: f.id, target: c, relation: "enables" },
        });
      }

      // Breach-genealogy edges: address lineage flowing into the finding.
      const lineage = f.genealogy ?? [];
      for (let i = 0; i < lineage.length; i++) {
        const addr = lineage[i];
        addNode({ data: { id: addr, label: addr, type: "address" } });
        const next = i + 1 < lineage.length ? lineage[i + 1] : f.id;
        edges.push({
          data: {
            id: `${addr}->${next}`,
            source: addr,
            target: next,
            relation: "lineage",
          },
        });
      }
    }
  }

  return { nodes: [...nodes.values()], edges };
}

function genealogySection(report: ForensicReport): string {
  const paths: string[] = [];
  for (const entry of report.entries) {
    for (const f of entry.findings) {
      if (f.genealogy && f.genealogy.length > 0) {
        paths.push(`- \`${f.locator}\` ← ${f.genealogy.join(" → ")} _(${f.title})_`);
      }
    }
  }
  let md = `\n## Breach genealogy paths\n\n`;
  if (paths.length === 0) {
    md +=
      "_No historical breach lineage linked to these targets yet._ " +
      "Populate from the historical-tracing DB (see `db/`) to escalate targets " +
      "that share lineage with known-compromised contracts.\n";
  } else {
    md += paths.join("\n") + "\n";
  }
  return md;
}

function attackPathGraphSection(report: ForensicReport): string {
  const graph = attackPathGraph(report);
  return (
    `\n## Attack-path graph\n\n` +
    `Machine-readable graph (Cytoscape.js \`elements\` / D3-compatible): ` +
    `${graph.nodes.length} nodes, ${graph.edges.length} edges. ` +
    `Render to visualise how an enabler or a compromised wallet reaches a core seam.\n\n` +
    "```json\n" +
    JSON.stringify({ nodes: graph.nodes, edges: graph.edges }, null, 2) +
    "\n```\n"
  );
}

export function toMarkdown(report: ForensicReport): string {
  const totalFindings = report.entries.reduce((s, e) => s + e.findings.length, 0);
  let md =
    `# Multi-chain forensic report\n\n` +
    `- Generated: ${report.generatedAt}\n` +
    `- Targets: ${report.entries.length}\n` +
    `- Candidate findings: ${totalFindings}\n\n` +
    `> Candidates to confirm by hand — see docs/03-triage-rubric.md. Tooling never reports a verdict.\n`;
  for (const entry of report.entries) {
    md += `\n## ${entryHeading(entry.target)}\n\n`;
    md += findingsTable(entry.findings);
  }
  md += genealogySection(report);
  md += attackPathGraphSection(report);
  return md;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "note";
}

function securitySeverity(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.5";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

function ruleId(f: UnifiedFinding): string {
  return `${f.engine}/${f.lane}`.replace(/\s+/g, "-").toLowerCase();
}

export function toSarif(report: ForensicReport): unknown {
  const ruleIndex = new Map<string, number>();
  const rules: unknown[] = [];
  const results: unknown[] = [];

  for (const entry of report.entries) {
    const uri = entry.target.address
      ? `${entry.target.chain}/${entry.target.address}`
      : `${entry.target.program}/${entry.target.chain}`;
    for (const f of [...entry.findings].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    )) {
      const rid = ruleId(f);
      if (!ruleIndex.has(rid)) {
        ruleIndex.set(rid, rules.length);
        rules.push({
          id: rid,
          name: `${f.engine}-${f.lane}`.replace(/[^A-Za-z0-9]/g, ""),
          shortDescription: { text: `${f.engine}: ${f.lane}` },
          defaultConfiguration: { level: sarifLevel(f.severity) },
          properties: {
            engine: f.engine,
            lane: f.lane,
            "security-severity": securitySeverity(f.severity),
            tags: ["security", "web3", f.engine, f.lane],
          },
        });
      }
      const loc = f.subLocator ? `${f.locator}.${f.subLocator}` : f.locator;
      results.push({
        ruleId: rid,
        ruleIndex: ruleIndex.get(rid),
        level: sarifLevel(f.severity),
        message: {
          text:
            `[${f.severity}/${f.confidence}] ${f.detail} ` +
            `Recommendation: ${f.recommendation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri },
              region: { startLine: 1 },
            },
            logicalLocations: [
              { name: loc, fullyQualifiedName: `${uri}#${loc}`, kind: "function" },
            ],
          },
        ],
        partialFingerprints: { forensic: f.id },
        properties: {
          program: entry.target.program,
          chain: entry.target.chain,
          vm: entry.target.vm,
          confidence: f.confidence,
          risk: f.risk,
          payoutWeight: f.payoutWeight,
          vulnTypeId: f.vulnTypeId,
          ...(f.chains ? { chains: f.chains } : {}),
          ...(f.components ? { components: f.components } : {}),
          ...(f.genealogy ? { genealogy: f.genealogy } : {}),
        },
      });
    }
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "reddead-x-forensic",
            version: "1.0.0",
            informationUri:
              "https://github.com/TIMMAYTHETOOLMANN/Red-dead-X/blob/main/soex-premiumcvt-audit/docs/06-multichain-forensics.md",
            rules,
          },
        },
        results,
      },
    ],
  };
}
