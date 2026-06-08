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

export type Vm = "evm" | "svm";

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
  engine: "svm-static" | "evm-static";
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
    lines.push(
      `| ${f.risk} | ${f.payoutWeight} | ${f.severity} | ${f.confidence} | ${f.lane} | ` +
        `\`${loc}\` | ${f.vulnTypeId ?? "—"} | ${f.title} |`,
    );
  }
  return lines.join("\n") + "\n";
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
