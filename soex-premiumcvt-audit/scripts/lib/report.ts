import { AnalysisResult, Finding, Severity } from "./analyze";

/**
 * SARIF 2.1.0 exporter for the static IDL analyzer.
 *
 * Emitting SARIF lets the candidate findings flow into CI dashboards and code-
 * scanning UIs (GitHub Advanced Security, etc.) instead of living only in ad-hoc
 * JSON/Markdown. Everything here is a pure transform — no I/O, no network.
 *
 * These remain *candidate* leads (see docs/03-triage-rubric.md): SARIF is a
 * transport, not a verdict.
 */

const TOOL_NAME = "soex-premiumcvt-idl-analyzer";
const TOOL_VERSION = "1.0.0";
const INFO_URI =
  "https://github.com/TIMMAYTHETOOLMANN/Red-dead-X/blob/main/soex-premiumcvt-audit/docs/05-deep-analysis.md";

/** SARIF only has error/warning/note — map our five severities onto them. */
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
    case "low":
      return "warning";
    default:
      return "note";
  }
}

/** SARIF security-severity is a 0–10 string; map our severities sensibly. */
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

function ruleId(f: Finding): string {
  // One rule per (lane, title) pair keeps the rules list compact and stable.
  return `${f.lane}/${f.title}`.replace(/\s+/g, "-").toLowerCase();
}

export function toSarif(result: AnalysisResult, idlPath: string): unknown {
  const ruleIndex = new Map<string, number>();
  const rules: unknown[] = [];

  for (const f of result.findings) {
    const id = ruleId(f);
    if (ruleIndex.has(id)) continue;
    ruleIndex.set(id, rules.length);
    rules.push({
      id,
      name: f.title.replace(/\s+/g, ""),
      shortDescription: { text: f.title },
      fullDescription: { text: `${f.lane}: ${f.title}` },
      defaultConfiguration: { level: sarifLevel(f.severity) },
      properties: {
        lane: f.lane,
        "security-severity": securitySeverity(f.severity),
        tags: ["security", "solana", "anchor", f.lane],
      },
    });
  }

  const results = result.findings.map((f) => ({
    ruleId: ruleId(f),
    ruleIndex: ruleIndex.get(ruleId(f)),
    level: sarifLevel(f.severity),
    message: {
      text:
        `[${f.severity}/${f.confidence}] ${f.detail} ` +
        `Recommendation: ${f.recommendation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: idlPath },
          region: { startLine: 1 },
        },
        logicalLocations: [
          {
            name: f.account ?? f.instruction,
            fullyQualifiedName: f.account
              ? `${f.instruction}.${f.account}`
              : f.instruction,
            kind: f.account ? "member" : "function",
          },
        ],
      },
    ],
    partialFingerprints: { idlAnalyzer: f.id },
    properties: {
      instruction: f.instruction,
      account: f.account,
      confidence: f.confidence,
      risk: f.risk,
    },
  }));

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: INFO_URI,
            rules,
          },
        },
        results,
      },
    ],
  };
}
