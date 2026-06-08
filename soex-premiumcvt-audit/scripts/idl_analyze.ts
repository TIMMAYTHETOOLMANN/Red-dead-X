import "dotenv/config";
import fs from "fs";
import { loadIdl } from "./lib/idl";
import {
  analyzeIdl,
  applyBaseline,
  Finding,
  MatrixRow,
  Severity,
  SEVERITY_ORDER,
} from "./lib/analyze";
import { toSarif } from "./lib/report";

/**
 * Deep static IDL analyzer (read-only, no chain access).
 *
 * Loads the pinned IDL, walks every instruction through the six hunting lanes,
 * and writes candidate findings + an auto-built instruction/account matrix to
 * `evidence/`. These are leads to confirm by hand, not verdicts — the triage
 * rubric in docs/03 still gates what becomes a report.
 */

const idlPath = (process.env.IDL_PATH ?? "./targets/premiumcvt.json").trim();
const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
const baselinePath = (process.env.BASELINE_PATH ?? "").trim();
const failOn = (process.env.FAIL_ON ?? "").trim().toLowerCase();

/** Load suppression ids from a baseline file (JSON array, or one id per line). */
function loadBaselineIds(path: string): string[] {
  const raw = fs.readFileSync(path, "utf8").trim();
  if (raw === "") return [];
  if (raw.startsWith("[")) {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map((x) => String(x));
  }
  return raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

/** Count findings at or above the configured fail-on severity threshold. */
function countAtOrAbove(findings: Finding[], threshold: Severity): number {
  const max = SEVERITY_ORDER.indexOf(threshold);
  return findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= max).length;
}

function findingsToMarkdown(findings: Finding[]): string {
  if (findings.length === 0) return "_No candidate findings._\n";
  const lines = [
    "| Risk | Severity | Confidence | Lane | Instruction | Account | Title | ID |",
    "|------|----------|------------|------|-------------|---------|-------|----|",
  ];
  for (const f of findings) {
    lines.push(
      `| ${f.risk} | ${f.severity} | ${f.confidence} | ${f.lane} | \`${f.instruction}\` | ${
        f.account ? `\`${f.account}\`` : "—"
      } | ${f.title} | \`${f.id}\` |`,
    );
  }
  return lines.join("\n") + "\n";
}

function matrixToMarkdown(matrix: MatrixRow[]): string {
  const lines = [
    "| Instruction | Account | Signer | Writable | Seeds | Pinned addr | Relations |",
    "|-------------|---------|--------|----------|-------|-------------|-----------|",
  ];
  for (const r of matrix) {
    lines.push(
      `| \`${r.instruction}\` | \`${r.account}\` | ${r.signer ? "yes" : ""} | ${
        r.writable ? "yes" : ""
      } | ${r.seeds || ""} | ${r.pinnedAddress ? "yes" : ""} | ${r.relations || ""} |`,
    );
  }
  return lines.join("\n") + "\n";
}

function main() {
  if (!fs.existsSync(idlPath)) {
    throw new Error(
      `IDL not found at ${idlPath}. Pin IDL_PATH in .env to the official PremiumCVT IDL ` +
        `(never guess it).`,
    );
  }

  const idl = loadIdl(idlPath);
  if (idl.instructions.length === 0) {
    console.warn(
      "Warning: IDL parsed but contains no instructions. Check the IDL format/path.",
    );
  }

  const result = analyzeIdl(idl);

  // Baseline suppression (enhancement): drop previously-accepted findings so CI
  // only surfaces *new* seams. The full result is still written for the record.
  let suppressed = 0;
  let activeFindings = result.findings;
  if (baselinePath) {
    if (!fs.existsSync(baselinePath)) {
      throw new Error(`BASELINE_PATH set but file not found at ${baselinePath}.`);
    }
    const applied = applyBaseline(result.findings, loadBaselineIds(baselinePath));
    activeFindings = applied.kept;
    suppressed = applied.suppressed;
  }

  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");

  const jsonOut = `${evidenceDir}/idl-analysis-${stamp}.json`;
  fs.writeFileSync(
    jsonOut,
    JSON.stringify(
      {
        idlPath,
        analyzedAt: new Date().toISOString(),
        readOnly: true,
        baselinePath: baselinePath || null,
        suppressed,
        ...result,
        activeFindings,
      },
      null,
      2,
    ),
  );

  // SARIF for CI / code-scanning integration (enhancement).
  const sarifOut = `${evidenceDir}/idl-analysis-${stamp}.sarif`;
  fs.writeFileSync(
    sarifOut,
    JSON.stringify(toSarif({ ...result, findings: activeFindings }, idlPath), null, 2),
  );

  const mdOut = `${evidenceDir}/idl-analysis-${stamp}.md`;
  const md =
    `# IDL static analysis — ${result.program}\n\n` +
    `- IDL: \`${idlPath}\`\n` +
    `- Program address: ${result.address ?? "(none in IDL)"}\n` +
    `- Instructions: ${result.instructionCount}\n` +
    `- Max risk: ${result.maxRisk}\n` +
    `- Severity counts: ${JSON.stringify(result.severityCounts)}\n` +
    `- Lane counts: ${JSON.stringify(result.laneCounts)}\n` +
    (baselinePath ? `- Suppressed by baseline: ${suppressed}\n` : "") +
    `\n## Candidate findings (confirm by hand — see docs/03-triage-rubric.md)\n\n` +
    findingsToMarkdown(activeFindings) +
    `\n## Instruction / account matrix\n\n` +
    matrixToMarkdown(result.matrix);
  fs.writeFileSync(mdOut, md);

  console.log(`Wrote ${jsonOut}`);
  console.log(`Wrote ${sarifOut}`);
  console.log(`Wrote ${mdOut}`);
  console.log(
    `\nProgram: ${result.program}  Instructions: ${result.instructionCount}  ` +
      `Findings: ${activeFindings.length}` +
      (suppressed ? ` (+${suppressed} suppressed)` : ""),
  );
  console.log("Severity:", result.severityCounts);
  if (activeFindings.length > 0) {
    console.table(
      activeFindings.map((f) => ({
        risk: f.risk,
        severity: f.severity,
        confidence: f.confidence,
        lane: f.lane,
        instruction: f.instruction,
        account: f.account ?? "",
        title: f.title,
      })),
    );
  }

  // CI severity gating (enhancement): exit non-zero when findings at or above
  // the FAIL_ON threshold remain after baseline suppression.
  if (failOn) {
    if (!SEVERITY_ORDER.includes(failOn as Severity)) {
      throw new Error(
        `FAIL_ON must be one of ${SEVERITY_ORDER.join(", ")}; got "${failOn}".`,
      );
    }
    const breaches = countAtOrAbove(activeFindings, failOn as Severity);
    if (breaches > 0) {
      console.error(
        `FAIL_ON=${failOn}: ${breaches} finding(s) at or above "${failOn}". Exiting non-zero.`,
      );
      process.exitCode = 1;
    }
  }
}

main();
