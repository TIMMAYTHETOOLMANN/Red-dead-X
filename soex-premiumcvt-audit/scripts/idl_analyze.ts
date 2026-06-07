import "dotenv/config";
import fs from "fs";
import { loadIdl } from "./lib/idl";
import { analyzeIdl, Finding, MatrixRow } from "./lib/analyze";

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

function findingsToMarkdown(findings: Finding[]): string {
  if (findings.length === 0) return "_No candidate findings._\n";
  const lines = [
    "| Severity | Lane | Instruction | Account | Title |",
    "|----------|------|-------------|---------|-------|",
  ];
  for (const f of findings) {
    lines.push(
      `| ${f.severity} | ${f.lane} | \`${f.instruction}\` | ${
        f.account ? `\`${f.account}\`` : "—"
      } | ${f.title} |`,
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
        ...result,
      },
      null,
      2,
    ),
  );

  const mdOut = `${evidenceDir}/idl-analysis-${stamp}.md`;
  const md =
    `# IDL static analysis — ${result.program}\n\n` +
    `- IDL: \`${idlPath}\`\n` +
    `- Program address: ${result.address ?? "(none in IDL)"}\n` +
    `- Instructions: ${result.instructionCount}\n` +
    `- Severity counts: ${JSON.stringify(result.severityCounts)}\n\n` +
    `## Candidate findings (confirm by hand — see docs/03-triage-rubric.md)\n\n` +
    findingsToMarkdown(result.findings) +
    `\n## Instruction / account matrix\n\n` +
    matrixToMarkdown(result.matrix);
  fs.writeFileSync(mdOut, md);

  console.log(`Wrote ${jsonOut}`);
  console.log(`Wrote ${mdOut}`);
  console.log(
    `\nProgram: ${result.program}  Instructions: ${result.instructionCount}  ` +
      `Findings: ${result.findings.length}`,
  );
  console.log("Severity:", result.severityCounts);
  if (result.findings.length > 0) {
    console.table(
      result.findings.map((f) => ({
        severity: f.severity,
        lane: f.lane,
        instruction: f.instruction,
        account: f.account ?? "",
        title: f.title,
      })),
    );
  }
}

main();
