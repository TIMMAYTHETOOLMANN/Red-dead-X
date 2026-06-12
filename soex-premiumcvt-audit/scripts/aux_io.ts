import fs from "fs";
import path from "path";
import {
  ForensicEntry,
  ForensicReport,
  assembleReport,
  toMarkdown,
  toSarif,
} from "./lib/forensic_report";

/**
 * Shared I/O glue for the auxiliary analyzer CLIs (admin/encoding/data/economic).
 *
 * Keeps the analyzers themselves pure (in `lib/aux_analyzers.ts`) while this
 * thin layer handles reading a real input file — with a clearly-announced bundled
 * sample fallback so the documented `npm run *-analyze` commands still work out of
 * the box — and writing the unified JSON + SARIF + Markdown brief to evidence.
 */

/** Read a JSON input from `envVar` (or the sample), announcing which was used. */
export function readJsonInput<T>(envVar: string, sampleRelPath: string): T {
  const provided = (process.env[envVar] ?? "").trim();
  if (provided) {
    if (!fs.existsSync(provided)) {
      throw new Error(`${envVar}="${provided}" does not exist.`);
    }
    console.log(`Input: ${provided} (from ${envVar})`);
    return JSON.parse(fs.readFileSync(provided, "utf8")) as T;
  }
  const samplePath = path.resolve(process.cwd(), sampleRelPath);
  console.log(
    `Input: ${sampleRelPath} (bundled sample — set ${envVar} to analyze a real target)`,
  );
  return JSON.parse(fs.readFileSync(samplePath, "utf8")) as T;
}

/** Assemble a single-target report and write JSON + SARIF + Markdown to evidence. */
export function writeUnifiedReport(slug: string, entry: ForensicEntry): ForensicReport {
  const report = assembleReport([entry]);
  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = `${evidenceDir}/${slug}-${stamp}`;

  fs.writeFileSync(`${base}.json`, JSON.stringify(report, null, 2));
  fs.writeFileSync(`${base}.sarif`, JSON.stringify(toSarif(report), null, 2));
  fs.writeFileSync(`${base}.md`, toMarkdown(report));

  console.log(`Wrote ${base}.json / .sarif / .md`);
  console.log(`Candidate findings: ${entry.findings.length}`);
  for (const f of entry.findings) {
    console.log(`- [${f.severity}/${f.confidence}] ${f.lane}: ${f.title} (${f.locator})`);
  }
  return report;
}
