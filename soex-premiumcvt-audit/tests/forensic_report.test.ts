import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { loadIdl } from "../scripts/lib/idl";
import { analyzeIdl } from "../scripts/lib/analyze";
import { normalizeAbi } from "../scripts/lib/evm_abi";
import { analyzeAbi } from "../scripts/lib/evm_analyze";
import {
  assembleReport,
  entryFromEvm,
  entryFromSolana,
  toMarkdown,
  toSarif,
} from "../scripts/lib/forensic_report";

const solanaIdl = loadIdl(path.join(__dirname, "fixtures", "advanced-idl.json"));
const evmAbi = normalizeAbi(
  JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "evm-abi.json"), "utf8")),
);

function buildReport() {
  const solana = entryFromSolana(
    { program: "soex-premiumcvt", chain: "solana", vm: "svm", address: null },
    analyzeIdl(solanaIdl),
  );
  const evm = entryFromEvm(
    { program: "bitget", chain: "ethereum", vm: "evm", address: "0xabc", label: "Vault" },
    analyzeAbi(evmAbi),
  );
  return assembleReport([solana, evm]);
}

test("assembles a unified multi-chain report from both engines", () => {
  const report = buildReport();
  assert.equal(report.entries.length, 2);
  assert.ok(report.entries[0].findings.length > 0);
  assert.ok(report.entries[1].findings.length > 0);
  assert.equal(report.entries[0].findings[0].engine, "svm-static");
  assert.equal(report.entries[1].findings[0].engine, "evm-static");
});

test("renders Markdown covering both targets", () => {
  const md = toMarkdown(buildReport());
  assert.match(md, /soex-premiumcvt/);
  assert.match(md, /bitget · ethereum \(evm\)/);
});

test("renders valid combined SARIF with rules and results", () => {
  const sarif = toSarif(buildReport()) as {
    version: string;
    runs: { tool: { driver: { rules: unknown[] } }; results: unknown[] }[];
  };
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length > 0);
  assert.ok(sarif.runs[0].tool.driver.rules.length > 0);
});
