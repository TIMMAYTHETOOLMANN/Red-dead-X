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
  attackPathGraph,
  entryFromEvm,
  entryFromSolana,
  fromBytecodeFinding,
  toMarkdown,
  toSarif,
} from "../scripts/lib/forensic_report";
import { analyzeBytecode } from "../scripts/lib/bytecode_fingerprint";

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

test("folds bytecode compiler findings into the unified stream", () => {
  const bc = analyzeBytecode("0x6080604052a264736f6c6343000c0c0033"); // solc 0.12.12 → no sig
  const unified = bc.findings.map(fromBytecodeFinding);
  assert.ok(unified.length >= 1);
  assert.equal(unified[0].engine, "bytecode-static");
  assert.match(unified[0].locator, /solc/);
});

test("attackPathGraph builds nodes for findings and lineage/enabler edges", () => {
  const report = buildReport();
  // Attach a synthetic exploit-chain + genealogy to the first EVM finding.
  const evmFindings = report.entries[1].findings;
  const a = evmFindings[0];
  const b = evmFindings[1] ?? evmFindings[0];
  a.components = [b.id];
  a.genealogy = ["0xBreached2021", "0xRelayWallet"];

  const graph = attackPathGraph(report);
  assert.ok(graph.nodes.some((n) => n.data.id === a.id));
  assert.ok(
    graph.edges.some((e) => e.data.relation === "enables" && e.data.target === b.id),
  );
  assert.ok(
    graph.edges.some(
      (e) => e.data.relation === "lineage" && e.data.source === "0xBreached2021",
    ),
  );
});

test("Markdown includes breach-genealogy and attack-path graph sections", () => {
  const report = buildReport();
  report.entries[1].findings[0].genealogy = ["0xBreached2021", "0xRelayWallet"];
  const md = toMarkdown(report);
  assert.match(md, /## Breach genealogy paths/);
  assert.match(md, /## Attack-path graph/);
  assert.match(md, /0xBreached2021/);
});
