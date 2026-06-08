import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { loadIdl } from "../scripts/lib/idl";
import {
  analyzeIdl,
  applyBaseline,
  fingerprint,
  riskScore,
} from "../scripts/lib/analyze";
import { toSarif } from "../scripts/lib/report";

const advanced = path.join(__dirname, "fixtures", "advanced-idl.json");
const sample = path.join(__dirname, "fixtures", "sample-idl.json");

test("lane G flags an unpinned CPI program account", () => {
  const result = analyzeIdl(loadIdl(advanced));
  const f = result.findings.find(
    (x) => x.lane === "G-cpi-program" && x.account === "token_program",
  );
  assert.ok(f, "expected a CPI-program finding for unpinned token_program");
  assert.equal(f!.severity, "high");
});

test("lane G does NOT flag a pinned program account", () => {
  // In sample-idl the token/system programs carry a fixed address.
  const result = analyzeIdl(loadIdl(sample));
  const noise = result.findings.find(
    (x) => x.lane === "G-cpi-program" && x.account === "token_program",
  );
  assert.equal(noise, undefined, "pinned programs must not be CPI-flagged");
});

test("lane H flags a non-PDA init target (re-init risk)", () => {
  const idl = loadIdl(sample);
  const result = analyzeIdl(idl);
  const f = result.findings.find(
    (x) => x.lane === "H-init-safety" && x.instruction === "init_config",
  );
  assert.ok(f, "expected an init-safety finding for init_config admin");
});

test("lane H does NOT flag a PDA-bound init target", () => {
  const result = analyzeIdl(loadIdl(advanced));
  // init_config.config is a PDA in the advanced fixture -> safe.
  const f = result.findings.find(
    (x) =>
      x.lane === "H-init-safety" &&
      x.instruction === "init_config" &&
      x.account === "config",
  );
  assert.equal(f, undefined, "PDA-bound init target must not be flagged");
});

test("lane I flags an unbounded vec argument", () => {
  const result = analyzeIdl(loadIdl(advanced));
  const f = result.findings.find(
    (x) => x.lane === "I-dos-compute" && x.instruction === "submit_batch",
  );
  assert.ok(f, "expected a DoS finding for the vec<pubkey> arg");
});

test("cross-instruction correlation flags inconsistent constraints", () => {
  const result = analyzeIdl(loadIdl(advanced));
  // `config` is a PDA in init_config but an unbound writable in update_config.
  const f = result.findings.find(
    (x) =>
      x.lane === "X-correlation" &&
      x.account === "config" &&
      x.instruction === "update_config",
  );
  assert.ok(f, "expected a correlation finding for config");
  assert.equal(f!.severity, "high");
});

test("findings carry stable fingerprints and composite risk", () => {
  const result = analyzeIdl(loadIdl(sample));
  const f = result.findings[0];
  assert.equal(typeof f.id, "string");
  assert.equal(f.id.length, 16);
  assert.equal(f.id, fingerprint(f.lane, f.instruction, f.account));
  assert.equal(f.risk, riskScore(f.severity, f.confidence));
  // re-running yields identical ids (determinism).
  const again = analyzeIdl(loadIdl(sample));
  assert.deepEqual(
    result.findings.map((x) => x.id).sort(),
    again.findings.map((x) => x.id).sort(),
  );
});

test("findings are sorted by descending composite risk", () => {
  const result = analyzeIdl(loadIdl(sample));
  for (let i = 1; i < result.findings.length; i++) {
    assert.ok(result.findings[i - 1].risk >= result.findings[i].risk);
  }
  assert.equal(result.maxRisk, result.findings[0].risk);
});

test("baseline suppression drops findings by id", () => {
  const result = analyzeIdl(loadIdl(sample));
  const drop = result.findings[0].id;
  const { kept, suppressed } = applyBaseline(result.findings, [drop]);
  assert.equal(suppressed, 1);
  assert.equal(kept.find((f) => f.id === drop), undefined);
});

test("all new lanes are counted in laneCounts", () => {
  const result = analyzeIdl(loadIdl(advanced));
  assert.ok("G-cpi-program" in result.laneCounts);
  assert.ok("H-init-safety" in result.laneCounts);
  assert.ok("I-dos-compute" in result.laneCounts);
  assert.ok("X-correlation" in result.laneCounts);
});

test("SARIF export is well-formed", () => {
  const result = analyzeIdl(loadIdl(advanced));
  const sarif = toSarif(result, "targets/premiumcvt.json") as any;
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].results.length, result.findings.length);
  // every result references a defined rule index.
  const ruleCount = sarif.runs[0].tool.driver.rules.length;
  for (const r of sarif.runs[0].results) {
    assert.ok(r.ruleIndex >= 0 && r.ruleIndex < ruleCount);
    assert.equal(typeof r.partialFingerprints.idlAnalyzer, "string");
  }
});
