import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeAdmin,
  analyzeData,
  analyzeEconomic,
  analyzeEncoding,
} from "../scripts/lib/aux_analyzers";

test("admin: single-sig upgrade authority is critical and EOA-classified", () => {
  const findings = analyzeAdmin({
    contract: "Vault",
    state: { upgradeAuthority: "0xEOA0000000000000000000000000000000000001" },
  });
  const auth = findings.find((f) => f.lane === "admin-authority")!;
  assert.equal(auth.severity, "critical");
  assert.match(auth.title, /single-sig\/EOA/);
});

test("admin: known multisig override downgrades the EOA guess", () => {
  const addr = "0x1234567890123456789012345678901234567890";
  const findings = analyzeAdmin({
    contract: "Vault",
    state: { owner: addr },
    classification: { knownMultisigs: [addr] },
  });
  const auth = findings.find((f) => f.lane === "admin-authority")!;
  // owner under multisig is not the critical single-sig upgrade case
  assert.notEqual(auth.title, "Privileged authority is single-sig/EOA");
  assert.equal(auth.confidence, "likely");
});

test("admin: unguarded privileged action is high severity", () => {
  const findings = analyzeAdmin({
    contract: "Vault",
    abi: [
      { name: "emergencyWithdraw", modifiers: [] },
      { name: "mint", modifiers: ["onlyOwner"] },
    ],
  });
  const unguarded = findings.find(
    (f) => f.lane === "admin-privilege" && f.locator === "Vault" && f.subLocator === "emergencyWithdraw",
  )!;
  assert.equal(unguarded.severity, "high");
  const guarded = findings.find((f) => f.subLocator === "mint")!;
  assert.equal(guarded.severity, "info");
});

test("encoding: a field decoding to a privileged term is flagged", () => {
  const findings = analyzeEncoding({ fields: [{ name: "role", value: "YWRtaW4=" }] }); // base64 'admin'
  assert.equal(findings.length, 1);
  assert.equal(findings[0].lane, "encoding-obfuscation");
  assert.match(findings[0].detail, /admin/);
});

test("encoding: a benign field yields no findings", () => {
  const findings = analyzeEncoding({ fields: [{ name: "memo", value: "0x68656c6c6f" }] }); // 'hello'
  assert.equal(findings.length, 0);
});

test("data: authority drift between snapshots is high severity", () => {
  const findings = analyzeData({
    pre: { upgradeAuthority: "0xaaa" },
    post: { upgradeAuthority: "0xbbb" },
  });
  const drift = findings.find((f) => f.lane === "data-authority-drift")!;
  assert.ok(drift);
  assert.equal(drift.severity, "high");
});

test("data: duplicate identifiers are flagged", () => {
  const findings = analyzeData({ uuids: ["x", "x", "y"] });
  const collision = findings.find((f) => f.lane === "data-id-collision")!;
  assert.equal(collision.locator, "x");
});

test("economic: dust-fee swap produces a dust-drain finding", () => {
  const findings = analyzeEconomic({ feeRateBps: 100, swapAmounts: ["1"] });
  const dust = findings.find((f) => f.lane === "economic-dust")!;
  assert.ok(dust);
  assert.equal(dust.severity, "medium");
});

test("economic: vulnerable mint probe surfaces an overflow finding", () => {
  const findings = analyzeEconomic({ probeVulnerableMint: true, swapAmounts: [] });
  const overflow = findings.find((f) => f.lane === "economic-overflow")!;
  assert.ok(overflow);
  assert.equal(overflow.severity, "high");
});

test("aux findings carry stable ids and computed risk", () => {
  const a = analyzeEncoding({ fields: [{ name: "role", value: "YWRtaW4=" }] })[0];
  const b = analyzeEncoding({ fields: [{ name: "role", value: "YWRtaW4=" }] })[0];
  assert.equal(a.id, b.id);
  assert.ok(a.risk > 0);
});
