import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeBytecode,
  fingerprintBytecode,
} from "../scripts/lib/bytecode_fingerprint";

// Minimal synthetic runtime bytecode carrying a Solidity CBOR metadata trailer.
// The solc marker is `64 736f6c63 43` (text(4)"solc" + bytes(3)) + version bytes.
// 0x00 06 0c => 0.6.12 ; 0x00 08 11 => 0.8.17.
function solcBytecode(major: number, minor: number, patch: number): string {
  const v = [major, minor, patch]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
  return `0x6080604052a264736f6c6343${v}0033`;
}

function vyperBytecode(major: number, minor: number, patch: number): string {
  const v = [major, minor, patch]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
  return `0x6080604052a1657679706572${"43"}${v}0033`;
}

test("fingerprintBytecode decodes a solc version from the metadata trailer", () => {
  const fp = fingerprintBytecode(solcBytecode(0, 6, 12));
  assert.equal(fp.kind, "solc");
  assert.equal(fp.version, "0.6.12");
  assert.equal(fp.hasMetadata, true);
});

test("fingerprintBytecode decodes a vyper version", () => {
  const fp = fingerprintBytecode(vyperBytecode(0, 3, 7));
  assert.equal(fp.kind, "vyper");
  assert.equal(fp.version, "0.3.7");
});

test("fingerprintBytecode returns unknown for empty / non-hex bytecode", () => {
  assert.deepEqual(fingerprintBytecode("0x"), {
    kind: "unknown",
    version: null,
    hasMetadata: false,
  });
  assert.equal(fingerprintBytecode("not-hex").kind, "unknown");
});

test("analyzeBytecode flags pre-0.8.0 unchecked arithmetic", () => {
  const result = analyzeBytecode(solcBytecode(0, 6, 12));
  const bug = result.findings.find((f) => f.lane === "BC-known-compiler-bug");
  assert.ok(bug, "expected a known-compiler-bug finding for solc 0.6.12");
  assert.equal(bug!.severity, "high");
  assert.equal(bug!.vulnTypeId, "smart-contract/overflow");
  // Always emits an informational fingerprint finding too.
  assert.ok(result.findings.some((f) => f.lane === "BC-compiler-fingerprint"));
});

test("analyzeBytecode does NOT flag the pre-0.8.0 overflow bug on 0.8.17", () => {
  const result = analyzeBytecode(solcBytecode(0, 8, 17));
  assert.ok(
    !result.findings.some(
      (f) => f.lane === "BC-known-compiler-bug" && f.vulnTypeId === "smart-contract/overflow",
    ),
    "0.8.x has built-in overflow checks; should not flag the pre-0.8.0 signature",
  );
});

test("analyzeBytecode flags the 0.8.13–0.8.14 optimizer assembly bug", () => {
  const result = analyzeBytecode(solcBytecode(0, 8, 13));
  const bug = result.findings.find(
    (f) => f.lane === "BC-known-compiler-bug" && /optimizer/i.test(f.title),
  );
  assert.ok(bug, "expected the inline-assembly optimizer signature for 0.8.13");
});

test("analyzeBytecode on unknown bytecode emits only an informational fingerprint", () => {
  const result = analyzeBytecode("0x6080604052");
  assert.equal(result.fingerprint.kind, "unknown");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].lane, "BC-compiler-fingerprint");
  assert.equal(result.findings[0].severity, "info");
});

test("findings carry stable ids, risk, and payout weight", () => {
  const a = analyzeBytecode(solcBytecode(0, 6, 12));
  const b = analyzeBytecode(solcBytecode(0, 6, 12));
  assert.deepEqual(
    a.findings.map((f) => f.id),
    b.findings.map((f) => f.id),
  );
  for (const f of a.findings) {
    assert.equal(typeof f.risk, "number");
    assert.equal(typeof f.payoutWeight, "number");
  }
});
