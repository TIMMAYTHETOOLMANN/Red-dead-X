import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { normalizeAbi } from "../scripts/lib/evm_abi";
import { analyzeAbi } from "../scripts/lib/evm_analyze";

const abiPath = path.join(__dirname, "fixtures", "evm-abi.json");
const abiJson = JSON.parse(fs.readFileSync(abiPath, "utf8"));

test("normalizeAbi parses JSON ABI entries", () => {
  const abi = normalizeAbi(abiJson);
  assert.ok(abi.functions.find((f) => f.name === "mint"));
  assert.equal(abi.hasFallback, true);
  assert.equal(abi.hasReceive, true);
  assert.ok(abi.events.find((e) => e.name === "Transfer"));
});

test("normalizeAbi parses human-readable signatures", () => {
  const abi = normalizeAbi([
    "function transfer(address to, uint256 amount) returns (bool)",
    "function owner() view returns (address)",
    "event Approval(address indexed owner, address indexed spender, uint256 value)",
  ]);
  const transfer = abi.functions.find((f) => f.name === "transfer");
  assert.ok(transfer);
  assert.equal(transfer!.inputs.length, 2);
  assert.equal(transfer!.inputs[0].type, "address");
  assert.equal(abi.functions.find((f) => f.name === "owner")!.readOnly, true);
  assert.ok(abi.events.find((e) => e.name === "Approval")!.inputs[0].indexed);
});

test("EVM analyzer flags upgradeToAndCall as critical upgradeability", () => {
  const result = analyzeAbi(normalizeAbi(abiJson));
  const f = result.findings.find((x) => x.lane === "EB-upgradeability");
  assert.ok(f, "expected an upgradeability finding");
  assert.equal(f!.severity, "critical");
});

test("EVM analyzer flags execute(address,bytes) as arbitrary call", () => {
  const result = analyzeAbi(normalizeAbi(abiJson));
  const f = result.findings.find(
    (x) => x.lane === "EC-arbitrary-call" && x.function === "execute",
  );
  assert.ok(f);
  assert.equal(f!.severity, "critical");
});

test("EVM analyzer flags permit without nonce/deadline as signature replay", () => {
  const result = analyzeAbi(normalizeAbi(abiJson));
  const f = result.findings.find((x) => x.lane === "EE-signature-replay");
  assert.ok(f);
  assert.equal(f!.severity, "high");
});

test("EVM analyzer flags kill as self-destruct", () => {
  const result = analyzeAbi(normalizeAbi(abiJson));
  assert.ok(result.findings.find((x) => x.lane === "EH-self-destruct"));
});

test("findings are payout-weighted and ranked by expected payout", () => {
  const result = analyzeAbi(normalizeAbi(abiJson));
  assert.ok(result.totalPayoutWeight > 0);
  for (let i = 1; i < result.findings.length; i++) {
    assert.ok(
      result.findings[i - 1].payoutWeight >= result.findings[i].payoutWeight,
      "findings must be sorted by descending payout weight",
    );
  }
});

test("read-only ABI produces no privileged findings", () => {
  const abi = normalizeAbi([
    "function name() view returns (string)",
    "function balanceOf(address a) view returns (uint256)",
  ]);
  const result = analyzeAbi(abi);
  assert.equal(result.findings.length, 0);
});
