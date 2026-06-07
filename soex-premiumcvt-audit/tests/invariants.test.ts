import { test } from "node:test";
import assert from "node:assert/strict";
import {
  U64_MAX,
  addOverflowsU64,
  burnRefund,
  computeFee,
  mulOverflowsU64,
  simulateInvariants,
} from "../scripts/lib/invariants";

test("computeFee floors and ceils correctly", () => {
  // 19 * 500 / 10000 = 0.95 -> floor 0, ceil 1
  assert.equal(computeFee(19n, 500n, "floor"), 0n);
  assert.equal(computeFee(19n, 500n, "ceil"), 1n);
  // 100 * 500 / 10000 = 5
  assert.equal(computeFee(100n, 500n, "floor"), 5n);
});

test("burnRefund conserves value", () => {
  assert.equal(burnRefund(100n, 500n, "floor"), 95n);
  assert.equal(burnRefund(0n, 500n, "floor"), 0n);
});

test("u64 overflow helpers", () => {
  assert.equal(addOverflowsU64(U64_MAX, 1n), true);
  assert.equal(addOverflowsU64(U64_MAX - 1n, 1n), false);
  assert.equal(mulOverflowsU64(U64_MAX, 2n), true);
  assert.equal(mulOverflowsU64(1n, 1n), false);
});

test("simulator surfaces fee-rounds-to-zero at the dust boundary", () => {
  const issues = simulateInvariants({
    feeBps: 500n,
    feeRounding: "floor",
    amounts: [19n],
  });
  const dust = issues.find((i) => /rounds to 0/.test(i.detail));
  assert.ok(dust, "expected a fee-rounds-to-zero issue for value=19 at 5%");
  assert.equal(dust!.severity, "medium");
});

test("simulator surfaces u64 overflow at the max boundary", () => {
  const issues = simulateInvariants({
    feeBps: 500n,
    feeRounding: "floor",
    amounts: [U64_MAX],
  });
  const overflow = issues.find((i) => /overflow/.test(i.invariant));
  assert.ok(overflow, "expected an overflow issue for value=u64::MAX");
});

test("simulator surfaces ceil fee exceeding value", () => {
  // value=1, bps=500 ceil -> fee = ceil(500/10000)=1; not > value.
  // value=1, bps=20000 (200%) ceil -> fee=2 > value -> fee>value issue.
  const issues = simulateInvariants({
    feeBps: 20000n,
    feeRounding: "ceil",
    amounts: [1n],
  });
  const tooBig = issues.find((i) => /fee <= value/.test(i.invariant));
  assert.ok(tooBig, "expected fee>value issue when fee basis points exceed 100%");
});

test("clean parameters at a round value produce no high-severity issues", () => {
  const issues = simulateInvariants({
    feeBps: 500n,
    feeRounding: "floor",
    amounts: [1000n],
  });
  const high = issues.find((i) => i.severity === "high");
  assert.equal(high, undefined);
});

test("supply cap breach is flagged", () => {
  const issues = simulateInvariants({
    feeBps: 0n,
    feeRounding: "floor",
    supplyCap: 100n,
    amounts: [1000n],
  });
  const cap = issues.find((i) => /supply_cap/.test(i.invariant));
  assert.ok(cap, "expected a supply cap breach issue");
});
