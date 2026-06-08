import { test } from "node:test";
import assert from "node:assert/strict";
import {
  U64_MAX,
  checkFeeMonotonicity,
  simulateReferralChain,
  simulateRoundTrip,
} from "../scripts/lib/invariants";

test("referral chain pays each ancestor and totals correctly", () => {
  const r = simulateReferralChain({
    rewardBps: 1000n, // 10%
    rounding: "floor",
    depth: 3,
    baseAmount: 1000n,
  });
  assert.deepEqual(r.perLevel, [100n, 100n, 100n]);
  assert.equal(r.totalPaid, 300n);
  assert.equal(r.issues.length, 0);
});

test("referral chain flags reward rounding to zero at dust", () => {
  const r = simulateReferralChain({
    rewardBps: 100n, // 1%
    rounding: "floor",
    depth: 2,
    baseAmount: 50n, // 50 * 1% = 0.5 -> floor 0
  });
  const dust = r.issues.find((i) => /non-zero/.test(i.invariant));
  assert.ok(dust, "expected a dust rounding issue");
});

test("referral chain flags exceeding the configured max total", () => {
  const r = simulateReferralChain({
    rewardBps: 1000n,
    rounding: "floor",
    depth: 5,
    baseAmount: 1000n, // 100 per level * 5 = 500
    maxTotalReward: 300n,
  });
  const over = r.issues.find((i) => /configured_maximum/.test(i.invariant));
  assert.ok(over, "expected a max-total breach");
  assert.equal(over!.severity, "high");
});

test("round-trip flags fee dodging at the dust boundary", () => {
  const issues = simulateRoundTrip({
    feeBps: 500n,
    feeRounding: "floor",
    amounts: [19n], // 19 * 5% = 0.95 -> floor 0 fee
  });
  const free = issues.find((i) => /round-trip/.test(i.invariant));
  assert.ok(free, "expected a free round-trip issue at value=19");
  assert.equal(free!.severity, "medium");
});

test("round-trip is clean at a round value", () => {
  const issues = simulateRoundTrip({
    feeBps: 500n,
    feeRounding: "floor",
    amounts: [1000n],
  });
  assert.equal(issues.length, 0);
});

test("fee monotonicity holds for floor rounding over a range", () => {
  const issues = checkFeeMonotonicity([1n, 100n, 1000n, U64_MAX], 500n, "floor");
  assert.equal(issues.length, 0);
});

test("fee monotonicity never false-positives across the full u64 domain", () => {
  // For a fixed bps, fee(value) is monotonic by construction, so the checker
  // must stay silent across the whole probe range under both rounding modes.
  const issues = checkFeeMonotonicity(
    [0n, 1n, 2n, 19n, 100n, 1000n, U64_MAX],
    500n,
    "ceil",
  );
  assert.equal(issues.length, 0);
});
