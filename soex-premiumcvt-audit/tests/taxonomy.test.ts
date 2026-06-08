import { test } from "node:test";
import assert from "node:assert/strict";
import {
  allVulnClasses,
  payoutBand,
  payoutMidpoint,
  vulnTypeById,
  vulnTypesByClass,
  vulnTypesForEngine,
} from "../scripts/lib/taxonomy";

test("taxonomy covers all seven bounty classes", () => {
  const classes = allVulnClasses();
  assert.equal(classes.length, 7);
  for (const c of classes) {
    assert.ok(vulnTypesByClass(c).length >= 1, `class ${c} must have at least one vuln type`);
  }
});

test("vulnTypeById resolves a known type", () => {
  const t = vulnTypeById("smart-contract/reentrancy");
  assert.ok(t);
  assert.equal(t!.typicalSeverity, "critical");
});

test("vulnTypesForEngine returns engine-covered types", () => {
  const evm = vulnTypesForEngine("evm-static");
  assert.ok(evm.some((t) => t.id === "smart-contract/access-control"));
});

test("payout bands and midpoints follow severity", () => {
  assert.equal(payoutBand("critical").maxUsd, 20000);
  assert.ok(payoutMidpoint("critical") > payoutMidpoint("high"));
  assert.ok(payoutMidpoint("high") > payoutMidpoint("medium"));
  assert.equal(payoutMidpoint("info"), 0);
});

test("program override payout bands are respected", () => {
  const override = [{ severity: "critical" as const, minUsd: 50000, maxUsd: 100000 }];
  assert.equal(payoutMidpoint("critical", override), 75000);
});
