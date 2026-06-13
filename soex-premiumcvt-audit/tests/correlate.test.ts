import { test } from "node:test";
import assert from "node:assert/strict";
import { ForensicEntry, UnifiedFinding } from "../scripts/lib/forensic_report";
import {
  annotateExploitChains,
  collapseCrossChain,
  correlateExploitChains,
} from "../scripts/lib/correlate";

function uf(partial: Partial<UnifiedFinding> & { lane: string; locator: string }): UnifiedFinding {
  return {
    id: `${partial.lane}:${partial.locator}:${partial.subLocator ?? ""}`,
    engine: partial.engine ?? "evm-static",
    lane: partial.lane,
    severity: partial.severity ?? "medium",
    confidence: partial.confidence ?? "likely",
    risk: partial.risk ?? 6,
    payoutWeight: partial.payoutWeight ?? 0,
    vulnTypeId: partial.vulnTypeId ?? null,
    locator: partial.locator,
    subLocator: partial.subLocator ?? null,
    title: partial.title ?? "t",
    detail: partial.detail ?? "d",
    recommendation: partial.recommendation ?? "r",
  };
}

function entry(chain: string, address: string | null, findings: UnifiedFinding[]): ForensicEntry {
  return { target: { program: "p", chain, vm: "evm", address }, findings };
}

test("collapseCrossChain merges the same seam across chains and tags the chains", () => {
  const f = uf({ lane: "EA-access-control", locator: "withdraw", title: "no role" });
  const result = collapseCrossChain([
    entry("ethereum", "0xABC", [f]),
    entry("bsc", "0xabc", [{ ...f }]),
    entry("polygon", "0xAbC", [{ ...f }]),
  ]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.merged, 2);
  assert.equal(result.multiChainSeams, 1);
  assert.deepEqual(result.findings[0].chains, ["bsc", "ethereum", "polygon"]);
});

test("collapseCrossChain keeps distinct seams separate and leaves chains unset", () => {
  const result = collapseCrossChain([
    entry("ethereum", "0xABC", [uf({ lane: "EA-access-control", locator: "withdraw" })]),
    entry("ethereum", "0xABC", [uf({ lane: "EF-reentrancy", locator: "claim" })]),
  ]);
  assert.equal(result.findings.length, 2);
  assert.equal(result.multiChainSeams, 0);
  assert.ok(result.findings.every((f) => f.chains === undefined));
});

test("collapseCrossChain does not merge same finding on different addresses", () => {
  const f = uf({ lane: "EA-access-control", locator: "withdraw" });
  const result = collapseCrossChain([
    entry("ethereum", "0xAAA", [f]),
    entry("bsc", "0xBBB", [{ ...f }]),
  ]);
  assert.equal(result.findings.length, 2);
  assert.equal(result.multiChainSeams, 0);
});

test("correlateExploitChains links an access-control gap to an amplifier", () => {
  const enabler = uf({
    lane: "EA-access-control",
    locator: "setOwner",
    severity: "high",
    risk: 12,
  });
  const amplifier = uf({ lane: "EC-arbitrary-call", locator: "execute", severity: "high" });
  const composites = correlateExploitChains([enabler, amplifier]);
  assert.equal(composites.length, 1);
  assert.equal(composites[0].engine, "correlation");
  assert.equal(composites[0].lane, "exploit-chain");
  assert.equal(composites[0].severity, "critical"); // escalated from high
  assert.deepEqual(composites[0].components, [enabler.id, amplifier.id]);
});

test("correlateExploitChains requires both an enabler and an amplifier", () => {
  assert.equal(correlateExploitChains([uf({ lane: "EC-arbitrary-call", locator: "execute" })]).length, 0);
  assert.equal(
    correlateExploitChains([uf({ lane: "EA-access-control", locator: "setOwner", severity: "high", risk: 12 })])
      .length,
    0,
  );
});

test("correlateExploitChains ignores same-locator gap+primitive (not a cross-function chain)", () => {
  const both = [
    uf({ lane: "EA-access-control", locator: "mint", severity: "high", risk: 12 }),
    uf({ lane: "EG-economic-math", locator: "mint", severity: "high" }),
  ];
  assert.equal(correlateExploitChains(both).length, 0);
});

test("a weak (low-severity) access-control finding is not treated as an enabler", () => {
  const composites = correlateExploitChains([
    uf({ lane: "EA-access-control", locator: "setOwner", severity: "low", risk: 2 }),
    uf({ lane: "EC-arbitrary-call", locator: "execute", severity: "high" }),
  ]);
  assert.equal(composites.length, 0);
});

test("annotateExploitChains appends composites to the originating entry only", () => {
  const withChain = entry("ethereum", "0xABC", [
    uf({ lane: "admin-authority", locator: "Vault", severity: "critical", risk: 15 }),
    uf({ lane: "EC-arbitrary-call", locator: "execute", severity: "high" }),
  ]);
  const without = entry("bsc", "0xDEF", [uf({ lane: "EF-reentrancy", locator: "claim" })]);
  const out = annotateExploitChains([withChain, without]);
  assert.ok(out[0].findings.some((f) => f.lane === "exploit-chain"));
  assert.ok(!out[1].findings.some((f) => f.lane === "exploit-chain"));
});
