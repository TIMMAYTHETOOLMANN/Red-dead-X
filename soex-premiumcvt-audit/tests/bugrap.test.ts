import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import {
  checkScope,
  assertInScope,
  loadRegistry,
  normalizeRegistry,
  programByKey,
  programChains,
} from "../scripts/lib/bugrap";

const registryPath = path.join(__dirname, "..", "targets", "bugrap-programs.json");

test("loads and validates the on-disk registry", () => {
  const reg = loadRegistry(registryPath);
  assert.ok(reg.programs.length >= 10, "expected the full BugRap program set");
  assert.ok(programByKey(reg, "soex-premiumcvt"));
  assert.ok(programByKey(reg, "bitget"));
});

test("program chains resolve to catalog entries", () => {
  const reg = loadRegistry(registryPath);
  const merlin = programByKey(reg, "merlinchain")!;
  const chains = programChains(merlin);
  assert.ok(chains.some((c) => c.vm === "evm"));
});

test("rejects an unknown chain in a program", () => {
  assert.throws(
    () =>
      normalizeRegistry({
        programs: [{ key: "x", chains: ["narnia"], vulnClasses: ["smart-contract"] }],
      }),
    /Unknown chain/,
  );
});

test("rejects an unknown vuln class", () => {
  assert.throws(
    () =>
      normalizeRegistry({
        programs: [{ key: "x", chains: ["ethereum"], vulnClasses: ["telepathy"] }],
      }),
    /unknown vuln class/,
  );
});

test("rejects duplicate program keys", () => {
  assert.throws(
    () =>
      normalizeRegistry({
        programs: [
          { key: "dup", chains: [], vulnClasses: [] },
          { key: "dup", chains: [], vulnClasses: [] },
        ],
      }),
    /Duplicate program key/,
  );
});

test("scope gate accepts in-scope and refuses out-of-scope targets", () => {
  const reg = loadRegistry(registryPath);
  const soex = programByKey(reg, "soex-premiumcvt")!;
  const ok = checkScope(soex, { chain: "solana", vulnClass: "smart-contract" });
  assert.equal(ok.inScope, true);

  const bad = checkScope(soex, { chain: "ethereum", vulnClass: "input-validation" });
  assert.equal(bad.inScope, false);
  assert.ok(bad.reasons.length >= 1);

  assert.throws(() => assertInScope(soex, { chain: "ethereum" }), /Out-of-scope/);
});
