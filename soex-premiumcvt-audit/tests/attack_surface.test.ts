import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { loadRegistry, programByKey } from "../scripts/lib/bugrap";
import {
  mapProgramSurface,
  mapEcosystemSurface,
  prioritizeCells,
  summarizeCoverage,
} from "../scripts/lib/attack_surface";

const registryPath = path.join(__dirname, "..", "targets", "bugrap-programs.json");
const registry = loadRegistry(registryPath);

test("maps every chain x bounty-class cell for a program", () => {
  const bitget = programByKey(registry, "bitget")!;
  const cells = mapProgramSurface(bitget);
  assert.equal(cells.length, bitget.chains.length * bitget.vulnClasses.length);
});

test("EVM smart-contract cells are automated; auth cells are manual-only", () => {
  const bitget = programByKey(registry, "bitget")!;
  const cells = mapProgramSurface(bitget);
  const sc = cells.find((c) => c.vm === "evm" && c.vulnClass === "smart-contract")!;
  assert.equal(sc.automated, true);
  const auth = cells.find((c) => c.vulnClass === "auth")!;
  assert.equal(auth.automated, false);
});

test("Solana smart-contract cell routes to svm-static", () => {
  const soex = programByKey(registry, "soex-premiumcvt")!;
  const cells = mapProgramSurface(soex);
  const sc = cells.find((c) => c.vm === "svm" && c.vulnClass === "smart-contract")!;
  assert.ok(sc.engines.includes("svm-static"));
  assert.equal(sc.automated, true);
});

test("ecosystem coverage summary spans many chains and classes", () => {
  const cells = mapEcosystemSurface(registry.programs);
  const summary = summarizeCoverage(cells);
  assert.ok(summary.totalCells > 20);
  assert.equal(summary.automatedCells + summary.manualOnlyCells, summary.totalCells);
  assert.ok(summary.chains.length >= 5);
});

test("prioritizeCells orders by expected payout ceiling first", () => {
  const cells = prioritizeCells(mapEcosystemSurface(registry.programs));
  for (let i = 1; i < cells.length; i++) {
    assert.ok(cells[i - 1].payoutCeilingUsd >= cells[i].payoutCeilingUsd);
  }
});
