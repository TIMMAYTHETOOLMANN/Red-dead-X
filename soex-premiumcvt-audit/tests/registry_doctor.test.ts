import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { loadRegistry, normalizeRegistry } from "../scripts/lib/bugrap";
import {
  assessRegistry,
  programReadiness,
} from "../scripts/lib/registry_doctor";

const registryPath = path.join(__dirname, "..", "targets", "bugrap-programs.json");

test("a program with no pinned contracts is a shell", () => {
  const reg = normalizeRegistry({
    programs: [
      {
        key: "shellprog",
        chains: ["ethereum"],
        vulnClasses: ["smart-contract"],
        contracts: [{ chain: "ethereum", address: "", label: "to pin" }],
      },
    ],
  });
  const r = programReadiness(reg.programs[0]);
  assert.equal(r.state, "shell");
  assert.equal(r.contractsPinned, 0);
  assert.equal(r.contractsUnpinned, 1);
});

test("a program with an empty contract list is a shell", () => {
  const reg = normalizeRegistry({
    programs: [{ key: "empty", chains: ["ethereum"], vulnClasses: ["smart-contract"] }],
  });
  assert.equal(programReadiness(reg.programs[0]).state, "shell");
});

test("a program with every contract pinned is armed", () => {
  const reg = normalizeRegistry({
    programs: [
      {
        key: "armedprog",
        chains: ["ethereum"],
        vulnClasses: ["smart-contract"],
        contracts: [
          { chain: "ethereum", address: "0xabc", label: "Vault" },
          { chain: "ethereum", address: "0xdef", label: "Router" },
        ],
      },
    ],
  });
  const r = programReadiness(reg.programs[0]);
  assert.equal(r.state, "armed");
  assert.equal(r.contractsPinned, 2);
  assert.equal(r.contractsUnpinned, 0);
});

test("a program with some pinned contracts is partial", () => {
  const reg = normalizeRegistry({
    programs: [
      {
        key: "partprog",
        chains: ["ethereum"],
        vulnClasses: ["smart-contract"],
        contracts: [
          { chain: "ethereum", address: "0xabc", label: "Vault" },
          { chain: "ethereum", address: "", label: "Router" },
        ],
      },
    ],
  });
  assert.equal(programReadiness(reg.programs[0]).state, "partial");
});

test("registry-level tallies sum to the program total", () => {
  const reg = normalizeRegistry({
    programs: [
      {
        key: "a",
        chains: ["ethereum"],
        vulnClasses: ["smart-contract"],
        contracts: [{ chain: "ethereum", address: "0x1", label: "x" }],
      },
      {
        key: "b",
        chains: ["ethereum"],
        vulnClasses: ["smart-contract"],
        contracts: [
          { chain: "ethereum", address: "0x1", label: "x" },
          { chain: "ethereum", address: "", label: "y" },
        ],
      },
      { key: "c", chains: ["ethereum"], vulnClasses: ["smart-contract"] },
    ],
  });
  const report = assessRegistry(reg);
  assert.equal(report.total, 3);
  assert.equal(report.armed, 1);
  assert.equal(report.partial, 1);
  assert.equal(report.shell, 1);
  assert.equal(report.armed + report.partial + report.shell, report.total);
});

test("the shipped registry is honestly reported as all-shell (placeholders)", () => {
  // The registry ships with placeholder addresses, so coverage numbers must not
  // pretend it is armed. This guards the trust property the doctor exists for.
  const report = assessRegistry(loadRegistry(registryPath));
  assert.equal(report.armed, 0);
  assert.equal(report.shell, report.total);
});
