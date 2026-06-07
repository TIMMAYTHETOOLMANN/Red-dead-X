import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { loadIdl, normalizeIdl } from "../scripts/lib/idl";
import { analyzeIdl } from "../scripts/lib/analyze";

const fixture = path.join(__dirname, "fixtures", "sample-idl.json");

test("normalizes the new-style Anchor IDL", () => {
  const idl = loadIdl(fixture);
  assert.equal(idl.name, "premiumcvt");
  assert.equal(idl.address, "PremiumCvt1111111111111111111111111111111111");
  assert.equal(idl.instructions.length, 4);
});

test("normalizes the legacy isMut/isSigner shape", () => {
  const legacy = {
    name: "legacy",
    instructions: [
      {
        name: "do_thing",
        accounts: [
          { name: "payer", isMut: true, isSigner: true },
          { name: "state", isMut: true },
        ],
        args: [{ name: "amount", type: "u64" }],
      },
    ],
  };
  const idl = normalizeIdl(legacy);
  const ix = idl.instructions[0];
  assert.equal(ix.accounts[0].signer, true);
  assert.equal(ix.accounts[0].writable, true);
  assert.equal(ix.accounts[1].writable, true);
  assert.equal(ix.accounts[1].signer, false);
  assert.equal(ix.args[0].type, "u64");
});

test("flags init_config as a privileged instruction with no signer (lane A)", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const f = result.findings.find(
    (x) => x.instruction === "init_config" && x.lane === "A-authority" && x.account === null,
  );
  assert.ok(f, "expected a no-signer finding for init_config");
  assert.equal(f!.severity, "high");
});

test("flags the unbound writable vault as token-custody and substitution risk", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const custody = result.findings.find(
    (x) => x.account === "vault" && x.lane === "C-token-custody",
  );
  const subst = result.findings.find(
    (x) => x.account === "vault" && x.lane === "B-account-substitution",
  );
  assert.ok(custody, "expected token-custody finding for vault");
  assert.ok(subst, "expected account-substitution finding for vault");
});

test("flags arg-derived PDA seed on claim_rewards (lane B)", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const f = result.findings.find(
    (x) =>
      x.instruction === "claim_rewards" &&
      x.account === "reward_account" &&
      /caller-supplied argument/.test(x.title),
  );
  assert.ok(f, "expected arg-seed finding for reward_account");
});

test("flags referrer participation and parent injection (lane E)", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const f = result.findings.find(
    (x) => x.account === "referrer" && x.lane === "E-referral",
  );
  assert.ok(f, "expected referral finding for referrer");
  assert.equal(f!.severity, "medium"); // writable + unbound
});

test("flags set_upgrade_authority with no signer as high (lane F)", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const f = result.findings.find(
    (x) => x.instruction === "set_upgrade_authority" && x.lane === "F-upgrade-admin",
  );
  assert.ok(f, "expected upgrade-admin finding");
  assert.equal(f!.severity, "high");
});

test("builds a full instruction/account matrix", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const totalAccounts = idl.instructions.reduce((n, ix) => n + ix.accounts.length, 0);
  assert.equal(result.matrix.length, totalAccounts);
});

test("does not flag a properly pinned program account", () => {
  const idl = loadIdl(fixture);
  const result = analyzeIdl(idl);
  const noise = result.findings.find((x) => x.account === "system_program");
  assert.equal(noise, undefined, "pinned program accounts should not be flagged");
});
