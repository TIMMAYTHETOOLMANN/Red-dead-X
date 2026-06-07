import {
  NormalizedAccount,
  NormalizedIdl,
  NormalizedInstruction,
} from "./idl";

/**
 * Deep, multi-layer static analysis of an Anchor IDL.
 *
 * This is a *static* pass: it reasons about the structure the IDL exposes
 * (signers, PDA seeds, writability, fixed addresses, relations) and walks every
 * instruction through the six hunting lanes from `docs/01-hunting-lanes.md`.
 *
 * The output is a list of **candidate** findings to confirm by hand — never a
 * verdict. The triage rubric (`docs/03-triage-rubric.md`) still applies: do not
 * report "the tool said so". The value here is coverage and ranking: it makes
 * sure no instruction/account pair is skipped and surfaces the deep seams
 * (account substitution, missing signer binding, unbound token custody,
 * attacker-influenced PDA seeds) that surface-level scanners miss.
 *
 * Pure functions only. No network, no transactions, no filesystem.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Lane =
  | "A-authority"
  | "B-account-substitution"
  | "C-token-custody"
  | "D-economic"
  | "E-referral"
  | "F-upgrade-admin";

export interface Finding {
  lane: Lane;
  severity: Severity;
  instruction: string;
  account: string | null;
  title: string;
  detail: string;
  recommendation: string;
}

export interface MatrixRow {
  instruction: string;
  account: string;
  signer: boolean;
  writable: boolean;
  seeds: string;
  pinnedAddress: boolean;
  relations: string;
}

export interface AnalysisResult {
  program: string;
  address: string | null;
  instructionCount: number;
  findings: Finding[];
  matrix: MatrixRow[];
  severityCounts: Record<Severity, number>;
  laneCounts: Record<Lane, number>;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// --- naming heuristics -----------------------------------------------------

/** Instructions whose names imply a privileged state mutation. */
const PRIVILEGED_RE =
  /(init|initialize|config|configure|set_|update|admin|owner|authority|withdraw|mint|burn|claim|close|upgrade|migrate|pause|unpause|freeze|thaw|govern|treasury|fee|price|whitelist|blacklist)/i;

/** Account names that imply an authority/role that should be enforced. */
const AUTHORITY_RE =
  /(authority|admin|owner|governance|treasury|signer|payer|delegate|manager|operator)/i;

/** Account names that imply token custody. */
const TOKEN_RE = /(token|vault|ata|mint|escrow|pool|reserve|treasury)/i;

/** Account names that imply referral-graph participation. */
const REFERRAL_RE = /(referr|referer|parent|sponsor|upline|downline|invite|inviter)/i;

/** Instruction names that imply upgrade/admin-authority changes. */
const UPGRADE_RE =
  /(upgrade|migrate|set_authority|transfer_authority|set_admin|set_owner|set_upgrade)/i;

/** Numeric argument types worth simulating for overflow/rounding. */
const NUMERIC_ARG_RE = /(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)/;

function isProgramLike(account: NormalizedAccount): boolean {
  // System/sysvar/token programs are typically pinned by a fixed address.
  return account.hasAddress || /program|sysvar|rent|clock/i.test(account.name);
}

function hasSeeds(account: NormalizedAccount): boolean {
  return account.seeds.length > 0;
}

function seedSummary(account: NormalizedAccount): string {
  if (account.seeds.length === 0) return "";
  return account.seeds.map((s) => `${s.kind}:${s.value}`).join(" + ");
}

// --- lane logic ------------------------------------------------------------

function laneAuthority(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  const privileged = PRIVILEGED_RE.test(ix.name);
  const anySigner = ix.accounts.some((a) => a.signer);

  if (privileged && ix.accounts.length > 0 && !anySigner) {
    findings.push({
      lane: "A-authority",
      severity: "high",
      instruction: ix.name,
      account: null,
      title: "Privileged instruction has no signer",
      detail:
        `Instruction \`${ix.name}\` looks state-mutating/privileged but declares no signer ` +
        `account. If no signer is enforced, anyone can invoke it.`,
      recommendation:
        "Confirm in source: require a `Signer<'info>` (or `has_one` against a stored " +
        "authority that must sign). Reproduce by invoking with an unrelated keypair.",
    });
  }

  for (const acc of ix.accounts) {
    if (!AUTHORITY_RE.test(acc.name)) continue;
    if (isProgramLike(acc)) continue;
    // Payers usually sign; an authority-ish account that neither signs nor is
    // bound by relations/seeds is the classic "authority stored but never compared".
    if (!acc.signer && acc.relations.length === 0 && !hasSeeds(acc) && !acc.hasAddress) {
      findings.push({
        lane: "A-authority",
        severity: "medium",
        instruction: ix.name,
        account: acc.name,
        title: "Authority-like account is not a signer and is unbound",
        detail:
          `Account \`${acc.name}\` in \`${ix.name}\` reads like an authority but is not a ` +
          `signer and has no PDA seeds, pinned address, or \`relations\`/\`has_one\` binding. ` +
          `An attacker may be able to pass an arbitrary account here.`,
        recommendation:
          "Verify the authority is compared to a signer (e.g. `has_one = authority` plus " +
          "`Signer`). Test by substituting an attacker-controlled account.",
      });
    }
  }
  return findings;
}

function laneAccountSubstitution(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  for (const acc of ix.accounts) {
    if (isProgramLike(acc)) continue;
    if (acc.signer) continue; // a signer cannot be silently substituted

    // Writable, non-signer, no seed binding, no pinned address, no relations:
    // the program is trusting an account it cannot verify by derivation.
    if (
      acc.writable &&
      !hasSeeds(acc) &&
      !acc.hasAddress &&
      acc.relations.length === 0 &&
      !/payer|funder/i.test(acc.name)
    ) {
      findings.push({
        lane: "B-account-substitution",
        severity: "medium",
        instruction: ix.name,
        account: acc.name,
        title: "Writable account has no PDA-seed or relation binding",
        detail:
          `Writable account \`${acc.name}\` in \`${ix.name}\` has no declared PDA seeds, ` +
          `pinned address, or \`relations\`. If the program does not re-derive/verify it, ` +
          `a substituted account could redirect writes (state or funds).`,
        recommendation:
          "Confirm the account is a checked PDA (`seeds`+`bump`) or constrained via " +
          "`has_one`/`address`. Try the wrong-account substitution from lane B.",
      });
    }

    // Attacker-influenced PDA seed (`arg`) — the caller can steer which PDA is hit.
    const argSeed = acc.seeds.find((s) => s.kind === "arg");
    if (argSeed) {
      findings.push({
        lane: "B-account-substitution",
        severity: "low",
        instruction: ix.name,
        account: acc.name,
        title: "PDA seed is derived from a caller-supplied argument",
        detail:
          `PDA \`${acc.name}\` in \`${ix.name}\` uses a caller-supplied arg (\`${argSeed.value}\`) ` +
          `as a seed. Caller-steered seeds can let an attacker target or collide PDAs they ` +
          `should not control.`,
        recommendation:
          "Confirm the arg-derived seed is additionally bound to the signer/owner so it " +
          "cannot address another user's PDA.",
      });
    }
  }
  return findings;
}

function laneTokenCustody(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  for (const acc of ix.accounts) {
    if (!TOKEN_RE.test(acc.name)) continue;
    if (isProgramLike(acc)) continue;
    if (acc.signer) continue;

    // Token/vault account that is writable but not seed-bound or relation-bound:
    // mint/owner constraints cannot be confirmed from the IDL, so flag for review.
    if (acc.writable && !hasSeeds(acc) && acc.relations.length === 0) {
      findings.push({
        lane: "C-token-custody",
        severity: "medium",
        instruction: ix.name,
        account: acc.name,
        title: "Token/vault account is not bound by seeds or relations",
        detail:
          `Token-custody account \`${acc.name}\` in \`${ix.name}\` is writable but has no PDA ` +
          `seeds or \`relations\`. The IDL cannot prove its mint/owner/token-program are ` +
          `constrained, so a wrong-mint or wrong-owner token account may be accepted.`,
        recommendation:
          "Confirm `token::mint`, `token::authority`/owner, and `token_program` constraints " +
          "in source. Test with a wrong-mint and wrong-owner token account.",
      });
    }
  }
  return findings;
}

function laneEconomic(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  const numericArgs = ix.args.filter((a) => NUMERIC_ARG_RE.test(a.type));
  const touchesValue = ix.accounts.some(
    (a) => TOKEN_RE.test(a.name) && a.writable && !isProgramLike(a),
  );
  if (numericArgs.length > 0 && touchesValue) {
    findings.push({
      lane: "D-economic",
      severity: "low",
      instruction: ix.name,
      account: null,
      title: "Value-moving instruction takes numeric amounts",
      detail:
        `Instruction \`${ix.name}\` takes numeric arg(s) ` +
        `[${numericArgs.map((a) => `${a.name}:${a.type}`).join(", ")}] and writes a ` +
        `token/vault account. Amount math here is a prime seam for overflow, fee ` +
        `rounding-to-zero, and value-conservation breaks.`,
      recommendation:
        "Run `npm run invariant-sim` against this instruction's fee/mint/burn math and " +
        "probe 0, 1, and near-u64-max boundaries (see docs/02-invariants.md).",
    });
  }
  return findings;
}

function laneReferral(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  for (const acc of ix.accounts) {
    if (!REFERRAL_RE.test(acc.name)) continue;
    const writableUnbound =
      acc.writable && !acc.signer && !hasSeeds(acc) && acc.relations.length === 0;
    findings.push({
      lane: "E-referral",
      severity: writableUnbound ? "medium" : "info",
      instruction: ix.name,
      account: acc.name,
      title: writableUnbound
        ? "Referral/parent account is writable and unbound"
        : "Referral/parent account participates in this instruction",
      detail:
        `Account \`${acc.name}\` in \`${ix.name}\` is part of the referral graph. ` +
        (writableUnbound
          ? "It is writable, non-signing, and unbound, which enables parent injection."
          : "Model the referral graph as a payment graph, not a profile feature."),
      recommendation:
        "Check self-referral, A↔B cycles, parent changes after accrual, duplicate-parent " +
        "injection, deep-chain rounding, and compute exhaustion (lane D).",
    });
  }
  return findings;
}

function laneUpgradeAdmin(ix: NormalizedInstruction): Finding[] {
  const findings: Finding[] = [];
  if (!UPGRADE_RE.test(ix.name)) return findings;
  const anySigner = ix.accounts.some((a) => a.signer);
  findings.push({
    lane: "F-upgrade-admin",
    severity: anySigner ? "medium" : "high",
    instruction: ix.name,
    account: null,
    title: anySigner
      ? "Authority/upgrade change instruction (verify the current authority must sign)"
      : "Authority/upgrade change instruction with no signer",
    detail:
      `Instruction \`${ix.name}\` changes admin/upgrade authority. ` +
      (anySigner
        ? "Confirm the *current* authority (not just any signer) is required."
        : "No signer is declared — an unintended caller may seize authority."),
    recommendation:
      "Verify the current authority is enforced via `has_one`+`Signer`. Cross-check the " +
      "on-chain upgrade authority with `npm run program-info`.",
  });
  return findings;
}

const LANES: ((ix: NormalizedInstruction) => Finding[])[] = [
  laneAuthority,
  laneAccountSubstitution,
  laneTokenCustody,
  laneEconomic,
  laneReferral,
  laneUpgradeAdmin,
];

export function analyzeInstruction(ix: NormalizedInstruction): Finding[] {
  return LANES.flatMap((lane) => lane(ix));
}

function buildMatrix(idl: NormalizedIdl): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const ix of idl.instructions) {
    for (const acc of ix.accounts) {
      rows.push({
        instruction: ix.name,
        account: acc.name,
        signer: acc.signer,
        writable: acc.writable,
        seeds: seedSummary(acc),
        pinnedAddress: acc.hasAddress,
        relations: acc.relations.join(", "),
      });
    }
  }
  return rows;
}

export function analyzeIdl(idl: NormalizedIdl): AnalysisResult {
  const findings = idl.instructions.flatMap(analyzeInstruction);

  const severityCounts = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: 0 }),
    {} as Record<Severity, number>,
  );
  const laneCounts: Record<Lane, number> = {
    "A-authority": 0,
    "B-account-substitution": 0,
    "C-token-custody": 0,
    "D-economic": 0,
    "E-referral": 0,
    "F-upgrade-admin": 0,
  };
  for (const f of findings) {
    severityCounts[f.severity] += 1;
    laneCounts[f.lane] += 1;
  }

  // Sort findings by severity (critical first) for readable output.
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.instruction.localeCompare(b.instruction),
  );

  return {
    program: idl.name,
    address: idl.address,
    instructionCount: idl.instructions.length,
    findings: sorted,
    matrix: buildMatrix(idl),
    severityCounts,
    laneCounts,
  };
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

export { SEVERITY_ORDER };
