import fs from "fs";

/**
 * Minimal, normalized Anchor IDL model.
 *
 * Anchor changed its IDL shape between releases (pre-0.30 used `isMut`/`isSigner`,
 * 0.30+ uses `writable`/`signer` and a richer `pda` object). The analyzers in this
 * scaffold should not care which compiler produced the file, so we normalize both
 * shapes into the structures below before doing any analysis.
 *
 * Everything here is pure data parsing. No network access, no transactions.
 */

export interface NormalizedSeed {
  /** "const" (literal bytes/string), "account" (another account), or "arg". */
  kind: "const" | "account" | "arg" | "unknown";
  /** Human-readable value: the literal string, account name, or arg name. */
  value: string;
}

export interface NormalizedAccount {
  name: string;
  /** True when the instruction writes to this account. */
  writable: boolean;
  /** True when this account must sign the transaction. */
  signer: boolean;
  /** True when the IDL marks the account optional. */
  optional: boolean;
  /** PDA seeds, when the IDL declares them. Empty array means "no declared seeds". */
  seeds: NormalizedSeed[];
  /** True when the IDL declares a fixed address (e.g. a pinned program/sysvar). */
  hasAddress: boolean;
  /** Relations declared via Anchor `relations`/`has_one` when present in the IDL. */
  relations: string[];
}

export interface NormalizedArg {
  name: string;
  /** Best-effort, lower-cased type string (e.g. "u64", "pubkey", "vec<u8>"). */
  type: string;
}

export interface NormalizedInstruction {
  name: string;
  accounts: NormalizedAccount[];
  args: NormalizedArg[];
}

export interface NormalizedIdl {
  /** Program name when available. */
  name: string;
  /** Program address when the IDL embeds one. */
  address: string | null;
  instructions: NormalizedInstruction[];
}

function typeToString(type: unknown): string {
  if (type == null) return "unknown";
  if (typeof type === "string") return type.toLowerCase();
  if (typeof type === "object") {
    const obj = type as Record<string, unknown>;
    if (typeof obj.defined === "string") return obj.defined.toLowerCase();
    if (obj.defined && typeof obj.defined === "object") {
      const name = (obj.defined as Record<string, unknown>).name;
      if (typeof name === "string") return name.toLowerCase();
    }
    if (obj.option) return `option<${typeToString(obj.option)}>`;
    if (obj.vec) return `vec<${typeToString(obj.vec)}>`;
    if (obj.array) {
      const arr = obj.array as unknown[];
      return `array<${typeToString(arr[0])}>`;
    }
    const key = Object.keys(obj)[0];
    if (key) return key.toLowerCase();
  }
  return "unknown";
}

function normalizeSeed(seed: unknown): NormalizedSeed {
  if (seed == null || typeof seed !== "object") {
    return { kind: "unknown", value: String(seed ?? "") };
  }
  const obj = seed as Record<string, unknown>;
  const kind = typeof obj.kind === "string" ? obj.kind : "";

  if (kind === "const") {
    // Const seeds can be a byte array or an embedded string/value.
    const value = obj.value;
    if (Array.isArray(value)) {
      // Try to render printable ASCII bytes as a string for readability.
      const bytes = value.filter((b): b is number => typeof b === "number");
      const printable = bytes.every((b) => b >= 32 && b < 127);
      const rendered = printable
        ? Buffer.from(bytes).toString("utf8")
        : `bytes[${bytes.length}]`;
      return { kind: "const", value: rendered };
    }
    return { kind: "const", value: String(value ?? "") };
  }

  if (kind === "account") {
    const path = typeof obj.path === "string" ? obj.path : String(obj.account ?? "");
    return { kind: "account", value: path };
  }

  if (kind === "arg") {
    const path = typeof obj.path === "string" ? obj.path : String(obj.arg ?? "");
    return { kind: "arg", value: path };
  }

  return { kind: "unknown", value: JSON.stringify(seed) };
}

function normalizeAccount(account: Record<string, unknown>): NormalizedAccount {
  const writable = Boolean(account.writable ?? account.isMut ?? false);
  const signer = Boolean(account.signer ?? account.isSigner ?? false);
  const optional = Boolean(account.optional ?? account.isOptional ?? false);
  const hasAddress = typeof account.address === "string" && account.address.length > 0;

  let seeds: NormalizedSeed[] = [];
  const pda = account.pda;
  if (pda && typeof pda === "object") {
    const rawSeeds = (pda as Record<string, unknown>).seeds;
    if (Array.isArray(rawSeeds)) {
      seeds = rawSeeds.map(normalizeSeed);
    } else {
      // pda object present but seeds not enumerated.
      seeds = [{ kind: "unknown", value: "pda" }];
    }
  }

  const relations = Array.isArray(account.relations)
    ? (account.relations as unknown[]).map((r) => String(r))
    : [];

  return {
    name: String(account.name ?? "unknown"),
    writable,
    signer,
    optional,
    seeds,
    hasAddress,
    relations,
  };
}

/**
 * Flatten Anchor account groups. Older IDLs may nest accounts under a group
 * via an `accounts` array on a composite account entry.
 */
function flattenAccounts(raw: unknown[]): NormalizedAccount[] {
  const out: NormalizedAccount[] = [];
  for (const entry of raw) {
    if (entry && typeof entry === "object") {
      const obj = entry as Record<string, unknown>;
      if (Array.isArray(obj.accounts)) {
        out.push(...flattenAccounts(obj.accounts));
      } else {
        out.push(normalizeAccount(obj));
      }
    }
  }
  return out;
}

function normalizeInstruction(ix: Record<string, unknown>): NormalizedInstruction {
  const accounts = Array.isArray(ix.accounts) ? flattenAccounts(ix.accounts) : [];
  const args = Array.isArray(ix.args)
    ? (ix.args as Record<string, unknown>[]).map((a) => ({
        name: String(a.name ?? "unknown"),
        type: typeToString(a.type),
      }))
    : [];
  return {
    name: String(ix.name ?? "unknown"),
    accounts,
    args,
  };
}

export function normalizeIdl(raw: unknown): NormalizedIdl {
  if (!raw || typeof raw !== "object") {
    throw new Error("IDL is not a JSON object.");
  }
  const obj = raw as Record<string, unknown>;

  const metadata = (obj.metadata ?? {}) as Record<string, unknown>;
  const name =
    (typeof metadata.name === "string" && metadata.name) ||
    (typeof obj.name === "string" && obj.name) ||
    "unknown-program";

  const address =
    (typeof obj.address === "string" && obj.address) ||
    (typeof metadata.address === "string" && metadata.address) ||
    null;

  const instructions = Array.isArray(obj.instructions)
    ? (obj.instructions as Record<string, unknown>[]).map(normalizeInstruction)
    : [];

  return { name, address, instructions };
}

export function loadIdl(path: string): NormalizedIdl {
  const raw = fs.readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse IDL JSON at ${path}: ${(err as Error).message}`);
  }
  return normalizeIdl(parsed);
}
