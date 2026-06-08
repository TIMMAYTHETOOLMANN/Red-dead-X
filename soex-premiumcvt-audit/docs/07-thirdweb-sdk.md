# 07 — thirdweb SDK integration (TypeScript v5 + .NET)

The forensic system leverages the **thirdweb SDK** dynamically to resolve live
on-chain attack surface across every EVM network in the catalog. Two SDK
surfaces are wired in:

- **TypeScript v5** — <https://portal.thirdweb.com/references/typescript/v5>
- **.NET** — <https://portal.thirdweb.com/dotnet>

Both paths are **read-only**: they fetch a contract's ABI / implementation /
bytecode and may call a constant getter (`owner()`), but never build, sign, or
send a transaction. This keeps them inside the same rules of engagement as the
rest of the scaffold (docs/00).

## Why thirdweb

A forensic sweep needs the *real* surface of a deployed contract — every external
function, the proxy implementation behind it, and the bytecode — on any of ~dozens
of EVM chains, with one client. thirdweb gives us:

- one client for any EVM chain by id (`defineChain(chainId)`),
- automatic ABI resolution (`resolveContractAbi`) — including for verified and
  thirdweb-deployed contracts,
- proxy/implementation resolution (`resolveImplementation`) to see *through* a
  proxy to the logic contract that actually holds the seams, and
- type-safe read calls for constant getters.

The resolved ABI flows straight into `lib/evm_analyze.ts`, so live recon and
offline analysis share the exact same hunting lanes and ranking.

## TypeScript v5 — `scripts/evm_recon.ts`

```bash
# A client key is required. Get one at https://thirdweb.com/create-api-key
export THIRDWEB_SECRET_KEY=...        # server-side; or THIRDWEB_CLIENT_ID=...
export EVM_CHAIN=ethereum             # catalog key or numeric id (e.g. 1, 56, 4200)
export EVM_ADDRESS=0xYourTarget
export BUGRAP_PROGRAM=bitget          # optional: scope-check + payout weighting
npm run evm-recon
```

What it does, in order:

1. Enforces `READ_ONLY=true`.
2. Resolves the chain (must be EVM) from `lib/chains.ts`.
3. If `BUGRAP_PROGRAM` is set, runs the scope-compliance gate and **refuses**
   out-of-scope chain/address targets.
4. Builds a thirdweb client, `getContract`, and resolves the ABI +
   implementation (proxy-aware) — all read-only.
5. Runs `analyzeAbi` (payout-weighted by the program's bands) and writes a
   JSON + SARIF + Markdown evidence bundle to `evidence/`.

Key thirdweb v5 imports used:

```ts
import { createThirdwebClient, defineChain, getContract } from "thirdweb";
import { resolveContractAbi } from "thirdweb/contract";
import { resolveImplementation } from "thirdweb/utils";
```

## .NET — `dotnet/ThirdwebForensics`

A standalone read-only console tool that mirrors the TypeScript recon using the
thirdweb .NET SDK, for teams operating in the .NET ecosystem.

```bash
cd dotnet/ThirdwebForensics
dotnet build -c Release

export THIRDWEB_SECRET_KEY=...        # or THIRDWEB_CLIENT_ID
export EVM_CHAIN_ID=1                  # numeric chain id
export EVM_ADDRESS=0xYourTarget
dotnet run -c Release
```

It uses:

```csharp
var client = ThirdwebClient.Create(secretKey: secretKey);
var abiJson = await ThirdwebContract.FetchAbi(client, address, chainId);
var contract = await ThirdwebContract.Create(client, address, chainId, abiJson);
var owner = await ThirdwebContract.Read<string>(contract, "owner"); // constant getter
```

and runs a C# port of the EVM hunting lanes (`EvmHeuristics`) so the .NET output
is the same class of candidate findings as the TypeScript path. It refuses to run
when `READ_ONLY=false` and never touches a wallet.

## Security notes

- **Never commit `THIRDWEB_SECRET_KEY` / `THIRDWEB_CLIENT_ID`.** They live in
  `.env` (git-ignored). The secret key is server-side only.
- Both tools are read-only by construction. There is no transaction path; the
  PoC "hands" remain the guardrailed Solana harness (`scripts/poc_harness.ts`).
- ABI resolution depends on the contract being verified/resolvable; when it is
  not, pin the published ABI and use `npm run forensic-scan` with `EVM_ABI_PATH`.
