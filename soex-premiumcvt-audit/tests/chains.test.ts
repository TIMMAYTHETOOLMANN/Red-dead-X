import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chainByChainId,
  chainByKey,
  evmChains,
  ingestionSource,
  isEvm,
  resolveChain,
  usesP2p,
} from "../scripts/lib/chains";

test("chainByKey resolves known chains case-insensitively", () => {
  assert.equal(chainByKey("ethereum")?.chainId, 1);
  assert.equal(chainByKey("  BSC ")?.chainId, 56);
  assert.equal(chainByKey("solana")?.vm, "svm");
});

test("chainByChainId resolves EVM chains by numeric id", () => {
  assert.equal(chainByChainId(42161)?.key, "arbitrum");
  assert.equal(chainByChainId(999999), undefined);
});

test("isEvm classifies VM families", () => {
  assert.equal(isEvm(chainByKey("merlin")!), true);
  assert.equal(isEvm(chainByKey("solana")!), false);
  assert.equal(isEvm(chainByKey("bitcoin")!), false);
});

test("resolveChain throws on unknown chain", () => {
  assert.throws(() => resolveChain("doesnotexist"), /Unknown chain/);
});

test("evmChains returns only EVM chains, each with a thirdweb chain id", () => {
  const chains = evmChains();
  assert.ok(chains.length >= 5);
  for (const c of chains) {
    assert.equal(c.vm, "evm");
    assert.equal(typeof c.thirdwebChainId, "number");
  }
});

test("ingestionSource defaults to rpc when no descriptor is set", () => {
  assert.equal(ingestionSource(chainByKey("ethereum")!), "rpc");
  assert.equal(usesP2p(chainByKey("ethereum")!), false);
});

test("ingestionSource honours an explicit p2p/hybrid descriptor", () => {
  const p2p = {
    ...chainByKey("ethereum")!,
    ingestion: { source: "p2p" as const, bootnodes: ["enode://abc@1.2.3.4:30303"] },
  };
  assert.equal(ingestionSource(p2p), "p2p");
  assert.equal(usesP2p(p2p), true);

  const hybrid = { ...chainByKey("base")!, ingestion: { source: "hybrid" as const } };
  assert.equal(ingestionSource(hybrid), "hybrid");
  assert.equal(usesP2p(hybrid), true);
});
