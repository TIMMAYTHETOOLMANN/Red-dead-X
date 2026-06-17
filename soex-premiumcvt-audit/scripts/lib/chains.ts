/**
 * Multi-chain / network catalog.
 *
 * The original scaffold was Solana-only. BugRap (the D5 bounty ecosystem) spans
 * many networks — EVM L1s/L2s, Bitcoin L2s, Solana (SVM), privacy chains, and
 * more — so forensic analysis has to know *which* virtual machine a target runs
 * on before it can pick the right analyzer lane and the right SDK adapter.
 *
 * This module is the routing table: it maps a human network key to its VM
 * family, numeric chain id (for EVM), and the thirdweb chain handle used by the
 * read-only recon collectors. It is pure data + lookups — no network, no SDK
 * calls. The thirdweb-backed collectors (`scripts/evm_recon.ts`) consume
 * `thirdwebChainId` to call `defineChain(...)` at the edge.
 */

/** Virtual-machine family a network belongs to. Drives analyzer/SDK selection. */
export type Vm = "evm" | "svm" | "btc" | "cosmos" | "other";

/**
 * How raw chain data is ingested for a network.
 *
 * - `rpc`    — query a standard JSON-RPC endpoint (today's thirdweb path). The
 *              default for every chain so existing behaviour is unchanged.
 * - `p2p`    — peer directly with the network (the future "Forged Node": devp2p
 *              for EVM, native wire protocols for others) to read mempool/blocks
 *              without a rate-limited RPC provider.
 * - `hybrid` — peer for the firehose but fall back to RPC for point lookups.
 */
export type IngestionSource = "rpc" | "p2p" | "hybrid";

/**
 * Optional ingestion descriptor laying the seam for the "Forged Node" P2P tier.
 * Purely declarative — no peer is dialled here. Collectors read `source` to pick
 * a data path; a future out-of-process Forged Node service consumes `bootnodes`.
 */
export interface IngestionConfig {
  /** Preferred ingestion path. Absent ⇒ treated as `rpc`. */
  source: IngestionSource;
  /**
   * Bootstrap peers for the P2P path (enode/multiaddr/host:port strings). Unused
   * by the offline analyzers; consumed only by the opt-in Forged Node service.
   */
  bootnodes?: string[];
}

export interface ChainInfo {
  /** Stable lower-case key used across the registry (e.g. "ethereum", "bsc"). */
  key: string;
  /** Human-readable display name. */
  name: string;
  /** Virtual machine family. */
  vm: Vm;
  /** EVM numeric chain id when applicable (thirdweb `defineChain` input). null otherwise. */
  chainId: number | null;
  /** Native gas/settlement asset symbol. */
  nativeSymbol: string;
  /** True for test networks (devnet/testnet) — preferred for any active PoC. */
  testnet: boolean;
  /**
   * thirdweb chain id to pass to `defineChain`. For EVM chains this equals
   * `chainId`; non-EVM chains have no thirdweb EVM handle (null) and are routed
   * to their native analyzer instead.
   */
  thirdwebChainId: number | null;
  /**
   * True when P2P fallback mode is allowed or enabled (bypass RPC limits)
   */
  p2pFallback?: boolean;
  /**
   * Forged Node bootstrap peers for sustained unrestricted P2P peering
   */
  p2pPeers?: string[];
  /**
   * Optional ingestion descriptor. Absent ⇒ standard RPC. Lets a chain opt into
   * the future P2P "Forged Node" firehose without changing any collector today.
   */
  ingestion?: IngestionConfig;
}

/**
 * Catalog of the networks that appear across BugRap programs. EVM chain ids are
 * the canonical mainnet ids; extend as new programs are scoped. Keep keys lower
 * case and unique.
 */
export const CHAINS: ChainInfo[] = [
  {
    key: "ethereum",
    name: "Ethereum",
    vm: "evm",
    chainId: 1,
    nativeSymbol: "ETH",
    testnet: false,
    thirdwebChainId: 1,
    p2pFallback: true,
    p2pPeers: [
      "enode://d860a01f9722d59c4e13d72d14154336@18.135.143.102:30303",
      "enode://22a8232c3eb761119b90eb47d57050d4@3.209.45.79:30303"
    ],
  },
  {
    key: "bsc",
    name: "BNB Smart Chain",
    vm: "evm",
    chainId: 56,
    nativeSymbol: "BNB",
    testnet: false,
    thirdwebChainId: 56,
    p2pFallback: true,
    p2pPeers: [
      "enode://9e3c98f9ef94d4d12c0192e22a36b3f2@54.120.35.42:30303"
    ],
  },
  {
    key: "polygon",
    name: "Polygon PoS",
    vm: "evm",
    chainId: 137,
    nativeSymbol: "POL",
    testnet: false,
    thirdwebChainId: 137,
    p2pFallback: true,
    p2pPeers: [
      "enode://04e8d38403d9de0398f8cf112a970e5c@100.25.10.12:30303"
    ],
  },
  {
    key: "arbitrum",
    name: "Arbitrum One",
    vm: "evm",
    chainId: 42161,
    nativeSymbol: "ETH",
    testnet: false,
    thirdwebChainId: 42161,
    p2pFallback: true,
  },
  {
    key: "optimism",
    name: "OP Mainnet",
    vm: "evm",
    chainId: 10,
    nativeSymbol: "ETH",
    testnet: false,
    thirdwebChainId: 10,
    p2pFallback: true,
  },
  {
    key: "base",
    name: "Base",
    vm: "evm",
    chainId: 8453,
    nativeSymbol: "ETH",
    testnet: false,
    thirdwebChainId: 8453,
    p2pFallback: true,
  },
  {
    key: "merlin",
    name: "Merlin Chain (Bitcoin L2, EVM-equivalent)",
    vm: "evm",
    chainId: 4200,
    nativeSymbol: "BTC",
    testnet: false,
    thirdwebChainId: 4200,
  },
  {
    key: "morph",
    name: "Morph (Ethereum L2)",
    vm: "evm",
    chainId: 2818,
    nativeSymbol: "ETH",
    testnet: false,
    thirdwebChainId: 2818,
  },
  {
    key: "platon",
    name: "PlatON (privacy-preserving)",
    vm: "evm",
    chainId: 210425,
    nativeSymbol: "LAT",
    testnet: false,
    thirdwebChainId: 210425,
  },
  {
    key: "solana",
    name: "Solana",
    vm: "svm",
    chainId: null,
    nativeSymbol: "SOL",
    testnet: false,
    thirdwebChainId: null,
  },
  {
    key: "solana-devnet",
    name: "Solana Devnet",
    vm: "svm",
    chainId: null,
    nativeSymbol: "SOL",
    testnet: true,
    thirdwebChainId: null,
  },
  {
    key: "bitcoin",
    name: "Bitcoin",
    vm: "btc",
    chainId: null,
    nativeSymbol: "BTC",
    testnet: false,
    thirdwebChainId: null,
  },
];

const BY_KEY = new Map<string, ChainInfo>(CHAINS.map((c) => [c.key, c]));
const BY_CHAIN_ID = new Map<number, ChainInfo>(
  CHAINS.filter((c): c is ChainInfo & { chainId: number } => c.chainId !== null).map(
    (c) => [c.chainId, c],
  ),
);

/** Look up a chain by its lower-case key. Returns undefined when unknown. */
export function chainByKey(key: string): ChainInfo | undefined {
  return BY_KEY.get(key.trim().toLowerCase());
}

/** Look up an EVM chain by numeric id. Returns undefined when unknown. */
export function chainByChainId(chainId: number): ChainInfo | undefined {
  return BY_CHAIN_ID.get(chainId);
}

/** True when the chain runs the EVM (so the EVM analyzer + thirdweb apply). */
export function isEvm(chain: ChainInfo): boolean {
  return chain.vm === "evm";
}

/**
 * Resolve a chain reference (key or numeric chain id) to a `ChainInfo`. Throws a
 * descriptive error for unknown chains so callers fail loudly instead of
 * silently analyzing the wrong VM.
 */
export function resolveChain(ref: string | number): ChainInfo {
  const found =
    typeof ref === "number" ? chainByChainId(ref) : chainByKey(ref);
  if (!found) {
    throw new Error(
      `Unknown chain "${ref}". Add it to scripts/lib/chains.ts before analyzing ` +
        `(routing the wrong VM produces meaningless findings).`,
    );
  }
  return found;
}

/** All EVM chains in the catalog (for thirdweb-backed sweeps). */
export function evmChains(): ChainInfo[] {
  return CHAINS.filter(isEvm);
}

/** Check if a chain supports P2P fallback peering mode (unrestricted mempool/block ingestion) */
export function isP2PEnabled(chain: ChainInfo): boolean {
  return !!chain.p2pFallback;
}

/** Retrieve the bootstrap peer enode/multiaddr references for forged node connection */
export function getBootstrapPeers(chain: ChainInfo): string[] {
  return chain.p2pPeers ?? [];
}

/**
 * Resolve a chain's ingestion source. Defaults to `"rpc"` when the chain has no
 * explicit `ingestion` descriptor, so today's thirdweb/RPC collectors keep
 * working unchanged while P2P-enabled chains can opt into the Forged Node tier.
 */
export function ingestionSource(chain: ChainInfo): IngestionSource {
  return chain.ingestion?.source ?? "rpc";
}

/** True when a chain is configured to use the P2P "Forged Node" path. */
export function usesP2p(chain: ChainInfo): boolean {
  const src = ingestionSource(chain);
  return src === "p2p" || src === "hybrid";
}
