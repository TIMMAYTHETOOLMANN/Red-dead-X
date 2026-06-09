import fs from "fs";

// Multi-chain Provider Pool and Rotation

export const PROVIDER_POOL: Record<string, string[]> = {
  ethereum: ["https://eth.llamarpc.com", "https://rpc.ankr.com/eth"],
  solana: ["https://api.mainnet-beta.solana.com", "https://solana-api.projectserum.com"],
  bsc: ["https://bsc-dataseed.binance.org"],
  polygon: ["https://polygon-rpc.com"],
  base: ["https://mainnet.base.org"],
  sui: ["https://fullnode.mainnet.sui.io:443"],
  aptos: ["https://fullnode.mainnet.aptoslabs.com/v1"],
};

export async function rotateProvider(chain: string): Promise<string> {
  const pool = PROVIDER_POOL[chain] || [];
  if (pool.length === 0) {
    throw new Error(`CRITICAL: Provider pool exhausted for chain ${chain}`);
  }
  // In a real scenario, this would test latency and select the best provider
  return pool[Math.floor(Math.random() * pool.length)];
}

export async function fetchWithFallback(chain: string, action: (rpc: string) => Promise<any>): Promise<any> {
  const pool = PROVIDER_POOL[chain] || [];
  for (const rpc of pool) {
    try {
      return await action(rpc);
    } catch (e) {
      console.error(`Provider ${rpc} failed for ${chain}. Rotating...`);
    }
  }
  throw new Error(`CRITICAL: All RPCs failed for ${chain}. No stale data allowed.`);
}
