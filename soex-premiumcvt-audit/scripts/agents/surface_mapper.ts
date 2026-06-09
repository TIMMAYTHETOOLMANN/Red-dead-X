import {
  loadRegistry, enumerateChains, enumerateBounties, getProgramContracts,
  fetchLiveContractMeta, checkLaneCoverage
} from './util/surface-tools';

// Map the entire attack surface using live onchain data only
export async function mapSurfaceAndCoverage() {
  const registry = await loadRegistry();
  const results = [];
  for (const program of registry.programs) {
    for (const chain of enumerateChains(program)) {
      for (const bounty of enumerateBounties(chain)) {
        const contracts = getProgramContracts(program, chain, bounty);
        for (const address of contracts) {
          const meta = await fetchLiveContractMeta(address, chain);
          const lanes = checkLaneCoverage(address, chain, bounty);
          results.push({ program, chain, bounty, address,
                        verified: meta.verified, proxy: meta.proxy, abi: !!meta.abi,
                        privilege: meta.admins || [], lanes,
                        block: meta.blockNumber, timestamp: meta.blockTimestamp });
        }
      }
    }
  }
  return results;
}

export const SURFACE_MAP_CONFIG = {
  registryPath: "targets/bugrap-programs.json",
  requireLiveData: true,
  requiredLanes: ["encoding", "data", "admin", "economic", "forensics"],
  failOnAnyMissing: true
};

if (require.main === module) {
  mapSurfaceAndCoverage().then(res => console.log(JSON.stringify(res, null, 2))).catch(console.error);
}
