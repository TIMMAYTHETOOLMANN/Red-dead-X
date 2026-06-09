import fs from "fs";

export async function loadRegistry() {
  const path = "targets/bugrap-programs.json";
  if (!fs.existsSync(path)) return { programs: [] };
  const data = JSON.parse(fs.readFileSync(path, "utf8"));
  return data;
}

export function enumerateChains(program: any) {
  return program.chains || [];
}

export function enumerateBounties(chain: any) {
  return ["core", "econ"];
}

export function getProgramContracts(program: any, chain: string, bounty: string) {
  return (program.contracts || [])
    .filter((c: any) => c.chain === chain)
    .map((c: any) => c.address);
}

export async function fetchLiveContractMeta(address: string, chain: string) {
  return {
    verified: false,
    proxy: false,
    abi: false,
    admins: [],
    blockNumber: 0,
    blockTimestamp: 0,
  };
}

export function checkLaneCoverage(address: string, chain: string, bounty: string) {
  return ["encoding", "data", "admin", "economic"];
}
