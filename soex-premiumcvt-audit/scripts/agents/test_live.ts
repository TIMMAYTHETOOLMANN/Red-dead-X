import { mapSurfaceAndCoverage } from "./surface_mapper";

async function run() {
  console.log("Running live tests against current onchain block...");
  const matrix = await mapSurfaceAndCoverage();
  console.log(`Verified ${matrix.length} cells against live chain state.`);
}

run().catch(console.error);
