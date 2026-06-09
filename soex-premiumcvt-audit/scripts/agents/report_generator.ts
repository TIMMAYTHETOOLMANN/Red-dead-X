import { collectLaneFindings, generateSARIF, exportMarkdown, saveJSON, logTacticalAttackPlan } from './util/report-tools';
import { mapSurfaceAndCoverage } from './surface_mapper';

export async function exportUnifiedReport(matrix: any[]) {
  for (const cell of matrix) {
    const findings = await collectLaneFindings(cell.address, cell.chain, cell.bounty);
    generateSARIF(cell, findings);
    exportMarkdown(cell, findings);
    saveJSON(cell, findings);
    logTacticalAttackPlan(cell, findings);
  }
}

if (require.main === module) {
  mapSurfaceAndCoverage()
    .then(matrix => exportUnifiedReport(matrix))
    .then(() => console.log("Report generation complete."))
    .catch(console.error);
}
