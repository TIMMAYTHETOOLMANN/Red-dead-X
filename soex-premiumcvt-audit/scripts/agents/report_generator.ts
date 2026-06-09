import { collectLaneFindings, generateSARIF, exportMarkdown, saveJSON, logTacticalAttackPlan } from './util/report-tools';

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
  // Dummy run
  exportUnifiedReport([]).then(() => console.log("Report generation complete.")).catch(console.error);
}
