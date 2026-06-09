import fs from "fs";

export function logIncident(level: string, message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${level}] ${message} ${data ? JSON.stringify(data) : ""}\n`;
  fs.appendFileSync("incidents.log", logEntry);
  if (level === "CRITICAL") {
    console.error(`\x1b[31m${logEntry}\x1b[0m`);
    // CI should fail here
    process.exit(1);
  } else {
    console.warn(`\x1b[33m${logEntry}\x1b[0m`);
  }
}

export function enforceLiveData(data: any, source: string) {
  if (!data || Object.keys(data).length === 0) {
    logIncident("CRITICAL", `No data received from ${source}. Empty/stale data forbidden.`);
  }
}
