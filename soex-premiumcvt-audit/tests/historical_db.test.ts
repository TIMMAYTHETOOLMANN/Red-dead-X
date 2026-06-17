import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ForensicsTracingDB,
  CLICKHOUSE_SCHEMA,
  POSTGRES_SCHEMA
} from "../scripts/lib/historical_db";

test("historical_db defines valid schemas as SQL strings", () => {
  assert.ok(CLICKHOUSE_SCHEMA.includes("CREATE TABLE IF NOT EXISTS"));
  assert.ok(POSTGRES_SCHEMA.includes("CREATE TABLE breached_addresses"));
});

test("ForensicsTracingDB traces direct and indirect breach relationships", () => {
  const db = new ForensicsTracingDB();

  // Test direct breach detection
  const report1 = db.queryBreachGenealogy("0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
  assert.equal(report1.riskLevel, "critical");
  assert.ok(report1.directBreach);
  assert.equal(report1.directBreach.severityLevel, "critical");

  // Test clean address
  const cleanAddress = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae";
  const report2 = db.queryBreachGenealogy(cleanAddress);
  assert.equal(report2.riskLevel, "none");
  assert.equal(report2.indirectBreaches.length, 0);

  // Trace 1-hop relationship: clean address -> trace to compromised address
  const intermediate = "0xabcde12345abcde12345abcde12345abcde12345";
  const compromised = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"; // seeded as compromised

  db.addTrace({
    traceId: "uuid-1",
    fromAddress: intermediate,
    toAddress: compromised,
    blockNumber: 15200000,
    transactionHash: "0xhash1",
    valueTransferred: 1.5,
    chainKey: "ethereum",
    timestamp: new Date()
  });

  const report3 = db.queryBreachGenealogy(intermediate);
  assert.equal(report3.riskLevel, "high");
  assert.equal(report3.indirectBreaches.length, 1);
  assert.equal(report3.indirectBreaches[0].hops, 1);
  assert.equal(report3.indirectBreaches[0].breachedAddress.address, compromised);
});
