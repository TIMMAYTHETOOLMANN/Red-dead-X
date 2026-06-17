import { test } from "node:test";
import assert from "node:assert/strict";
import { scanEvmBytecode, scanSvmIdlMetadata } from "../scripts/lib/bytecode_scanner";

test("scanEvmBytecode detects Solidity pre-0.8.0 vulnerability", () => {
  // Mock a bytecode hex with 'solc' followed by pre-0.8.0 version metadata (0.7.6 => 00 07 06)
  // 'solc' ASCII hex is '736f6c63'
  // Version metadata is '736f6c6343000706' ('solc' + 'C' + 00 07 06)
  const pre08Bytecode = "0000a165627a7a72305820736f6c63430007060033";
  const findings = scanEvmBytecode(pre08Bytecode);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].compiler, "Solidity");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].versionDetected, "0.7.6");
  assert.match(findings[0].title, /Solidity < 0.8.0/);
});

test("scanEvmBytecode detects Solidity pre-0.5.0 uninitialized storage pointers", () => {
  // Mock 0.4.25 (00 04 19) version
  const pre05Bytecode = "0000a165627a7a72305820736f6c63430004190033";
  const findings = scanEvmBytecode(pre05Bytecode);
  assert.equal(findings.length, 2); // pre-0.8.0 AND pre-0.5.0
  const titles = findings.map(f => f.title);
  assert.ok(titles.some(t => t.includes("Uninitialized Storage Pointers")));
});

test("scanEvmBytecode detects Vyper reentrancy lock vulnerability", () => {
  // Mock vyper 0.3.0
  // 'vyper' hex is '7679706572'
  const vyperBytecode = "76797065722076302e332e30"; // 'vyper v0.3.0' as hex/ascii representation
  const findings = scanEvmBytecode(vyperBytecode);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].compiler, "Vyper");
  assert.equal(findings[0].versionDetected, "0.3.0");
  assert.equal(findings[0].severity, "critical");
});

test("scanSvmIdlMetadata detects old vulnerable Anchor framework versions", () => {
  const idlJson = {
    metadata: {
      origin: "anchor",
      version: "0.24.2"
    }
  };
  const findings = scanSvmIdlMetadata(idlJson);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].compiler, "Anchor");
  assert.equal(findings[0].versionDetected, "0.24.2");
  assert.equal(findings[0].severity, "high");
});
