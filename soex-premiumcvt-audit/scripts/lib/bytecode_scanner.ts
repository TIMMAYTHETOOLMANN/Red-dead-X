import { Severity, Confidence } from "./analyze";

export interface BytecodeFinding {
  id: string;
  source: "bytecode" | "idl";
  compiler: string;
  versionDetected: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  detail: string;
  recommendation: string;
}

/**
 * Scan EVM hex bytecode for compiler metadata, version strings, and compiler-specific CVEs
 */
export function scanEvmBytecode(bytecodeHex: string): BytecodeFinding[] {
  const findings: BytecodeFinding[] = [];
  if (!bytecodeHex) return findings;

  const bytecode = bytecodeHex.toLowerCase();

  // 1. Solidity Metadata and Compiler Version Check
  // Metadata often contains 'solc' followed by 3 bytes for version (e.g., 00 08 09 for 0.8.9)
  // Hex representation: '736f6c63' is 'solc' in ascii
  const solcIndex = bytecode.indexOf("736f6c63"); // 'solc'
  let detectedSolcVersion = "";

  if (solcIndex !== -1) {
    // Try offset + 10 (common with '43' prefix for version string/length)
    if (solcIndex + 16 <= bytecode.length) {
      const versionHex = bytecode.slice(solcIndex + 10, solcIndex + 16);
      const major = parseInt(versionHex.slice(0, 2), 16);
      const minor = parseInt(versionHex.slice(2, 4), 16);
      const patch = parseInt(versionHex.slice(4, 6), 16);
      if (!isNaN(major) && !isNaN(minor) && !isNaN(patch) && major === 0 && minor < 50) {
        detectedSolcVersion = `${major}.${minor}.${patch}`;
      }
    }
    // Try offset + 8 (direct prefix)
    if (!detectedSolcVersion && solcIndex + 14 <= bytecode.length) {
      const versionHex = bytecode.slice(solcIndex + 8, solcIndex + 14);
      const major = parseInt(versionHex.slice(0, 2), 16);
      const minor = parseInt(versionHex.slice(2, 4), 16);
      const patch = parseInt(versionHex.slice(4, 6), 16);
      if (!isNaN(major) && !isNaN(minor) && !isNaN(patch) && major === 0 && minor < 50) {
        detectedSolcVersion = `${major}.${minor}.${patch}`;
      }
    }
  }

  // Backup check: ascii search
  if (!detectedSolcVersion) {
    try {
      const ascii = Buffer.from(bytecode, "hex").toString("utf-8");
      const solcMatch = ascii.match(/solc\s*v?(\d+\.\d+\.\d+)/i);
      if (solcMatch) {
        detectedSolcVersion = solcMatch[1];
      }
    } catch {
      // ignore parsing errors
    }
  }

  // If detected, analyze solidity version vulnerabilities
  if (detectedSolcVersion) {
    const parts = detectedSolcVersion.split(".").map(Number);
    if (parts.length >= 3) {
      const [major, minor, patch] = parts;
      
      // Vulnerability: Pre-0.8.0 default overflow/underflow
      if (major === 0 && minor < 8) {
        findings.push({
          id: `bytecode-solc-underflow-${detectedSolcVersion}`,
          source: "bytecode",
          compiler: "Solidity",
          versionDetected: detectedSolcVersion,
          severity: "high",
          confidence: "likely",
          title: "Vulnerable Compiler: Solidity < 0.8.0 Default Integer Overflow/Underflow",
          detail: `The contract was compiled with Solidity version ${detectedSolcVersion}. ` +
                  `Prior to 0.8.0, arithmetic operations did not have default overflow/underflow protection, ` +
                  `which can lead to critical economic drains unless SafeMath is strictly used.`,
          recommendation: "Ensure SafeMath is used for all arithmetic, or upgrade compiler to 0.8.x."
        });
      }

      // Vulnerability: Pre-0.5.0 uninitialized storage pointers
      if (major === 0 && minor < 5) {
        findings.push({
          id: `bytecode-solc-uninitialized-storage-${detectedSolcVersion}`,
          source: "bytecode",
          compiler: "Solidity",
          versionDetected: detectedSolcVersion,
          severity: "high",
          confidence: "likely",
          title: "Vulnerable Compiler: Solidity < 0.5.0 Uninitialized Storage Pointers",
          detail: `The contract was compiled with Solidity version ${detectedSolcVersion}. ` +
                  `Prior to 0.5.0, uninitialized local storage variables could point to arbitrary storage slots, ` +
                  `allowing unauthorized writes to state variables.`,
          recommendation: "Upgrade contract compiler version to at least 0.5.x, ideally >= 0.8.0."
        });
      }
    }
  }

  // 2. Vyper Version Checks
  // Hex representation: '7679706572' is 'vyper' in ascii
  const vyperIndex = bytecode.indexOf("7679706572"); // 'vyper'
  let detectedVyperVersion = "";
  if (vyperIndex !== -1) {
    try {
      const ascii = Buffer.from(bytecode, "hex").toString("utf-8");
      const vyperMatch = ascii.match(/vyper\s*v?(\d+\.\d+\.\d+)/i);
      if (vyperMatch) {
        detectedVyperVersion = vyperMatch[1];
      }
    } catch {
      // ignore
    }
  }

  if (detectedVyperVersion) {
    // Vulnerability: Vyper reentrancy lock vulnerability (CVE-2023-40015, etc.) in 0.2.15, 0.2.16, 0.3.0
    if (["0.2.15", "0.2.16", "0.3.0"].includes(detectedVyperVersion)) {
      findings.push({
        id: `bytecode-vyper-reentrancy-${detectedVyperVersion}`,
        source: "bytecode",
        compiler: "Vyper",
        versionDetected: detectedVyperVersion,
        severity: "critical",
        confidence: "high",
        title: "Critical Compiler: Vyper Re-entrancy Lock Failure",
        detail: `The contract was compiled with Vyper ${detectedVyperVersion}, which is vulnerable to re-entrancy lock failure ` +
                `where cross-calling contracts can bypass @nonreentrant decorator protections under certain configurations.`,
        recommendation: "Recompile the contract using Vyper version 0.3.1 or higher."
      });
    }
  }

  return findings;
}

/**
 * Scan SVM IDL / Metadata for known old compiler or Anchor vulnerability flags
 */
export function scanSvmIdlMetadata(idlJson: any): BytecodeFinding[] {
  const findings: BytecodeFinding[] = [];
  if (!idlJson) return findings;

  // Look for anchor version in metadata
  let anchorVersion = "";
  if (idlJson.metadata && typeof idlJson.metadata === "object") {
    anchorVersion = idlJson.metadata.version || idlJson.metadata.compiler || "";
  }

  // Check if any comments indicate old versions or dependencies
  if (!anchorVersion && idlJson.instructions) {
    const idlStr = JSON.stringify(idlJson).toLowerCase();
    const match = idlStr.match(/"anchor"\s*:\s*"([^"]+)"/i);
    if (match) {
      anchorVersion = match[1];
    }
  }

  if (anchorVersion) {
    const parts = anchorVersion.split(".").map(Number);
    if (parts.length >= 2) {
      const [major, minor] = parts;
      // Anchor < 0.26.0 has some reinitialization risk / CPI account validation vulnerabilities
      if (major === 0 && minor < 26) {
        findings.push({
          id: `idl-anchor-reinit-${anchorVersion}`,
          source: "idl",
          compiler: "Anchor",
          versionDetected: anchorVersion,
          severity: "high",
          confidence: "likely",
          title: "Vulnerable Anchor Framework: Re-initialization & CPI vulnerabilities",
          detail: `The program is built using Anchor framework version ${anchorVersion}. ` +
                  `Anchor versions below 0.26.0 have known vulnerabilities in automated account validation, ` +
                  `re-initialization checks, and PDA owner derivation under certain contexts.`,
          recommendation: "Upgrade the project's Anchor framework to at least 0.26.0 or preferably >= 0.30.0."
        });
      }
    }
  }

  return findings;
}
