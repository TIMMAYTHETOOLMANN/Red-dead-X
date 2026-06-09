/**
 * Encoding & Decoding Tools - Security & Methodology Scaffold
 *
 * This module facilitates the systematic forensic decoding of contract inputs,
 * looking for obfuscated privilege escalation, parameter smuggling, and injection.
 */

export const ENCODING_ANALYSIS_CONFIG = {
  fields: [
    // Add ABI or config fields here for analysis
    { name: "init_payload", encodings: ["hex", "base64", "ascii", "utf8"] },
    { name: "role", encodings: ["utf8", "base64", "url"] },
    { name: "referrer", encodings: ["hex", "ascii", "url"] },
  ],
  test_vectors: [
    // Use for simulation and fuzzing
    {
      original: "admin",
      hex: "0x61646d696e",
      base64: "YWRtaW4=",
      url: "admin",
      padded_32b: "admin".padEnd(32, "\x00"),
    },
  ],
  edge_cases: [
    { input: "", purpose: "Empty field (DoS/Bypass check)" },
    { input: "%00", purpose: "Null bytes (parsing/logic breakage)" },
    { input: "0x0000000000000000000000000000000000000000000000000000000000000000", purpose: "Zero field (privilege edge case)" },
    { input: "YQ==", decode: "a", purpose: "Single-char to check len bounds" },
  ],
};

export interface DecodedResult {
  format: string;
  decodedValue: string;
  isPrintable: boolean;
  suspicious: boolean;
}

export interface FuzzVariant {
  format: string;
  encodedValue: string;
}

const SUSPICIOUS_TERMS = ["admin", "sudo", "upgrader", "owner", "root", "system"];

/**
 * Attempts to decode a given string across various formats.
 */
export function decodeCandidate(input: string): DecodedResult[] {
  const results: DecodedResult[] = [];

  // Remove 0x prefix for hex
  const cleanHex = input.startsWith("0x") ? input.slice(2) : input;

  // 1. Hex -> UTF8
  try {
    if (/^[0-9a-fA-F]+$/.test(cleanHex)) {
      const decoded = Buffer.from(cleanHex, 'hex').toString('utf8');
      results.push({
        format: "hex",
        decodedValue: decoded,
        isPrintable: isPrintableASCII(decoded),
        suspicious: isSuspicious(decoded)
      });
    }
  } catch (e) {}

  // 2. Base64 -> UTF8
  try {
    if (/^[a-zA-Z0-9+/]*={0,2}$/.test(input)) {
      const decoded = Buffer.from(input, 'base64').toString('utf8');
      results.push({
        format: "base64",
        decodedValue: decoded,
        isPrintable: isPrintableASCII(decoded),
        suspicious: isSuspicious(decoded)
      });
    }
  } catch (e) {}

  // 3. URL Decode
  try {
    if (input.includes('%')) {
      const decoded = decodeURIComponent(input);
      results.push({
        format: "url",
        decodedValue: decoded,
        isPrintable: isPrintableASCII(decoded),
        suspicious: isSuspicious(decoded)
      });
    }
  } catch (e) {}

  return results;
}

/**
 * Generates test payloads for a given string (e.g. 'admin')
 */
export function generateFuzzVariants(input: string): FuzzVariant[] {
  const variants: FuzzVariant[] = [];
  
  // Raw
  variants.push({ format: "raw", encodedValue: input });
  
  // Hex
  variants.push({ format: "hex", encodedValue: "0x" + Buffer.from(input, 'utf8').toString('hex') });
  
  // Base64
  variants.push({ format: "base64", encodedValue: Buffer.from(input, 'utf8').toString('base64') });
  
  // URL Encode
  variants.push({ format: "url", encodedValue: encodeURIComponent(input) });

  // Padded 32 bytes (common in Solidity)
  if (input.length <= 32) {
    const padded = input.padEnd(32, "\x00");
    variants.push({ format: "padded_32b", encodedValue: padded });
    variants.push({ format: "hex_padded_32b", encodedValue: "0x" + Buffer.from(padded, 'utf8').toString('hex') });
  }

  return variants;
}

function isPrintableASCII(str: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7E]*$/.test(str.replace(/\x00/g, '')); // Allow null padding
}

function isSuspicious(str: string): boolean {
  const lower = str.toLowerCase().replace(/\x00/g, ''); // ignore null padding
  return SUSPICIOUS_TERMS.some(term => lower.includes(term));
}
