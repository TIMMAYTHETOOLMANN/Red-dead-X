import { ENCODING_ANALYSIS_CONFIG, decodeCandidate, generateFuzzVariants } from "./lib/encoding.js";

async function main() {
  console.log("=== ENCODING & DECODING FORENSICS ===");
  console.log("Stage 1 Analysis\n");

  console.log("--- 1. Testing Default Fields from Config ---");
  for (const field of ENCODING_ANALYSIS_CONFIG.fields) {
    console.log(`\nField: ${field.name}`);
    console.log(`Encodings to check: ${field.encodings.join(", ")}`);
  }

  console.log("\n--- 2. Fuzzing Test Vectors ---");
  for (const vector of ENCODING_ANALYSIS_CONFIG.test_vectors) {
    console.log(`\nOriginal Vector: "${vector.original}"`);
    
    // Convert to fuzz variants
    const variants = generateFuzzVariants(vector.original);
    for (const variant of variants) {
      console.log(`  Format [${variant.format.padEnd(14)}] => Encoded: ${variant.encodedValue}`);
    }
  }

  console.log("\n--- 3. Decoding Simulated 'Malicious' Inputs ---");
  // We'll simulate receiving these encoded strings from a transaction
  const simulatedInputs = [
    "0x61646d696e", // 'admin' in hex
    "YWRtaW4=",      // 'admin' in base64
    "%61%64%6d%69%6e", // 'admin' url encoded
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "726f757465313233" // 'route123' hex without 0x
  ];

  for (const input of simulatedInputs) {
    console.log(`\nSimulated Input: ${input}`);
    const results = decodeCandidate(input);
    if (results.length === 0) {
      console.log("  No valid decodings found.");
    }
    for (const res of results) {
      console.log(`  => Decoded via [${res.format.padEnd(8)}] = "${res.decodedValue.replace(/\x00/g, '\\x00')}"`);
      if (res.suspicious) {
        console.log(`     [!] WARNING: Suspicious value detected!`);
      }
    }
  }

  console.log("\n--- 4. Edge Cases ---");
  for (const edge of ENCODING_ANALYSIS_CONFIG.edge_cases) {
    console.log(`\nEdge Case: "${edge.input}"`);
    console.log(`Purpose:   ${edge.purpose}`);
    const results = decodeCandidate(edge.input);
    for (const res of results) {
      console.log(`  => Decoded via [${res.format.padEnd(8)}] = "${res.decodedValue.replace(/\x00/g, '\\x00')}"`);
      if (res.suspicious) {
        console.log(`     [!] WARNING: Suspicious value detected!`);
      }
    }
  }

  console.log("\n======================================");
}

main().catch(console.error);
