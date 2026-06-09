# Stage 1: Encoding & Decoding Tools – Forensic Analysis Scaffold

This module provides a structured approach to encoding/decoding analysis for smart contract security, specifically focusing on identifying hidden privilege escalations, payload smuggling, and input sanitization bypasses.

## 1. Structured Tool Inventory

| Tool | Category | Example Usage | Contract/Attack Pitfall |
|---|---|---|---|
| Base64/Base32 | Encoder/Decoder | Encode calldata, decode secrets | Leaked base64 params; payload smuggling |
| URL Encoding | Encoder/Decoder | Onchain URIs; calldata | Malformed inputs → privilege escalation, path traversal |
| ASCII/Text Escape | Escape/Unescape | ABI param crafting; log parsing | Input sanitization bypass via unicode/junk |
| Hex Encoder | Encoder/Decoder | Decode storage keys/event fields | Obfuscated privileges/logic bits, hidden admin flags |
| JWT, HMAC | Crypto Auth | Simulate auth headers, sigs | Weak secret, JWT/HMAC bypass, replay attacks |

## 2. Systematic Encoding/Decoding Forensics Checklist

1. Locate all encoded ABI fields: bytes, string, arrays, off-chain signatures ("meta", "route", etc.).
2. Phase-1 agent checks:
   - Decode all candidate fields using: Base64, Hex, URL, ASCII, UTF-8.
     * e.g., Input: `0x61646d696e` or `YWRtaW4=` → "admin"
   - Compare decoded results, flag hidden values like "admin", "upgrader", or hex zero padding.
   - Try multiple padding/length variants (raw, 32-byte padded, ascii/hex/base64, url-encoded).
   - For role/privilege, test forms: "admin" (raw), as hex, as base64, url: `%61%64%6d%69%6e`.
   - Fuzz empty/null/overlong and edge-encoded payloads for consent/role/logic bypass.
   - Store each attempt (input/encoding/decoded/result) in the forensic report for that contract/field.

## 3. Configuration & Test Vectors

See `scripts/lib/encoding.ts` for the `ENCODING_ANALYSIS_CONFIG` implementation, which serves as a plug-in starter for programmatic encoding analysis.
