---
title: MCP Stealth Chrome
emoji: 🛰️
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: 5.29.0
app_file: app.py
pinned: false
---

# 🛰️ MCP Stealth Chrome

Offline blockchain forensics as an **MCP server + Gradio app**, hosted on Hugging Face Spaces.

Re-packages the offline forensic tooling from [Red-dead-X / soex-premiumcvt-audit](https://github.com/TIMMAYTHETOOLMANN/Red-dead-X) as a **Gradio app that is also an MCP server**, requiring only a URL for MCP clients to connect.

**No Docker. No mainnet sends. No required secrets.**

---

## ✨ What it does

- **Chat tab** — conversational forensic assistant; routes intents to tool functions below. No LLM key required (deterministic command router); if `OPENAI_API_KEY` / `HF_TOKEN` is present it MAY enhance responses.
- **Tools tab** — each forensic capability as a normal Gradio UI (paste your own IDL/ABI).
- **MCP server** — every tool function is a typed, documented MCP tool reachable over SSE.

### Forensic capabilities (all offline)

| Tool | Description |
|------|-------------|
| `analyze_idl_tool` | Solana Anchor IDL static analysis — 10 hunting lanes, stable fingerprints, SARIF output |
| `simulate_invariants_tool` | Economic invariant simulator — exact u64 integer math (overflow, fee rounding, referral chain) |
| `map_attack_surface_tool` | Attack-surface / coverage mapper — BugRap registry, (program × chain × bounty class) matrix |
| `forensic_scan_tool` | Unified offline Solana-IDL + EVM-ABI forensic report (combined SARIF + Markdown) |
| `analyze_evm_abi_tool` | Offline EVM ABI hunting lanes (9 lanes: access control, upgradeability, arbitrary call, etc.) |
| `list_programs_tool` | List in-scope BugRap programs from the bundled registry |
| `scope_check_tool` | Scope-compliance gate — is a (program, chain, vuln class) target in scope? |

---

## 🔌 MCP Connection

### SSE endpoint (URL-only, for clients that support SSE)

```
https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse
```

### Claude Desktop / stdio-only clients

Use `mcp-remote` as a bridge:

```bash
npx mcp-remote https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse
```

Add to `~/.config/claude-desktop/config.json`:

```json
{
  "mcpServers": {
    "mcp-stealth-chrome": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse"
      ]
    }
  }
}
```

### Other MCP clients (Cursor, VS Code Copilot, etc.)

Set the server URL to:
```
https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse
```

---

## 💬 Chat usage

Open the **Chat** tab and try:

```
help
list programs
attack surface program:soex-premiumcvt
invariant simulate
analyze idl
analyze evm
forensic scan
scope check soex-premiumcvt
```

For real analysis, paste your own Anchor IDL or EVM ABI JSON in the **Tools** tab.

---

## 🛡️ Guardrails

- `READ_ONLY=true` — no blockchain writes
- `ALLOW_TX=false` — no transaction broadcasting
- All analysis is **offline** (no live RPC calls required)
- No mainnet sends, ever
- Keys git-ignored (see `.env.example`)
- The PoC harness from the TS source is **not** ported to this Space

---

## ⚙️ Environment variables

See `.env.example` for the full list. All optional:

| Variable | Default | Description |
|----------|---------|-------------|
| `READ_ONLY` | `true` | Enforce read-only mode |
| `ALLOW_TX` | `false` | Allow transaction broadcasting (never set true) |
| `GRADIO_MCP_SERVER` | `true` | Enable the MCP server |
| `BASELINE_PATH` | `""` | Path to a baseline JSON for finding suppression |
| `FAIL_ON` | `""` | Severity gate for CI (critical/high/medium/low/info) |
| `THIRDWEB_SECRET_KEY` | `""` | Optional — for live EVM recon (not used in this Space) |

---

## 🗂️ Source

- TypeScript source: `soex-premiumcvt-audit/` in [TIMMAYTHETOOLMANN/Red-dead-X](https://github.com/TIMMAYTHETOOLMANN/Red-dead-X)
- Python port: `mcp-stealth-chrome/engine/` (faithful port of the deterministic/offline analyzers)
