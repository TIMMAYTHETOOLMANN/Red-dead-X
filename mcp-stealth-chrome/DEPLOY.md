# Deploying MCP Stealth Chrome to Hugging Face Spaces

This document explains how to push the `mcp-stealth-chrome/` folder to the
Hugging Face Space `timmaythetoolmann/MCP-Stealth-Chrome`.

---

## Method 1 — Web UI (simplest)

1. Go to https://huggingface.co/spaces and click **Create new Space**.
2. Set Space name: `MCP-Stealth-Chrome`, SDK: **Gradio**, visibility: Public.
3. In the Space's **Files** tab, click **Upload files**.
4. Upload all files from this `mcp-stealth-chrome/` folder, preserving the directory structure:
   - `app.py`
   - `requirements.txt`
   - `README.md` (with the valid HF frontmatter — **do not rename or move this**)
   - `engine/` (all `.py` files)
   - `data/bugrap-programs.json`
   - `data/samples/sample_idl.json`
   - `data/samples/sample_evm_abi.json`
   - `.env.example`
5. The Space will automatically install `gradio[mcp]` and start `app.py`.

---

## Method 2 — Git push

```bash
# 1. Add the HF Space as a remote (inside the Red-dead-X repo)
git remote add space https://huggingface.co/spaces/timmaythetoolmann/MCP-Stealth-Chrome

# 2. Push only the mcp-stealth-chrome/ subtree to the Space root
#    (the Space expects files at the repo root, not in a subdirectory)
git subtree push --prefix mcp-stealth-chrome space main

# Or, if you prefer a separate clone:
git clone https://huggingface.co/spaces/timmaythetoolmann/MCP-Stealth-Chrome hf-space
cp -r mcp-stealth-chrome/* hf-space/
cd hf-space
git add -A
git commit -m "deploy: MCP Stealth Chrome v1"
git push
```

**Note:** When using `git subtree push`, the Space will see the contents of
`mcp-stealth-chrome/` at the root — so `app.py` will be at `/app.py` on the
Space, which matches the `app_file: app.py` in the README frontmatter.

---

## Method 3 — huggingface_hub Python client

```python
from huggingface_hub import HfApi
api = HfApi()
api.upload_folder(
    folder_path="mcp-stealth-chrome",
    repo_id="timmaythetoolmann/MCP-Stealth-Chrome",
    repo_type="space",
)
```

---

## Verifying the MCP endpoint is live

After deployment (usually 1-2 minutes), verify:

```bash
# Should return a valid MCP SSE stream header
curl -I https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse

# Test with mcp-remote (requires Node.js)
npx mcp-remote https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse
```

The MCP SSE URL:
```
https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse
```

---

## Space configuration

The `README.md` frontmatter configures the Space:

```yaml
---
title: MCP Stealth Chrome
emoji: 🛰️
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: 5.9.1
app_file: app.py
pinned: false
---
```

**No Docker** — the `sdk: gradio` setting uses the native Python runtime.

---

## Secrets / environment variables

Set Space secrets in **Settings → Repository secrets** on the Space page:

- `GRADIO_MCP_SERVER=True` (usually not needed — set in app.py already)
- `BASELINE_PATH` — optional, path to your baseline JSON
- `FAIL_ON` — optional, severity gate
- `THIRDWEB_SECRET_KEY` — optional, only for live EVM recon

Never commit real secrets to the repository. See `.env.example` for the full list.
