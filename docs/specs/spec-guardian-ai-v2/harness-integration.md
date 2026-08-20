# Harness Integration — Guardian-AI v2

Companion to [SPEC.md](./SPEC.md). Details the per-tool proxy integration mechanisms referenced by CAP-1 and CAP-5.

## Proxy Architecture

Guardian-AI operates as a local MITM (Man-in-the-Middle) HTTPS proxy. On activation (`llm-firewall on`), it:

1. Generates a local CA certificate (if not already present) at `~/.guardian-ai/ca.pem`.
2. Trusts the CA in the OS trust store:
   - **macOS:** `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.guardian-ai/ca.pem`
   - **Linux:** Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
3. Starts the proxy on `localhost:<port>` (default: `13713`).
4. Auto-detects installed AI tools and patches their configuration.
5. On deactivation (`llm-firewall off`), reverses all config patches and optionally removes the CA cert.

## Per-Tool Integration

### Claude Code

**Preferred method:** `HTTP_PROXY` / `HTTPS_PROXY` environment variables.

Claude Code natively respects standard proxy environment variables. Guardian-AI patches the shell profile (`.zshrc`, `.bashrc`) or sets them in the active terminal session:

```bash
export HTTP_PROXY=http://localhost:13713
export HTTPS_PROXY=http://localhost:13713
```

**Fallback method (if proxy env vars are insufficient):** Override `ANTHROPIC_BASE_URL=http://localhost:13713`. This requires Guardian-AI to act as a full API-compatible endpoint, forwarding to `https://api.anthropic.com` after redaction. Note: when using base URL override, tool search and local MCP tools may require `ENABLE_TOOL_SEARCH=true`.

**User preference:** HTTP_PROXY is preferred to avoid modifying the API base URL.

### Cursor

**Method:** Programmatic `settings.json` patching.

Cursor is an Electron app that ignores terminal environment variables when launched from the desktop. Guardian-AI must patch the user's VS Code / Cursor settings file directly:

**Location:** `~/.config/Cursor/User/settings.json` (Linux) or `~/Library/Application Support/Cursor/User/settings.json` (macOS)

**Injected settings:**
```json
{
  "http.proxy": "http://localhost:13713",
  "http.proxySupport": "override",
  "http.proxyStrictSSL": true,
  "cursor.general.disableHttp2": true
}
```

**Notes:**
- `http.proxyStrictSSL` is set to `true` (not `false`) because Guardian-AI generates and trusts a local CA cert. This maintains full TLS verification.
- `cursor.general.disableHttp2` prevents Cursor from freezing if the proxy doesn't handle HTTP/2 perfectly. Can be revisited once HTTP/2 proxy support is validated.
- Guardian-AI backs up the original settings before patching and restores on `llm-firewall off`.

### GitHub Copilot (VS Code)

**Method:** Same `settings.json` patching as Cursor.

**Location:** `~/.config/Code/User/settings.json` (Linux) or `~/Library/Application Support/Code/User/settings.json` (macOS)

**Injected settings:**
```json
{
  "http.proxy": "http://localhost:13713",
  "http.proxySupport": "override",
  "http.proxyStrictSSL": true
}
```

Copilot reads standard VS Code proxy settings. The local CA cert ensures TLS verification passes without weakening security.

## Auto-Detection Logic

On `llm-firewall on`, Guardian-AI scans for installed tools:

| Tool | Detection Method |
|---|---|
| Claude Code | Check for `claude` binary in `$PATH` |
| Cursor | Check for Cursor settings directory or `cursor` binary |
| VS Code + Copilot | Check for VS Code settings directory and Copilot extension |

Only detected tools are patched. The activation output reports which tools were configured:

```
🛡️ Guardian-AI activated on localhost:13713
   ✓ Claude Code — HTTP_PROXY set
   ✓ Cursor — settings.json patched
   ✗ VS Code — not detected
   
   CA certificate trusted in system keychain.
   Run 'llm-firewall off' to deactivate.
```

## Deactivation (`llm-firewall off`)

1. Restore backed-up `settings.json` files for Cursor / VS Code.
2. Unset `HTTP_PROXY` / `HTTPS_PROXY` from shell profile (or current session).
3. Stop the proxy process.
4. Optionally remove the CA cert from the OS trust store (prompted, not automatic).
