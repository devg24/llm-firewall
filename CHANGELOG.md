# Changelog

All notable changes to the `llm-firewall` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] - 2026-08-29

### Added
- **Single-Port TCP Multiplexer**: Integrated a zero-overhead TCP-peeking listener (`guardian-proxy::connect::accept_loop`) capable of transparently multiplexing HTTP/HTTPS `CONNECT` forward tunnels and standard HTTP reverse proxy traffic simultaneously on port 3000.
- **Deep Cursor IDE Interception**: Added specialized endpoint adapter for Cursor (`RunSSE` and `BidiAppend` streams) that intercepts protobuf/hex payloads and returns gRPC-compliant error responses (`grpc-status: 7` / `permission_denied`) to prevent client retries and surface clean firewall block alerts in the IDE.
- **Modular IDE Adapter Architecture**: Extracted IDE-specific protocol parsers into `guardian_proxy::ide_adapters` for streamlined extensibility.
- **Elevated CA Trust Automation**: Enhanced `guardian on` with macOS Keychain integration via `sudo security add-trusted-cert` and automated graceful untrusting on shutdown (`Ctrl+C`).

### Changed
- **Background Log Streamlining**: Silenced noisy tracing and debug polling logs to maintain clean terminal output and prevent log bloat.
- **Git Ignore Security**: Added automatic ignoring of local generated root CA certificates (`~/.llm-firewall-certs`) and transient artifacts.

---

## [0.4.0] - 2026-08-27

### Added
- **Unattended Pre-Flight Security Plans (`llm-firewall preflight`)**: Added pre-execution workspace scanning and approval workflow (`.guardian-plan.json`) allowing autonomous agents (Devin, SWE-bench, Cursor Background Agent) to run safely without manual prompts.
- **Strict Sandbox Path Jailing**: Enforced physical path canonicalization with symlink breakout protection, returning `403 Forbidden` on out-of-boundary access attempts (`~/.ssh`, `/etc/passwd`).
- **Pure-Rust Non-Blocking Telemetry (`~/.guardian/audit.jsonl`)**: Implemented an asynchronous append-only event ledger with restricted `0o600` permissions and zero global lock contention on the proxy hot path.
- **Aggregate KPI & Financial Savings Engine (`llm-firewall stats`)**: Added interactive CLI command to calculate intercepted threats and estimated breach cost avoided across time windows (`--since 24h`, `--since 7d`, `--json`).
- **Multi-Framework Compliance Auditing (`llm-firewall report`)**: Added exportable compliance audit reports with SHA-256 integrity verification mapped directly to SOC 2 Type II, HIPAA, GDPR Article 32, and PCI-DSS v4.0.

---

## [0.3.0] - 2026-08-25

### Added
- **Automatic Domain Profile Detection**: Automatic detection of project domains (`Standard`, `Crypto`, `Healthcare`, `Fintech`) from manifest files (`Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`, `requirements.txt`).
- **Power-User Repository Configuration (`.guardian.toml`)**: Added repository-level rule overrides, custom ReDoS-validated regular expressions, threshold adjustments, and variable allowlists.
- **Domain-Aware Shannon Entropy Tuning**: Dynamically adjusted entropy detection tiers based on domain characteristics to eliminate false positives in cryptography and blockchain projects while maximizing recall in standard repositories.

---

## [0.2.0] - 2026-08-20

### Added
- **4-Tier Multi-Modal Detection Cascade**:
  - *Tier 1*: High-throughput deterministic regex (AWS keys, GitHub tokens, Stripe secrets, private RSA keys, IPv4/IPv6, SSNs, credit cards).
  - *Tier 2*: Contextual Shannon entropy detection for high-entropy tokens and hex strings.
  - *Tier 3*: Local BERT Named Entity Recognition (NER) inference powered by Candle on CPU.
  - *Tier 4*: Ambiguity classification.
- **Request-Scoped Pseudonymization**: Ephemeral `TokenMap` replacement engine with zero cross-request memory retention.
- **Bidirectional Streaming SSE Mutator**: Real-time token substitution on outbound payloads and reverse restoration on inbound Server-Sent Events streams.
- **Context-Aware Dangerous Sink Blocking**: Rolling 512-byte lookbehind detection blocking prompt injection exfiltration vectors (`curl`, `eval`, `exec`).

---

## [0.1.0] - 2026-08-19

### Added
- **Multi-Crate Workspace Architecture**:
  - `guardian-core`: Pure security, tokenization, entropy, and ML detection engine.
  - `guardian-proxy`: High-throughput async Axum / Tokio proxy layer.
  - `guardian-cli`: Developer command-line interface.
- **Local Certificate Authority (`rcgen`)**: Dynamic generation and installation of local root CA certificates for transparent TLS inspection.
- **AI Harness Config Auto-Patcher**: Automated detection and configuration patching for Cursor, VS Code Copilot, and Claude Code.
- **Workspace Exposure Scanner (`llm-firewall scan`)**: Silent first-run scanner identifying uncommitted secrets, API keys, and PII across codebases.
