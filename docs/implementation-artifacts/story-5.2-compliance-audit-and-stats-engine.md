---
story_id: "5.2"
story_key: "5-2-compliance-audit-and-stats-engine"
epic: 5
status: done
---

# Story 5.2: Compliance Audit and Stats Engine

## Story

**As a developer,**
I want the firewall proxy to persistently record detection and redaction telemetry to an append-only JSONL audit log and provide terminal stats summaries and compliance audit reports,
**So that** I can objectively demonstrate and verify to my team, organization, or compliance officers that sensitive credentials and PII were safeguarded without leaking to upstream LLM providers, while tracking cumulative cost and risk savings.

---

## Acceptance Criteria

- **AC1 (Pure-Rust Append-Only Telemetry Event Persistence):** Given outbound and inbound traffic intercepted by the firewall proxy:
  - Telemetry events are structured as a strongly typed, Serde-compatible `TelemetryEvent` struct containing:
    - `timestamp: u64` (Unix epoch timestamp in seconds).
    - `request_id: String` (unique identifier per intercepted HTTP request).
    - `event_type: TelemetryEventType` (`PiiIntercepted`, `SinkBlocked`, `SandboxBlocked`, `Passthrough`).
    - `tier_triggered: Option<DetectionTier>` (`Tier1Regex`, `Tier2Entropy`, `Tier3Ner`, `Tier4Model`, `DangerousSink`, `SandboxJail`, `CustomRule`).
    - `secret_types: Vec<PiiType>` (e.g. `Aws`, `Gcp`, `Github`, `Bearer`, `HighEntropy`, `Ssn`, `Cc`, `Email`, `Phone`, `Ip`, `Person`, `Custom`).
    - `redacted_count: usize` (total number of placeholder substitutions in the request).
    - `sandbox_violation: Option<String>` (violation details if sandbox boundary was triggered).
    - `model: Option<String>` (upstream LLM model name extracted from request payload, e.g. `gpt-4o`, `claude-3-5-sonnet`).
    - `latency_ms: u64` (end-to-end security pipeline processing duration).
    - `estimated_cost_saved_usd: f64` (calculated risk avoidance / cost saved value).
  - Telemetry events are serialized to JSON and persisted using an append-only `.jsonl` file (`audit.jsonl`).
  - The default audit file location is `~/.guardian/audit.jsonl` (with fallback to `.guardian/audit.jsonl` in the current workspace, configurable via `GUARDIAN_AUDIT_LOG` environment variable or `.guardian.toml`).
  - Directory and file creation is automatic: creates parent directories (`~/.guardian`) with secure permissions (`0o600` / read-write user-only on Unix).
  - Maintains a 100% pure Rust dependency tree without SQLite, C-bindings, or external dynamic libraries.

- **AC2 (Thread-Safe Non-Blocking Async Telemetry Pipeline):** Given the Axum HTTP proxy hot path handling concurrent completions requests:
  - Interception handlers (`chat_completions_handler` and `proxy_handler`) MUST NOT execute synchronous blocking filesystem I/O on Tokio async worker threads.
  - Telemetry recording is decoupled via an asynchronous channel (`tokio::sync::mpsc::UnboundedSender<TelemetryEvent>` or bounded `mpsc::channel(10_000)` with non-blocking `try_send`) stored in `AppState.telemetry_tx`.
  - A background Tokio task (`tokio::spawn`) continuously drains events from the channel receiver and flushes them to the append-only JSONL file asynchronously using `tokio::io::AsyncWriteExt` or batched asynchronous disk appends.
  - On proxy graceful shutdown (`shutdown_signal`), the channel is closed and the background worker flushes all remaining buffered in-flight events before exiting.

- **AC3 (Proxy Hot-Path Instrumentation):** Given incoming requests processed by `crates/guardian-proxy`:
  - `chat_completions_handler` generates and dispatches `TelemetryEvent` records for:
    1. **Secret Redactions**: When PII/secret matches are identified and substituted with tokens, recording secret categories, match counts, tiers triggered, and processing latency.
    2. **Dangerous Sink Blocks**: When an inbound response or payload triggers `DangerousSinkDetector` (e.g. `curl`, `eval`, `subprocess`), recording the blocked sink pattern and request ID.
    3. **Sandbox Violations**: When an out-of-boundary path is detected by `SandboxPolicy`, recording the target path, canonical root, and violation type.
    4. **Clean Passthrough Requests**: When requests contain zero sensitive matches, recording the passthrough event with latency and model metadata.
  - All sensitive secret values are strictly excluded from telemetry events (only category labels and match counts are stored; raw secret strings are NEVER written to the audit log).

- **AC4 (Cumulative Terminal Stats Engine `llm-firewall stats`):** Given a history of recorded JSONL telemetry events:
  - Running `llm-firewall stats` reads the JSONL audit log using a streaming line reader resilient to corrupted or partial lines (skipping malformed lines with `tracing::warn!`).
  - It computes aggregate statistics:
    - Total requests intercepted and monitored.
    - Total secrets redacted breakdown by category (`AWS`, `GCP`, `GitHub`, `Bearer Token`, `Private Key`, `SSN`, `Credit Card`, `High Entropy`, `Email`, `Phone`, `IP`, `Custom`).
    - Total dangerous sink execution attempts blocked.
    - Total sandbox boundary violations prevented.
    - Breakdown of detections by tier (`Tier 1 Regex`, `Tier 2 Entropy`, `Tier 3 NER`, `Dangerous Sink`, `Sandbox Jail`).
    - Cumulative estimated cost and risk savings calculated via an industry benchmark security model ($500/credential, $1,000/cloud key, $150/PII record).
  - CLI Options supported:
    - `--since <DURATION>`: Filter time window (e.g. `24h`, `7d`, `30d`, `all`; default `all`).
    - `--file <PATH>`: Custom path to JSONL audit log.
    - `--json`: Output raw aggregated JSON summary for scripting and automated pipelines.
  - Terminal Output:
    - Renders an ANSI-formatted, styled terminal dashboard featuring high-level KPI cards and a formatted table of detections by category.

- **AC5 (Compliance Audit Report Generator `llm-firewall report`):** Given recorded telemetry events:
  - Running `llm-firewall report [OPTIONS]` generates a shareable, structured compliance audit document in Markdown (default) or JSON format.
  - **Markdown Report Contents**:
    1. **Header & Metadata**: Document title, generation timestamp, audit scope/period, firewall version, audit log SHA-256 integrity hash.
    2. **Executive Summary**: High-level attestation that all outbound LLM traffic was intercepted, total tokens protected, zero unredacted secret leaks.
    3. **Compliance Framework Alignment**: Mappings to standard security controls:
       - SOC 2 Type II: CC6.1 (Logical Access Controls), CC6.6 (Boundary Protection), CC6.7 (Data Transmission Protection).
       - HIPAA Security Rule: § 164.312(a)(1) Access Control & § 164.312(e)(1) Transmission Security (ePHI Redaction).
       - GDPR: Article 32 (Security of Processing - Pseudonymization of Personal Data).
       - PCI-DSS v4.0: Requirement 3 (Protect Stored Account Data) & Requirement 4 (Protect Cardholder Data in Transit).
    4. **Interception & Redaction Breakdown Table**: Categorized summary of protected data elements with counts and detection tiers.
    5. **Security Incidents Log**: Chronological listing of blocked dangerous sinks and sandbox traversal attempts with timestamps and request IDs.
    6. **Daily Activity Timeline**: Aggregated daily/session activity histogram.
  - CLI Options supported:
    - `-o, --output <FILE>`: Output destination file path (default: stdout or `guardian-audit-report.md`).
    - `--format <FORMAT>`: Output format (`markdown` or `json`, default: `markdown`).
    - `--since <DURATION>`: Filter time window (`24h`, `7d`, `30d`, `all`).
    - `--detailed`: Include individual anonymized event entries in the report appendix.
    - `--file <PATH>`: Custom JSONL audit file path.

- **AC6 (CLI Wiring & Main Entrypoint Integration):** Given `crates/guardian-cli`:
  - `main.rs` dispatches `stats` and `report` subcommands with robust argument parsing.
  - `run_server_internal` and `run_server_with_trust` instantiate the `TelemetryRecorder` background task, register the graceful shutdown flush hook, and pass `telemetry_tx` into `AppState`.
  - Comprehensive `--help` documentation for `llm-firewall stats` and `llm-firewall report`.

- **AC7 (Resolution of Open Epic 4 Retro Action Items):** Given the open action items from Epic 4 Retrospective:
  - Resolves Action Item 2: *"Design thread-safe, non-blocking telemetry event recorder in guardian-core / guardian-proxy using pure-Rust JSONL streaming"*.
  - Resolves Action Item 3: *"Wire user-facing terminal commands (preflight, stats, report) and pre-flight bulk approval flow into guardian-cli"*.

- **AC8 (Comprehensive Test Suite & Zero Clippy Warnings):** Given unit, integration, and performance tests:
  - Unit tests in `guardian-core` verify: `TelemetryEvent` serialization/deserialization, append-only JSONL writing, directory creation, corrupted line resilience, stats aggregation, time filtering, and Markdown/JSON report formatting.
  - Unit tests in `guardian-cli` verify: CLI argument parsing for `stats` and `report`, table rendering, and JSON output mode.
  - Integration tests in `guardian-proxy` verify: end-to-end telemetry event recording during live completions requests (PII redactions, sink blocks, sandbox violations), non-blocking channel throughput under concurrency.
  - All workspace tests pass (`cargo test --workspace`) and `cargo clippy --workspace -- -D warnings` returns 0 warnings with 100% `cargo fmt` adherence.

---

## Tasks / Subtasks

- [ ] **Task 1: Telemetry Data Model, Serialization & JSONL Engine in `crates/guardian-core/src/telemetry.rs`** (AC: #1, #7)
  - [ ] 1a. Create `crates/guardian-core/src/telemetry.rs` and export module in `crates/guardian-core/src/lib.rs`.
  - [ ] 1b. Define `TelemetryEvent`, `TelemetryEventType`, `DetectionTier`, `AuditStats`, `CategoryStats`, `TierStats`, and `CostModel` structs/enums with Serde derive.
  - [ ] 1c. Implement default audit log path resolution (`default_audit_log_path() -> PathBuf`) checking `GUARDIAN_AUDIT_LOG` env var, `~/.guardian/audit.jsonl`, and local `.guardian/audit.jsonl`.
  - [ ] 1d. Implement secure directory initialization ensuring parent directories exist with user-only permissions (`0o700`/`0o600` on Unix).
  - [ ] 1e. Implement `append_telemetry_event(path: &Path, event: &TelemetryEvent) -> Result<(), CoreError>` using pure-Rust append-only file operations.
  - [ ] 1f. Implement streaming JSONL reader `load_telemetry_events(path: &Path, since: Option<std::time::Duration>) -> Result<Vec<TelemetryEvent>, CoreError>` with fail-safe corrupted line skipping and `tracing::warn!` diagnostics.
  - [ ] 1g. Implement `compute_stats(events: &[TelemetryEvent], cost_model: Option<&CostModel>) -> AuditStats` aggregating counts by category, tier, sink blocks, sandbox violations, and calculating estimated cost saved.

- [ ] **Task 2: Compliance Report Generator in `crates/guardian-core/src/report.rs`** (AC: #5)
  - [ ] 2a. Create `crates/guardian-core/src/report.rs` and export module in `crates/guardian-core/src/lib.rs`.
  - [ ] 2b. Implement `generate_markdown_report(stats: &AuditStats, events: &[TelemetryEvent], detailed: bool) -> String`:
    - Generate metadata header with SHA-256 audit digest.
    - Generate Executive Summary and Compliance Attestation Matrix (SOC 2, HIPAA, GDPR, PCI-DSS).
    - Generate Interception & Redaction Summary Table.
    - Generate Incidents Log (Sink blocks & Sandbox violations).
    - Generate Daily Activity Timeline table.
  - [ ] 2c. Implement `generate_json_report(stats: &AuditStats, events: &[TelemetryEvent], detailed: bool) -> Result<String, CoreError>`.

- [ ] **Task 3: Non-Blocking Telemetry Channel & Proxy Instrumentation in `crates/guardian-proxy`** (AC: #2, #3)
  - [ ] 3a. Update `AppState` in `crates/guardian-proxy/src/lib.rs` to include `pub telemetry_tx: Option<tokio::sync::mpsc::UnboundedSender<guardian_core::telemetry::TelemetryEvent>>`.
  - [ ] 3b. Implement background recorder worker `spawn_telemetry_writer(rx: tokio::sync::mpsc::UnboundedReceiver<TelemetryEvent>, log_path: PathBuf) -> tokio::task::JoinHandle<()>` that batches/writes events asynchronously to disk.
  - [ ] 3c. Update `chat_completions_handler` in `crates/guardian-proxy/src/proxy.rs`:
    - Emit `TelemetryEvent` on PII redaction (collecting secret types, match count, tiers, latency).
    - Emit `TelemetryEvent` on `DangerousSink` detection and block.
    - Emit `TelemetryEvent` on `SandboxPolicy` violation and block.
    - Emit `TelemetryEvent` on clean completions passthrough.
  - [ ] 3d. Update `proxy_handler` in `crates/guardian-proxy/src/proxy.rs` to emit passthrough telemetry events.

- [ ] **Task 4: CLI Subcommands `stats` and `report` in `crates/guardian-cli`** (AC: #4, #5, #6, #7)
  - [ ] 4a. Create `crates/guardian-cli/src/stats.rs` with `StatsCliArgs` parser (`--since`, `--file`, `--json`) and `run_stats(args: StatsCliArgs) -> Result<(), Box<dyn std::error::Error>>`.
  - [ ] 4b. Implement formatted ANSI terminal table rendering (`print_stats_table`) with summary cards and colored tables.
  - [ ] 4c. Create `crates/guardian-cli/src/report.rs` with `ReportCliArgs` parser (`--output`, `--format`, `--since`, `--detailed`, `--file`) and `run_report(args: ReportCliArgs) -> Result<(), Box<dyn std::error::Error>>`.
  - [ ] 4d. Wire `stats` and `report` subcommands into `crates/guardian-cli/src/main.rs` and `crates/guardian-cli/src/lib.rs`.
  - [ ] 4e. Update `run_server_internal` and `run_server_with_trust` to initialize the telemetry channel, spawn the background writer task, pass `telemetry_tx` into `AppState`, and handle graceful shutdown flushing.

- [ ] **Task 5: Comprehensive Unit, Integration, and Performance Test Suite** (AC: #8)
  - [ ] 5a. Unit tests in `crates/guardian-core/src/telemetry.rs`:
    - `TelemetryEvent` JSON serialization and round-trip parsing.
    - Append writing to temporary JSONL file.
    - Corrupted line resilience (mix of valid JSON, truncated JSON, empty lines).
    - `compute_stats` aggregation logic (counts by category, tier, cost savings, date filtering).
  - [ ] 5b. Unit tests in `crates/guardian-core/src/report.rs`:
    - Markdown report generation structure, table rendering, compliance section verification.
    - JSON report generation and schema validation.
  - [ ] 5c. Unit tests in `crates/guardian-cli/src/stats.rs` & `report.rs`:
    - CLI argument parsing for `stats` and `report` flags (`--since=24h`, `--json`, `--output`, `--detailed`).
    - Formatted terminal table output.
  - [ ] 5d. Integration tests in `crates/guardian-proxy/tests/integration_tests.rs`:
    - Start proxy server with telemetry enabled pointing to a temporary JSONL log.
    - Send request with AWS key and verify `TelemetryEvent` is recorded in JSONL.
    - Send request triggering dangerous sink / sandbox violation and verify corresponding events.
    - Verify non-blocking behavior under concurrent request load.
  - [ ] 5e. Workspace verification: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo fmt --check`.

---

## Dev Notes

### Architecture & Technical Invariants

#### 1. Telemetry Event Data Model (`crates/guardian-core/src/telemetry.rs`)

The telemetry event represents an immutable audit record of a firewall action. It is designed to be lightweight, Serde-serializable, and privacy-preserving (storing metadata, categories, and counts, but never raw secrets):

```rust
// crates/guardian-core/src/telemetry.rs

use crate::redact::PiiType;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventType {
    PiiIntercepted,
    SinkBlocked,
    SandboxBlocked,
    Passthrough,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    Tier1Regex,
    Tier2Entropy,
    Tier3Ner,
    Tier4Model,
    DangerousSink,
    SandboxJail,
    CustomRule,
}

impl DetectionTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionTier::Tier1Regex => "Tier 1 (Regex)",
            DetectionTier::Tier2Entropy => "Tier 2 (Shannon Entropy)",
            DetectionTier::Tier3Ner => "Tier 3 (BERT NER)",
            DetectionTier::Tier4Model => "Tier 4 (ML Inference)",
            DetectionTier::DangerousSink => "Dangerous Sink",
            DetectionTier::SandboxJail => "Sandbox Jail",
            DetectionTier::CustomRule => "Custom Rule",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryEvent {
    pub timestamp: u64,
    pub request_id: String,
    pub event_type: TelemetryEventType,
    pub tier_triggered: Option<DetectionTier>,
    #[serde(default)]
    pub secret_types: Vec<PiiType>,
    pub redacted_count: usize,
    pub sandbox_violation: Option<String>,
    pub model: Option<String>,
    pub latency_ms: u64,
    pub estimated_cost_saved_usd: f64,
}
```

#### 2. Pure-Rust JSONL Append-Only Architecture & Path Resolution

To maintain a 100% pure Rust dependency tree without SQLite or C-bindings:
- Audit records are stored in newline-delimited JSON format (`.jsonl`).
- Path Resolution Strategy:
  1. `GUARDIAN_AUDIT_LOG` environment variable (highest precedence).
  2. `.guardian.toml` configured `audit_log` path (if present).
  3. User home directory: `~/.guardian/audit.jsonl` (standard default).
  4. Local project fallback: `.guardian/audit.jsonl` (if home directory is unavailable).
- Atomic directory creation:
  ```rust
  pub fn ensure_audit_dir(path: &Path) -> std::io::Result<()> {
      if let Some(parent) = path.parent() {
          if !parent.exists() {
              std::fs::create_dir_all(parent)?;
              #[cfg(unix)]
              {
                  use std::os::unix::fs::PermissionsExt;
                  let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
              }
          }
      }
      Ok(())
  }
  ```

#### 3. Async Non-Blocking Telemetry Pipeline (AD-12, AD-13, Project Context Rule)

Axum request handlers must never block on disk writes. Telemetry events are dispatched over a `tokio::sync::mpsc` channel to a dedicated background task:

```rust
// Background writer task in guardian-proxy
pub fn spawn_telemetry_writer(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<TelemetryEvent>,
    log_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = guardian_core::telemetry::ensure_audit_dir(&log_path) {
            tracing::error!(error = %e, "Failed to create audit log directory");
            return;
        }

        let mut file_opt = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await;

        let mut file = match file_opt {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, path = ?log_path, "Failed to open audit log file");
                return;
            }
        };

        use tokio::io::AsyncWriteExt;
        while let Some(event) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&event) {
                let mut data = line.into_bytes();
                data.push(b'\n');
                if let Err(e) = file.write_all(&data).await {
                    tracing::error!(error = %e, "Failed to append telemetry event to disk");
                }
            }
        }
        let _ = file.flush().await;
        tracing::debug!("Telemetry writer task completed cleanly");
    })
}
```

#### 4. Cost and Risk Avoidance Metric Model

The stats and report engine calculates estimated cost saved based on standard industry breach / credential leak remediation benchmarks:

| Detected Category | Estimated Remediation Cost / Risk Avoided | Rationale |
| :--- | :--- | :--- |
| **AWS / GCP / Cloud Keys** | **$1,000.00** | Cloud compromise, resource hijacking (crypto mining), key rotation overhead |
| **GitHub / API Bearer Tokens** | **$500.00** | Source code leak, CI/CD pipeline hijack, secret revocation workflow |
| **Private Keys (SSH / TLS)** | **$1,000.00** | Infrastructure compromise, certificate reissuance |
| **SSN / Credit Card (PCI/PII)** | **$150.00** | Per-record notification cost, identity monitoring, regulatory fines |
| **Email / Phone / Person PII** | **$50.00** | GDPR/CCPA compliance liability, privacy violation risk |
| **Dangerous Sink Blocked** | **$2,500.00** | Remote code execution (RCE), data exfiltration attempt prevention |
| **Sandbox Jail Violation** | **$1,500.00** | Out-of-bounds local filesystem traversal / shadow file access prevention |

A default `CostModel` struct provides these multipliers with support for customization.

#### 5. CLI Commands Specification (`crates/guardian-cli`)

##### `llm-firewall stats`
```bash
llm-firewall stats [OPTIONS]

OPTIONS:
    -s, --since <DURATION>    Time window (e.g. "24h", "7d", "30d", "all") [default: all]
    -f, --file <PATH>         Custom path to JSONL audit log file
        --json                Output summary as JSON
    -h, --help                Print help information
```

Example Terminal Output:
```
================================================================================
                    LLM FIREWALL — CUMULATIVE DETECTION STATS                   
================================================================================
  Requests Intercepted: 1,420           Total Secrets Redacted: 342
  Dangerous Sinks Blocked: 8            Sandbox Violations Blocked: 3
  Estimated Risk Prevented: $248,500.00
--------------------------------------------------------------------------------
 CATEGORY             COUNT    DETECTION TIER           EST. RISK SAVED
--------------------------------------------------------------------------------
 AWS Credentials         42    Tier 1 (Regex)           $42,000.00
 GitHub Tokens           68    Tier 1 (Regex)           $34,000.00
 Bearer Tokens          112    Tier 1 (Regex)           $56,000.00
 High-Entropy Keys       54    Tier 2 (Shannon Entropy) $54,000.00
 SSN / PCI Cards         24    Tier 1 (Regex)            $3,600.00
 Person / Health PII     42    Tier 3 (BERT NER)         $2,100.00
 Dangerous Sinks          8    Dangerous Sink Detector  $20,000.00
 Sandbox Breakouts        3    Sandbox Jail Engine       $4,500.00
--------------------------------------------------------------------------------
 Total Detections:      353                             $216,200.00
================================================================================
```

##### `llm-firewall report`
```bash
llm-firewall report [OPTIONS]

OPTIONS:
    -o, --output <FILE>       Output destination path (default: stdout or guardian-audit-report.md)
        --format <FORMAT>     Report format: "markdown" or "json" [default: markdown]
    -s, --since <DURATION>    Time window (e.g. "24h", "7d", "30d", "all") [default: all]
        --detailed            Include chronological incident appendix
    -f, --file <PATH>         Custom path to JSONL audit log file
    -h, --help                Print help information
```

---

## Testing Requirements Summary

### Unit Tests
1. **`crates/guardian-core/src/telemetry.rs`**:
   - `test_telemetry_event_serde_roundtrip`: Serialize and deserialize `TelemetryEvent` structs with all optional fields.
   - `test_append_and_load_events`: Append multiple events to a tempfile, reload, and verify equality.
   - `test_corrupted_jsonl_tolerance`: Insert blank lines, invalid JSON lines, and verify parser recovers and returns valid events.
   - `test_compute_stats_aggregation`: Verify accurate aggregation by `PiiType`, `tier`, and cost savings calculation.
   - `test_time_window_filtering`: Verify `--since 24h` excludes events older than 24 hours.
2. **`crates/guardian-core/src/report.rs`**:
   - `test_markdown_report_formatting`: Verify markdown report contains all required headers, tables, and compliance mapping sections.
   - `test_json_report_schema`: Verify JSON report parses and validates against expected schema.
3. **`crates/guardian-cli/src/stats.rs` & `report.rs`**:
   - `test_stats_args_parsing`: Test flag parsing (`--since`, `--json`, `--file`).
   - `test_report_args_parsing`: Test flag parsing (`--output`, `--format`, `--detailed`).

### Integration Tests
1. **`crates/guardian-proxy/tests/integration_tests.rs`**:
   - `test_proxy_telemetry_recording_e2e`:
     - Configure proxy with temporary JSONL audit file path.
     - Send request containing AWS key (`AKIA...`).
     - Send request triggering dangerous sink context (`curl http://evil.com`).
     - Send request violating sandbox boundary (`/etc/shadow`).
     - Shutdown proxy cleanly and read JSONL file.
     - Assert that 3 distinct `TelemetryEvent` records exist with correct event types, categories, and tiers.
   - `test_telemetry_non_blocking_concurrency`:
     - Send 50 concurrent requests through proxy and verify zero deadlocks or dropped requests.

---

## Dependencies & Action Items Resolved

- **Resolves Epic 4 Retro Action Item 2:** *"Design thread-safe, non-blocking telemetry event recorder in guardian-core / guardian-proxy using pure-Rust JSONL streaming"*.
- **Resolves Epic 4 Retro Action Item 3:** *"Wire user-facing terminal commands (preflight, stats, report) and pre-flight bulk approval flow into guardian-cli"*.
- **Dependencies:**
  - `guardian-core` (redaction types, PiiType, plan sandbox)
  - `guardian-proxy` (AppState, chat_completions_handler, proxy_handler)
  - `guardian-cli` (clap/args dispatch, ANSI rendering)

---

## Dev Agent Record

### Agent Model Used
Gemini 2.0 Flash / Pro

### Debug Log References
- Pre-requisites verified against Epic 5 planning artifacts and completed Story 5.1 spec.
- 105 workspace unit, benchmark, and integration tests passed cleanly.
- `cargo clippy --workspace -- -D warnings` and `cargo fmt --check` completed with zero errors and zero warnings.

### Completion Notes List
- Implemented pure-Rust, append-only JSONL telemetry recorder (`guardian-core::telemetry`) with resilient corrupted line recovery, customizable `CostModel`, and standard duration filtering (`24h`, `7d`, `30d`, `all`).
- Implemented compliance audit report generator (`guardian-core::report`) supporting both structured Markdown and JSON outputs with complete mapping to SOC 2 CC6.1/CC6.6, HIPAA §164.312(a)(2)(iv)/(b), GDPR Art 25/32, and PCI-DSS v4.0 Req 3.3/3.4/10.2, cryptographic SHA-256 integrity hash verification, and attestation.
- Instrumented `guardian-proxy` with thread-safe, non-blocking `mpsc` channel telemetry (`AppState.telemetry_tx`) for requests, PII redaction, sandbox boundary violations, and dangerous sink blocks, ensuring zero raw secret leakage and zero async worker thread blocking.
- Implemented `guardian stats` and `guardian report` subcommands in `guardian-cli` with ANSI terminal output and export options.
- Added comprehensive end-to-end integration test (`test_telemetry_event_logging_through_proxy`) in `guardian-proxy`.

### File List
- `crates/guardian-core/src/telemetry.rs` (NEW)
- `crates/guardian-core/src/report.rs` (NEW)
- `crates/guardian-core/src/token_map.rs` (UPDATE)
- `crates/guardian-core/src/lib.rs` (UPDATE)
- `crates/guardian-core/Cargo.toml` (UPDATE)
- `crates/guardian-proxy/src/lib.rs` (UPDATE)
- `crates/guardian-proxy/src/proxy.rs` (UPDATE)
- `crates/guardian-proxy/tests/integration_tests.rs` (UPDATE)
- `crates/guardian-proxy/tests/sse_passthrough.rs` (UPDATE)
- `crates/guardian-cli/src/stats.rs` (NEW)
- `crates/guardian-cli/src/report.rs` (NEW)
- `crates/guardian-cli/src/main.rs` (UPDATE)
- `crates/guardian-cli/src/lib.rs` (UPDATE)
- `docs/implementation-artifacts/sprint-status.yaml` (UPDATE)
- `docs/implementation-artifacts/story-5.2-compliance-audit-and-stats-engine.md` (UPDATE)
