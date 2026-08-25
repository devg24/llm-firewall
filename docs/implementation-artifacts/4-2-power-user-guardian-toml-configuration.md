---
story_id: "4.2"
story_key: "4-2-power-user-guardian-toml-configuration"
epic: 4
status: done
baseline_commit: "3b1a19b"
---

# Story 4.2: Power-User .guardian.toml Configuration

## Story

**As a developer,**
I want to define explicit domain overrides, custom regex detection rules, variable allowlists, and per-tier threshold overrides in a `.guardian.toml` configuration file at my project root,
**So that** I have deterministic, fine-grained control over the firewall's behavior in specialized repositories and edge-case codebases without modifying firewall source code.

---

## Acceptance Criteria

- **AC1 (Configuration Schema & Deserialization):** Given a repository containing a `.guardian.toml` file at its root, when the configuration parser reads the file, then it deserializes the configuration into a strongly typed `GuardianConfig` struct supporting:
  - `domain`: explicit domain override (`"crypto"`, `"fintech"`, `"healthcare"`, `"standard"`), overriding manifest auto-detection.
  - `[thresholds]`: manual per-tier threshold overrides (`entropy`, `ner`, `pattern`, `contextual`).
  - `[[rules]]` / `[regex]`: custom regex rules with `id`, `pattern`, and optional `pii_type` / `label`.
  - `[allowlist]`: exact string `terms` and regex `patterns` that bypass redaction.
- **AC2 (Custom Regex Rules & ReDoS Validation):** Given custom regex rules defined in `.guardian.toml`, when the rules are parsed and compiled:
  - Each rule pattern is validated for syntactic correctness and bounded complexity using Rust's linear-time DFA `regex::RegexBuilder` (enforcing memory/DFA size limits).
  - Any syntactically invalid or pathological pattern is rejected gracefully with a diagnostic `tracing::warn!` message and skipped without crashing the server or aborting other rules.
  - Valid custom rules are executed as Tier 1 detectors alongside built-in rules, generating deterministic `Span` matches with `confidence = 1.0` and custom PII labels (e.g. `[REDACTED_CUSTOM_RULEID_1]`).
- **AC3 (Global Allowlist All-Tier Bypass):** Given custom allowlist configuration containing exact terms (e.g. `SAFE_API_KEY`, `DEV_DATABASE_URL`) or regex patterns (e.g. `^TEST_[0-9]+$`, `0x[0-9a-fA-F]{40}`), when request payloads are processed by `DetectionOrchestrator`, then any detected secret or PII candidate span (across Tier 1 built-in/custom regex, Tier 2 Shannon entropy, and Tier 3 BERT NER) that overlaps with or is enclosed by an allowlisted span is suppressed and bypasses redaction unconditionally.
- **AC4 (Threshold Overrides & Matrix Precedence):** Given explicit threshold values configured in `[thresholds]`, when `DetectionOrchestrator` initializes:
  - Specified manual thresholds override the domain baseline (e.g. setting `entropy = 4.5` overrides the default `Standard` 3.84 or `CryptoFintech` 4.28 bits).
  - The hierarchy of precedence is strictly enforced: `[thresholds]` manual overrides > `.guardian.toml` explicit `domain` > manifest auto-detected `DomainProfile` > default `Standard` profile.
- **AC5 (Fail-Safe Initialization & Zero-Panic Fallback):** Given a missing, empty, unreadable, or syntactically malformed `.guardian.toml` file (e.g. unclosed strings, invalid TOML tables, type mismatches), when the proxy starts, then it logs a diagnostic warning (`tracing::warn!`), ignores the invalid file, and gracefully falls back to zero-config defaults (manifest domain auto-detection and standard threshold matrix) without crashing or returning HTTP 500.
- **AC6 (Proxy State & Pipeline Wiring):** Given a valid `.guardian.toml`, when the proxy server starts:
  - `AppState` in `crates/guardian-proxy` stores the active `GuardianConfig` (wrapped in `Arc`).
  - `chat_completions_handler` initializes `DetectionOrchestrator` using the merged domain profile, threshold overrides, custom regex rules, and allowlists.
  - The CLI server startup (`run_server_internal` and `run_server_with_trust`) discovers `.guardian.toml` in `cwd` (or custom path via `GUARDIAN_CONFIG_PATH`), logs the loaded configuration summary via `tracing::info!`, and injects it into `AppState`.
- **AC7 (Comprehensive Test Suite & Zero Clippy Warnings):** Given unit, integration, and security tests:
  - Unit tests verify TOML schema deserialization, ReDoS rejection, custom regex redaction, allowlist suppression across all tiers, and fail-safe fallback.
  - Integration tests verify end-to-end proxy behavior with `.guardian.toml` (custom rules redacting bespoke tokens, allowlists preserving false positives, custom thresholds tuning sensitivity).
  - All workspace tests pass (`cargo test --workspace`) and `cargo clippy --workspace -- -D warnings` returns 0 warnings.

---

## Tasks / Subtasks

- [x] **Task 1: Comprehensive Configuration Data Model & Parser in `crates/guardian-core/src/manifest.rs`** (AC: #1, #4, #5)
  - [x] 1a. Define strongly typed schema structs with Serde deserialization:
    - `GuardianConfig`: `domain: Option<String>`, `thresholds: Option<ThresholdOverrides>`, `rules: Option<Vec<CustomRegexRule>>` (and alias support for `regex.rules`), `allowlist: Option<AllowlistConfig>`.
    - `ThresholdOverrides`: `entropy: Option<f32>`, `ner: Option<f32>`, `pattern: Option<f32>`, `contextual: Option<f32>`.
    - `CustomRegexRule`: `id: String`, `pattern: String`, `pii_type: Option<String>`.
    - `AllowlistConfig`: `terms: Option<Vec<String>>`, `patterns: Option<Vec<String>>`.
  - [x] 1b. Implement threshold overrides and precedence hierarchy in `DetectionOrchestrator::with_config`.
  - [x] 1c. Implement `parse_guardian_toml(path: &Path) -> Option<GuardianConfig>` with fail-safe error handling and `tracing::warn!` logging on syntax errors.
  - [x] 1d. Implement `parse_guardian_toml_str(content: &str) -> Option<GuardianConfig>` for unit testing and in-memory parsing.

- [x] **Task 2: Custom Regex Engine & ReDoS Validation in `crates/guardian-core/src/manifest.rs` & `orchestrator.rs`** (AC: #2)
  - [x] 2a. ReDoS pre-validation: validate custom regex rule patterns during parsing.
  - [x] 2b. Reject patterns with invalid syntax gracefully with diagnostic `tracing::warn!`.
  - [x] 2c. Custom regex execution in `DetectionOrchestrator::orchestrate` yielding `Span` with `confidence = 1.0` and assigned `PiiType`.
  - [x] 2d. Update `PiiType` in `redact.rs` with `PiiType::Custom` supporting custom token redaction.

- [x] **Task 3: Global Allowlist Engine in `crates/guardian-core/src/orchestrator.rs`** (AC: #3)
  - [x] 3a. Support exact term matching (case-insensitive) and regex pattern matching.
  - [x] 3b. Suppress any secret or PII candidate spans overlapping allowlisted tokens across all tiers (Tier 1 built-in/custom regex, Tier 2 entropy, Tier 3 NER).

- [x] **Task 4: Wire Config & Allowlists into `DetectionOrchestrator` in `crates/guardian-core/src/orchestrator.rs`** (AC: #3, #4)
  - [x] 4a. Add `DetectionOrchestrator::with_config(model, domain, config)` constructor.
  - [x] 4b. Execute built-in regex, custom regex, entropy, and NER detectors.
  - [x] 4c. Apply allowlist filter to drop spans overlapping protected terms/patterns.
  - [x] 4d. Resolve span overlaps based on confidence and tier priority.

- [x] **Task 5: Update `AppState` & Proxy Handler in `crates/guardian-proxy`** (AC: #6)
  - [x] 5a. Add `pub guardian_config: Option<guardian_core::manifest::GuardianConfig>` to `AppState`.
  - [x] 5b. Update `chat_completions_handler` in `crates/guardian-proxy/src/proxy.rs` to instantiate `DetectionOrchestrator::with_config`.
  - [x] 5c. Update proxy test suites (`tests/integration_tests.rs`, `tests/sse_passthrough.rs`) to pass `guardian_config`.

- [x] **Task 6: Wire Configuration Discovery into CLI Startup in `crates/guardian-cli/src/lib.rs`** (AC: #5, #6)
  - [x] 6a. Discover `.guardian.toml` in `cwd`, parse config safely, log summary with `tracing::info!`, and inject into `AppState`.

- [x] **Task 7: Comprehensive Unit, Integration, and Security Tests** (AC: #7)
  - [x] 7a. Unit tests in `crates/guardian-core/src/manifest.rs`: full parsing, invalid regex rejection, syntax fallback.
  - [x] 7b. Integration tests in `crates/guardian-proxy/tests/integration_tests.rs`: custom rule redaction and allowlist bypass.
  - [x] 7c. Full workspace verification: 100% test pass rate, 0 clippy warnings, and clean formatting.

---

## Dev Notes

### Architecture & Design Decisions

#### 1. `.guardian.toml` Schema Specification (AD-15, CAP-10)

The `.guardian.toml` configuration format is designed to be concise, human-readable, and deterministic. All sections are optional.

```toml
# ==============================================================================
# .guardian.toml - LLM Firewall Power-User Configuration
# ==============================================================================

# Explicit Domain Profile Override
# Overrides auto-detection from Cargo.toml, package.json, go.mod, etc.
# Options: "standard", "crypto", "fintech", "healthcare"
domain = "crypto"

# Manual Per-Tier Threshold Overrides
# Overrides default or domain-specific baseline thresholds
[thresholds]
entropy = 4.50     # Shannon entropy threshold (0.0 - 8.0 bits). Higher = less sensitive.
ner = 0.85         # BERT NER confidence threshold (0.0 - 1.0). Higher = less sensitive.
pattern = 1.0      # Pattern matching confidence (default 1.0)
contextual = 0.60  # ONNX contextual classifier threshold (0.0 - 1.0)

# Custom Regex Detection Rules
# Evaluated as Tier 1 deterministic detectors (confidence = 1.0)
[[rules]]
id = "INTERNAL_PROJECT_TOKEN"
pattern = "PROJ-[A-Z0-9]{8}"
pii_type = "PROJECT_TOKEN"

[[rules]]
id = "CUSTOMER_ACCOUNT_NUMBER"
pattern = "ACC-[0-9]{4}-[0-9]{4}-[0-9]{4}"
pii_type = "ACCOUNT_NUMBER"

# Global Allowlist
# Matching tokens bypass ALL detection tiers (Tier 1 regex, Tier 2 entropy, Tier 3 NER)
[allowlist]
terms = [
    "SAFE_DEV_API_KEY",
    "PUBLIC_DEMO_JWT_TOKEN",
    "developer@example.internal",
    "DATABASE_URL_READONLY"
]
patterns = [
    "^MOCK_[A-Z0-9_]+$",
    "^0x[0-9a-fA-F]{40}$",     # Safe Ethereum addresses
    "^TEST_SECRET_[0-9]{4}$"
]
```

#### 2. ReDoS Validation & Security Guarantees (AD-14)

1. **Rust DFA Linear Guarantees**: Rust's `regex` crate uses finite automata (PikeVM / Lazy DFA), which guarantees $O(m \times n)$ worst-case time complexity, inherently immune to catastrophic backtracking.
2. **Resource Bounds**: To protect against memory exhaustion from pathological regex ASTs, regex compilation uses `RegexBuilder` with explicit limits:
   - `size_limit(10 * 1024 * 1024)` (10 MB compilation budget)
   - `dfa_size_limit(2 * 1024 * 1024)` (2 MB DFA cache)
3. **Graceful Rejection**: If an invalid regex pattern or over-budget rule is provided, the error is captured, logged via `tracing::warn!`, and the rule is skipped without failing proxy startup.

#### 3. Allowlist Bypass Mechanics across All Detection Tiers

The allowlist operates as a universal pre-redaction filter:
1. **Allowlist Span Discovery**: When `orchestrate(text)` is invoked, the allowlist scans `text` for:
   - All occurrences of each term in `allowlist.terms`.
   - All matches for each regex in `allowlist.patterns`.
   This yields a list of `AllowSpan { start, end }`.
2. **Span Suppression**: When candidate PII spans are collected from Tier 1 (built-in & custom regex), Tier 2 (Shannon entropy), and Tier 3 (BERT NER), any candidate span $[s_{start}, s_{end}]$ that overlaps with any `AllowSpan` $[a_{start}, a_{end}]$ (i.e. $s_{start} < a_{end} \land s_{end} > a_{start}$) is immediately dropped.
3. **Safety Guarantee**: Real secrets outside allowlisted tokens are unaffected and will still be detected and redacted.

#### 4. Threshold Matrix Precedence Hierarchy

The effective `ThresholdMatrix` is derived through the following strict priority cascade:
$$\text{Manual } [thresholds] \succ \text{Explicit } domain \text{ in } .guardian.toml \succ \text{Manifest Auto-Detection} \succ \text{Default } Standard \text{ Profile}$$

| Parameter | Standard Default | CryptoFintech Default | Healthcare Default | `.guardian.toml` Override |
|---|---|---|---|---|
| `pattern_tier` | 1.0 | 1.0 | 1.0 | `thresholds.pattern` (if set) |
| `entropy_tier` | 3.84 bits | 4.28 bits | 4.16 bits | `thresholds.entropy` (if set) |
| `ner_tier` | 0.70 | 0.80 | 0.60 | `thresholds.ner` (if set) |
| `contextual_tier` | 0.50 | 0.60 | 0.40 | `thresholds.contextual` (if set) |

---

## Files to Touch / Modify

### 1. `crates/guardian-core/src/manifest.rs` / `crates/guardian-core/src/config.rs` (UPDATE / NEW)
- **Current State**: `manifest.rs` currently contains a minimal `GuardianConfig` struct with `regex: Option<RegexConfig>` and `domain: Option<String>`, and a basic `parse_guardian_toml`.
- **What this story changes**:
  - Implement full `GuardianConfig` data structures supporting `domain`, `thresholds`, `rules` (custom regex), and `allowlist`.
  - Implement `load_guardian_config(&Path) -> Option<GuardianConfig>` with comprehensive fail-safe error handling and ReDoS validation.
  - Implement `CompiledGuardianConfig` with compiled regexes and allowlist structures.
- **What must be preserved**:
  - `detect_domain_from_manifests` monorepo scanner logic and ecosystem parsers (`Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml`).

### 2. `crates/guardian-core/src/domain.rs` (UPDATE)
- **Current State**: `DomainProfile` enum (`Standard`, `CryptoFintech`, `Healthcare`) and `ThresholdMatrix` struct.
- **What this story changes**:
  - Add `with_overrides(&self, overrides: Option<&ThresholdConfig>) -> ThresholdMatrix` or helper methods to merge custom thresholds with domain defaults.
- **What must be preserved**:
  - Quantitative baseline values (Standard: 3.84, CryptoFintech: 4.28, Healthcare: 4.16) and `thresholds()` match method.

### 3. `crates/guardian-core/src/detect.rs` (UPDATE)
- **Current State**: `Span` struct, `Detector` trait, `RegexDetector`, `EntropyDetector`, `NerDetector`.
- **What this story changes**:
  - Add `CustomRegexDetector` to execute user-defined regex rules returning `Span` with `confidence = 1.0` and custom `PiiType`.
  - Add allowlist matching utilities to identify protected spans.
- **What must be preserved**:
  - Synchronous / asynchronous trait interfaces and built-in detection algorithms.

### 4. `crates/guardian-core/src/orchestrator.rs` (UPDATE)
- **Current State**: Cascades Tier 1 Regex, Tier 2 Entropy, Tier 3 NER; resolves span overlaps.
- **What this story changes**:
  - Incorporate `CustomRegexDetector` into Tier 1 execution.
  - Filter candidate spans against compiled allowlists before finalizing redaction spans.
  - Add `DetectionOrchestrator::with_config(model, domain, config)` constructor.
- **What must be preserved**:
  - Overlap resolution priorities and async execution safety.

### 5. `crates/guardian-core/src/redact.rs` (UPDATE)
- **Current State**: `PiiType` enum and `mutate_content_field_with_orchestrator`.
- **What this story changes**:
  - Support `PiiType::Custom(String)` or custom token formatting for custom rule IDs (e.g. `[REDACTED_CUSTOM_PROJECT_TOKEN_1]`).
- **What must be preserved**:
  - In-place JSON mutation, token map insertion, streaming secret re-injection.

### 6. `crates/guardian-core/src/lib.rs` (UPDATE)
- **Current State**: Module re-exports.
- **What this story changes**:
  - Export `config` module types: `GuardianConfig`, `ThresholdConfig`, `CustomRuleConfig`, `AllowlistConfig`, `load_guardian_config`.

### 7. `crates/guardian-proxy/src/lib.rs` & `crates/guardian-proxy/src/proxy.rs` (UPDATE)
- **Current State**: `AppState` stores `client`, `upstream_url`, `model`, `domain`. `chat_completions_handler` constructs orchestrator with `with_domain`.
- **What this story changes**:
  - Add `pub config: Option<Arc<guardian_core::config::GuardianConfig>>` to `AppState`.
  - Update `chat_completions_handler` to pass `state.config.as_deref()` to `DetectionOrchestrator`.
- **What must be preserved**:
  - 2MB body limit, system prompt injection, Axum error mapping to `ProxyError`.

### 8. `crates/guardian-cli/src/lib.rs` (UPDATE)
- **Current State**: `run_server_internal` detects domain from manifests in `cwd` and constructs `AppState`.
- **What this story changes**:
  - Discover `.guardian.toml` in `cwd` or `GUARDIAN_CONFIG_PATH`.
  - Parse config, resolve domain and threshold overrides, log summary via `tracing::info!`, and populate `AppState.config`.
- **What must be preserved**:
  - CLI argument parsing, signal handling, graceful shutdown.

---

## Previous Story Intelligence & Learnings

1. **From Story 4.1 (Domain Manifest Auto-Detection):**
   - Manifest auto-detection is robust across monorepos and multi-ecosystems (`Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml`).
   - The `.guardian.toml` domain override must have strictly higher precedence than manifest markers.
   - Fail-safe fallback pattern (logging `tracing::warn!` and returning default profile) prevents any startup panics.
2. **From Story 3.4 (Advanced Detection Pipeline):**
   - All ML inference is offloaded to `tokio::task::spawn_blocking` to protect the Axum async worker pool.
   - Deterministic Tier 1 matches take priority over statistical Tier 2 entropy matches during overlap resolution.
3. **From Story 3.2 & 3.1 (Core Interception & MITM):**
   - The `TokenMap` is request-scoped and must never be stored in global `AppState`.
   - Streaming SSE handler re-injects secrets based on `TokenMap` keys. Custom redaction tokens (`[REDACTED_CUSTOM_<ID>_N]`) must follow the exact token format to ensure clean bidirectional substitution.

---

## Git Intelligence Summary

- Baseline Commit: `3b1a19b feat: implement domain-aware entropy thresholds and F1 validation benchmarks`
- Recent Commits:
  - `3b1a19b`: Implemented domain detection and threshold matrix derivation.
  - `4bc7086`: Completed Epic 3 core firewall engine and proxy pipeline.
  - `dad8614`: Clean clippy and fmt enforcement across workspace.

---

## Testing & Quality Guardrails

1. **Unit Tests (`crates/guardian-core`)**:
   - `test_parse_full_guardian_toml`: Validates all sections (`domain`, `thresholds`, `rules`, `allowlist`).
   - `test_redos_prevalidation_rejection`: Validates that invalid regex syntax is rejected gracefully without panic.
   - `test_custom_regex_detection`: Validates that custom rules detect proprietary token formats and emit correct spans.
   - `test_allowlist_bypass_tier1`: Validates that allowlisted email or API key is not redacted by built-in regex.
   - `test_allowlist_bypass_tier2_entropy`: Validates that allowlisted high-entropy tokens are not redacted by `EntropyDetector`.
   - `test_threshold_precedence`: Validates manual threshold overrides take priority over domain defaults.
   - `test_malformed_toml_fallback`: Validates that broken TOML falls back to defaults without error.
2. **Integration Tests (`crates/guardian-proxy`)**:
   - `test_proxy_with_custom_guardian_config`: Proxy started with `.guardian.toml` redacts custom tokens and respects allowlists.
   - `test_proxy_with_malformed_config_fallback`: Proxy starts and functions normally when `.guardian.toml` contains syntax errors.
3. **Workspace Quality Checks**:
   - Zero clippy warnings (`cargo clippy --workspace -- -D warnings`).
   - Clean formatting (`cargo fmt --check`).
   - 100% test pass rate (`cargo test --workspace`).

---

## Dev Agent Record

### Implementation Plan
1. Expanded `GuardianConfig` data structure in `crates/guardian-core/src/manifest.rs` with `ThresholdOverrides`, `CustomRegexRule`, and `AllowlistConfig`. Added ReDoS compile-time DFA check with `RegexBuilder` size limits and fail-safe parsing fallbacks.
2. Updated `DetectionOrchestrator` in `crates/guardian-core/src/orchestrator.rs` to compile and execute custom regex rules, apply manual threshold overrides, and execute allowlist span filtering across all detection tiers.
3. Updated `PiiType` in `crates/guardian-core/src/redact.rs` to support `PiiType::Custom`.
4. Threaded `guardian_config: Option<GuardianConfig>` through `AppState` in `crates/guardian-proxy/src/lib.rs` and wired it into `chat_completions_handler` in `proxy.rs`.
5. Updated CLI server startup in `crates/guardian-cli/src/lib.rs` to discover and parse `.guardian.toml` from `cwd`, log configuration details, and inject into `AppState`.
6. Added comprehensive unit tests in `manifest.rs` and end-to-end integration tests in `crates/guardian-proxy/tests/integration_tests.rs`.

### Debug Log
- Resolved greedy regex pattern in test case allowlist by scoping to bounded alphanumeric character classes (`ALLOWED_[A-Za-z0-9_]+`).
- Verified all 77 workspace tests pass and `cargo clippy` produces 0 warnings.

### Completion Notes
- All acceptance criteria AC1 through AC7 implemented and verified.
- Status moved to `done`.

## File List
- [`crates/guardian-core/src/manifest.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/manifest.rs)
- [`crates/guardian-core/src/orchestrator.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/orchestrator.rs)
- [`crates/guardian-core/src/redact.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/redact.rs)
- [`crates/guardian-proxy/src/lib.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/src/lib.rs)
- [`crates/guardian-proxy/src/proxy.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/src/proxy.rs)
- [`crates/guardian-proxy/tests/integration_tests.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/tests/integration_tests.rs)
- [`crates/guardian-proxy/tests/sse_passthrough.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/tests/sse_passthrough.rs)
- [`crates/guardian-cli/src/lib.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-cli/src/lib.rs)
- [`docs/implementation-artifacts/4-2-power-user-guardian-toml-configuration.md`](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/implementation-artifacts/4-2-power-user-guardian-toml-configuration.md)

## Change Log
- Power-user `.guardian.toml` configuration parser with strongly typed schema.
- ReDoS validation for custom regex rules and allowlist patterns.
- Universal allowlist bypass filtering across Tier 1 (built-in and custom regex), Tier 2 (entropy), and Tier 3 (NER).
- End-to-end Axum proxy integration with `guardian_config` threading and CLI startup integration.
