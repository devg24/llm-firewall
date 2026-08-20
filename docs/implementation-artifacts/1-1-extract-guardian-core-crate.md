# Story 1.1: Extract Guardian-Core Crate

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want to extract the detection engine, models, and state logic into an independent `guardian-core` crate,
so that the core firewall logic is fully decoupled from the web server and CLI.

## Acceptance Criteria

1. **AC1: Workspace Initialization and Structure**:
   - The root `Cargo.toml` is configured with a Cargo workspace `[workspace]` declaring `members = ["crates/guardian-core", "."]` (or configuring members to support the 3-crate layout `crates/*` and current root) with `resolver = "2"`.
   - The directory `crates/guardian-core/` is initialized as an independent library crate with its own `Cargo.toml` (targeting Rust edition 2021, MSRV 1.85.0) and `src/lib.rs`.
2. **AC2: Migration of Redaction and Detection Engine**:
   - All redaction functionality from `src/redact.rs` (deterministic regex definitions, static regex initializers `init_regexes`, regex accessors, `PiiType`, `PiiMatch`, text normalization `normalize_text`, match collection `collect_regex_matches`, overlap resolution `resolve_overlaps`, `RedactionState` co-reference tracking, `redact_text`, and JSON completion payload mutators `process_completions_payload`, `mutate_content_field`) is cleanly migrated to `crates/guardian-core/src/redact.rs`.
   - All types, functions, and regex accessors necessary for downstream consumers are given explicit `pub` visibility.
3. **AC3: Migration of Machine Learning & Inference Engine**:
   - The ML inference subsystem from `src/ml.rs` (`SharedModel`, `TokenClassification`, and `run_inference`) is cleanly migrated to `crates/guardian-core/src/ml.rs`.
   - The tight coupling to `crate::proxy::ProxyError` in the inference engine is eliminated by introducing an independent `CoreError` enum in `crates/guardian-core/src/error.rs` (implementing `std::error::Error` and `Display`), ensuring `guardian-core` has zero dependency on web/proxy crates.
4. **AC4: Public API Surface and Re-exports**:
   - `crates/guardian-core/src/lib.rs` exports the public API (`pub mod redact;`, `pub mod ml;`, `pub mod error;`), re-exporting primary types (`RedactionState`, `PiiType`, `PiiMatch`, `SharedModel`, `TokenClassification`, `CoreError`) for ergonomic consumption.
   - `crates/guardian-core` compiles cleanly with zero errors or warnings (`cargo check -p guardian-core`, `cargo build -p guardian-core`).
5. **AC5: Unit Test Preservation and Verification**:
   - All existing unit tests for the detection logic and ML inference (regex validation, normalization, overlap resolution, type-partitioned co-reference, payload mutation, and model loading) are migrated to `crates/guardian-core`.
   - Running `cargo test -p guardian-core` compiles and passes 100% of the unit tests.
6. **AC6: Root Binary Adaptation & Zero Regression**:
   - The root crate is updated to include `guardian-core = { path = "crates/guardian-core" }` in its dependencies, and root modules (`src/main.rs`, `src/proxy.rs`) are adapted to import from `guardian_core`.
   - The entire workspace builds cleanly (`cargo build --workspace`) and passes all existing unit and integration tests (`cargo test --workspace`), preserving complete MVP functionality.

## Tasks / Subtasks

- [x] Task 1: Initialize Workspace Configuration and Scaffold `guardian-core` Crate (AC: 1)
  - [x] Update root `Cargo.toml` to define `[workspace]` with `members = ["crates/guardian-core", "."]` (or virtual workspace structure) and `resolver = "2"`.
  - [x] Create directory structure `crates/guardian-core/src`.
  - [x] Create `crates/guardian-core/Cargo.toml` with package name `guardian-core`, version `0.1.0`, edition `2021`, rust-version `1.85.0`.
  - [x] Add required dependencies to `crates/guardian-core/Cargo.toml`:
    ```toml
    [dependencies]
    candle-core = "0.10.2"
    candle-nn = "0.10.2"
    candle-transformers = "0.10.2"
    regex = "1.12.4"
    tokenizers = "0.22.2"
    unicode-normalization = "0.1.25"
    serde = { version = "1.0", features = ["derive"] }
    serde_json = "1.0"
    tokio = { version = "1.52.3", features = ["sync", "time", "rt"] }
    tracing = "0.1"
    ```
- [x] Task 2: Implement Decoupled Core Error Types in `guardian-core` (AC: 3, 4)
  - [x] Create `crates/guardian-core/src/error.rs` defining `CoreError` with variants:
    - `ModelLoad(String)`
    - `Tokenization(String)`
    - `InferenceTimeout`
    - `TooManyRequests`
    - `TaskPanicked(String)`
    - `PayloadValidation(String)`
    - `Serialization(String)`
    - `Internal(String)`
  - [x] Implement `std::fmt::Display` and `std::error::Error` for `CoreError`.
  - [x] Implement `From<serde_json::Error>` and `From<std::io::Error>` for `CoreError` where convenient.
- [x] Task 3: Migrate Redaction Engine to `guardian-core` (AC: 2, 4)
  - [x] Create `crates/guardian-core/src/redact.rs` migrating all logic from `src/redact.rs`.
  - [x] Ensure all 10 regex static `OnceLock` initializers and accessors are exported: `init_regexes()`, `ssn_regex()`, `cc_regex()`, `email_regex()`, `phone_regex()`, `ip_regex()`, `ipv6_regex()`, `aws_regex()`, `gcp_regex()`, `github_regex()`, `bearer_regex()`.
  - [x] Export `PiiType` enum (`Ssn`, `Cc`, `Email`, `Phone`, `Ip`, `Aws`, `Gcp`, `Github`, `Bearer`) and `PiiMatch` struct.
  - [x] Export `normalize_text`, `collect_regex_matches`, `resolve_overlaps`, `RedactionState`, `redact_text`, `process_completions_payload`, `mutate_content_field`.
  - [x] Ensure `process_completions_payload` returns `Result<(), CoreError>` (or `Result<(), String>`).
- [x] Task 4: Migrate ML & Inference Engine to `guardian-core` (AC: 3, 4)
  - [x] Create `crates/guardian-core/src/ml.rs` migrating all logic from `src/ml.rs`.
  - [x] Migrate `SharedModel` struct and `SharedModel::load_from_dir(model_dir: &Path) -> Result<Self, CoreError>`.
  - [x] Migrate `TokenClassification` struct.
  - [x] Migrate `run_inference(model: Arc<SharedModel>, text: String) -> Result<Vec<TokenClassification>, CoreError>`.
  - [x] Replace any previous `ProxyError` return types with `CoreError`.
- [x] Task 5: Export Library API in `crates/guardian-core/src/lib.rs` (AC: 4)
  - [x] Declare modules: `pub mod error;`, `pub mod redact;`, `pub mod ml;`.
  - [x] Re-export key types at root of crate:
    ```rust
    pub use error::CoreError;
    pub use ml::{SharedModel, TokenClassification, run_inference};
    pub use redact::{
        collect_regex_matches, init_regexes, mutate_content_field, normalize_text,
        process_completions_payload, redact_text, resolve_overlaps, PiiMatch, PiiType,
        RedactionState,
    };
    ```
- [x] Task 6: Migrate and Validate Unit Tests in `guardian-core` (AC: 5)
  - [x] Migrate all unit tests from `src/redact.rs` (`test_ssn_regex`, `test_cc_regex`, `test_email_regex`, `test_phone_regex`, `test_ip_regex`, `test_ipv6_regex`, `test_text_normalization`, `test_zwnj_normalization`, `test_resolve_overlaps`, `test_resolve_overlaps_extended`, `test_co_reference_mapping_consistency`, `test_type_partitioned_co_reference`, `test_single_pass_redaction`, `test_process_payload_extended_scope_and_sequential`) into `crates/guardian-core/src/redact.rs`.
  - [x] Migrate all unit tests from `src/ml.rs` (`test_load_from_non_existent_dir`, `test_run_inference_with_model`) into `crates/guardian-core/src/ml.rs`.
  - [x] Run `cargo test -p guardian-core` and verify all tests pass.
- [x] Task 7: Update Monolithic Root to Consume `guardian-core` (AC: 6)
  - [x] Add `guardian-core = { path = "crates/guardian-core" }` to root `Cargo.toml`.
  - [x] Update `src/main.rs` to import `redact` and `ml` from `guardian_core` (or replace internal `mod redact; mod ml;` with `use guardian_core::{redact, ml};`).
  - [x] Update `src/proxy.rs` to import from `guardian_core::redact` and convert `guardian_core::error::CoreError` into `proxy::ProxyError` (e.g. `impl From<CoreError> for ProxyError`).
  - [x] Remove duplicate `src/redact.rs` and `src/ml.rs` or forward them to `guardian_core`.
  - [x] Run `cargo build --workspace` and `cargo test --workspace` to ensure zero regressions across the entire test suite.

## Dev Notes

### Architecture & Boundaries
- **AD-12 (Workspace and Binary Shape):** `guardian-core` is the foundational crate of the 3-crate architecture (`guardian-core` -> `guardian-proxy` -> `guardian-cli`).
- **Dependency Direction Invariant:** `guardian-core` must **NEVER** depend on `guardian-proxy`, `guardian-cli`, `axum`, or HTTP routing code. It is a pure, headless engine for detection, redaction, state management, and ML inference.
- **Fail-Closed Security (AD-5):** Any parsing, validation, or inference failure must return an explicit `Err(CoreError)` rather than failing open.

### Decoupling `ProxyError` -> `CoreError`
In the monolith, `src/ml.rs` depended on `crate::proxy::ProxyError`.
In `guardian-core`, all ML and redaction functions must return `CoreError`.
In `src/proxy.rs` (and later `guardian-proxy`), implement a `From<CoreError>` conversion:
```rust
impl From<guardian_core::CoreError> for ProxyError {
    fn from(err: guardian_core::CoreError) -> Self {
        match err {
            guardian_core::CoreError::TooManyRequests => ProxyError::TooManyRequests,
            guardian_core::CoreError::InferenceTimeout => ProxyError::Timeout("Inference timeout".to_string()),
            guardian_core::CoreError::PayloadValidation(msg) => ProxyError::BadRequest(msg),
            guardian_core::CoreError::ModelLoad(msg)
            | guardian_core::CoreError::Tokenization(msg)
            | guardian_core::CoreError::TaskPanicked(msg)
            | guardian_core::CoreError::Serialization(msg)
            | guardian_core::CoreError::Internal(msg) => ProxyError::Internal(msg),
        }
    }
}
```

### Exact Redaction & Tokenization Invariants to Preserve
1. **Regex Patterns & Names:**
   - SSN: `\b\d{3}-\d{2}-\d{4}\b`
   - CC: `\b(?:\d[ -]*?){13,19}\b`
   - Email: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
   - Phone: `\b(?:\+?\d{1,3}[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b`
   - IP: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`
   - IPv6: `(?i)\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b|(?:\b(?:[0-9a-fA-F]{1,4}:){1,6})?::(?:[0-9a-fA-F]{1,4}\b)?|::[0-9a-fA-F]{1,4}\b`
   - AWS: `(?i)\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`
   - GCP: `(?i)\bAIza[0-9A-Za-z-_]{35}\b`
   - GitHub: `(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b`
   - Bearer: `(?i)\bbearer\s+[A-Za-z0-9\-\._~\+\/]+=*\b`
2. **Text Normalization:**
   - NFC normalization via `unicode-normalization` crate.
   - Stripping zero-width spaces (`\u{200B}`), ZWNJ (`\u{200C}`), ZWJ (`\u{200D}`).
   - Stripping control characters EXCEPT `\n`, `\r`, `\t`.
3. **Token Formatting & Co-reference:**
   - Format: `[REDACTED_{PII_TYPE}_{COUNTER}]`, e.g., `[REDACTED_SSN_1]`, `[REDACTED_EMAIL_1]`.
   - Keys are lowercase strings partitioned by `(String, PiiType)` in `HashMap<(String, PiiType), String>`.
   - Sequential 1-based indexing per `PiiType`.
4. **ML Inference Sliding Window:**
   - `max_content_len = 510`, `stride = 256`, `[CLS]` (101) prepended, `[SEP]` (102) appended.
   - Character boundary snapping: `text.is_char_boundary(s)` and `text.is_char_boundary(e)` to prevent UTF-8 panic on non-ASCII multi-byte tokens.
   - Concurrency bounding: Semaphore with 1 permit and 15-second acquisition timeout.

### Testing Standards & Commands
- `cargo check -p guardian-core`
- `cargo test -p guardian-core`
- `cargo test --workspace` (or running with `NO_PROXY=*` or unsetting proxy env vars if running in sandboxed container environments)

### Project Structure Notes

```text
llm-firewall-rs/
├── Cargo.toml                      # Workspace root defining members
├── crates/
│   └── guardian-core/              # NEW: Core detection, ML & redaction library
│       ├── Cargo.toml              # Package definition for guardian-core
│       └── src/
│           ├── lib.rs              # Library root and re-exports
│           ├── error.rs            # CoreError definitions
│           ├── redact.rs           # Regexes, normalization, RedactionState, token mapping
│           └── ml.rs               # BERT model loader, inference worker, tokenizer
├── src/
│   ├── main.rs                     # Root binary entrypoint (uses guardian_core)
│   └── proxy.rs                    # Axum proxy handlers (uses guardian_core)
```

### References

- `docs/planning-artifacts/epics.md#Story 1.1: Extract Guardian-Core Crate`
- `docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md#AD-12`
- `docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md#AD-14`
- `docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md#Structural-Seed`

## Dev Agent Record

### Agent Model Used

Gemini 3.5 Flash (Medium)

### Debug Log References
- `cargo check -p guardian-core`: Checked cleanly with 0 errors.
- `cargo test -p guardian-core`: 16/16 tests passed.
- `cargo check --workspace`: 0 errors across all workspace members.
- `cargo build --workspace`: Successfully compiled all crates.
- `cargo test --workspace`: 30/30 tests passed (16 in `guardian-core`, 14 in `llm-firewall-rs`).
- `cargo clippy --workspace`: Clean pass with 0 warnings.

### Completion Notes List
- Successfully created Cargo workspace in root `Cargo.toml` with `members = [".", "crates/guardian-core"]` and `resolver = "2"`.
- Extracted `crates/guardian-core` as a headless, decoupled library crate containing `lib.rs`, `error.rs`, `redact.rs`, `ml.rs`.
- Created decoupled `CoreError` enum in `crates/guardian-core/src/error.rs` implementing `Display` and `std::error::Error`.
- Implemented `From<guardian_core::CoreError> for ProxyError` in `src/proxy.rs` and adapted root binary (`src/main.rs`, `src/proxy.rs`) to consume `guardian_core`.
- Removed legacy monolithic files `src/redact.rs` and `src/ml.rs`.
- Validated all 30 tests pass with zero regressions.

### File List
- `Cargo.toml` (modified)
- `Cargo.lock` (modified)
- `crates/guardian-core/Cargo.toml` (created)
- `crates/guardian-core/src/lib.rs` (created)
- `crates/guardian-core/src/error.rs` (created)
- `crates/guardian-core/src/redact.rs` (created)
- `crates/guardian-core/src/ml.rs` (created)
- `src/main.rs` (modified)
- `src/proxy.rs` (modified)
- `src/redact.rs` (deleted)
- `src/ml.rs` (deleted)
- `docs/implementation-artifacts/sprint-status.yaml` (modified)
- `docs/implementation-artifacts/1-1-extract-guardian-core-crate.md` (modified)
