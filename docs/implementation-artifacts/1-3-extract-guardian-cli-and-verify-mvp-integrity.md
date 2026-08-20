# Story 1.3: Extract Guardian-CLI and Verify MVP Integrity

Status: done
baseline_commit: be90d1ff1176847a7e6371ea80fcebc32b90d5fb

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want to create a `guardian-cli` crate serving as the main binary entrypoint that depends on both core and proxy crates,
so that the complete 3-crate workspace architecture is fully realized and MVP functionality is verified with zero regressions.

## Acceptance Criteria

1. **AC1: `guardian-cli` Crate Initialization**
   - `crates/guardian-cli/` exists as an independent binary/library crate with its own `Cargo.toml` (edition 2021, rust-version 1.85.0).
   - `Cargo.toml` declares `guardian-core = { path = "../guardian-core" }` and `guardian-proxy = { path = "../guardian-proxy" }`.
   - `Cargo.toml` contains necessary dependencies (`tokio`, `tracing`, `tracing-subscriber`, `reqwest`, `axum`, `serde`, `serde_json`).

2. **AC2: Migration of CLI & Main Entrypoint Logic**
   - Main entrypoint logic (`init_logging`, `parse_port`, `parse_upstream_url`, `run_server`) is cleanly located in `crates/guardian-cli/src/lib.rs` and `crates/guardian-cli/src/main.rs`.
   - Pure unit tests (`test_parse_port_*`, `test_parse_upstream_url_*`) are migrated to `crates/guardian-cli`.

3. **AC3: Workspace Alignment & Root Binary Forwarding**
   - Root `Cargo.toml` `[workspace] members` includes `"crates/guardian-core"`, `"crates/guardian-proxy"`, `"crates/guardian-cli"`, `"."`.
   - Workspace root package `llm-firewall-rs` forwards to `guardian_cli::run_server()`.
   - Profile optimization settings in root `Cargo.toml` are configured for `guardian-cli`.

4. **AC4: Verification of MVP Integrity & Zero Regression**
   - `cargo build --workspace` compiles cleanly across all workspace members.
   - `cargo test --workspace` passes 100% of tests across `guardian-core`, `guardian-proxy`, and `guardian-cli`.
   - `cargo clippy --workspace -- -D warnings` passes with 0 warnings.
   - The end-to-end proxy behavior and startup options (PORT, UPSTREAM_URL, MODEL_DIR, /health, /v1/chat/completions redaction) run identically to the v1 monolith.

## Tasks / Subtasks

- [x] Task 1: Initialize `crates/guardian-cli` Crate (AC: 1, 3)
  - [x] Create directory structure `crates/guardian-cli/src/`.
  - [x] Create `crates/guardian-cli/Cargo.toml` with:
    - `name = "guardian-cli"`
    - dependencies on `guardian-core`, `guardian-proxy`, `tokio`, `tracing`, `tracing-subscriber`, `reqwest`, `axum`, `serde`, `serde_json`
  - [x] Add `"crates/guardian-cli"` to root `Cargo.toml` `[workspace] members` and profile optimization blocks.
  - [x] Add `guardian-cli = { path = "crates/guardian-cli" }` to root `Cargo.toml` dependencies.

- [x] Task 2: Implement CLI Entrypoint in `guardian-cli` (AC: 2)
  - [x] Create `crates/guardian-cli/src/lib.rs` exporting helper functions (`init_logging`, `parse_port`, `parse_upstream_url`, `run_server`).
  - [x] Create `crates/guardian-cli/src/main.rs` invoking the CLI entrypoint.
  - [x] Migrate unit tests for `parse_port` and `parse_upstream_url` to `crates/guardian-cli`.
  - [x] Verify `cargo check -p guardian-cli` passes cleanly.

- [x] Task 3: Adapt Root Monolith / Wrapper Binary (AC: 3, 4)
  - [x] Update root `src/main.rs` to call `guardian_cli::run_server()`.
  - [x] Verify `cargo check --workspace` passes with 0 errors.

- [x] Task 4: Complete Workspace Test Suite & Regression Verification (AC: 4)
  - [x] Run `cargo test --workspace` and verify all tests in all crates pass.
  - [x] Run `cargo clippy --workspace -- -D warnings` and verify 0 warnings.
  - [x] Run `cargo build --workspace` to confirm release/debug artifacts build cleanly.

## Dev Notes

### Architecture & Boundaries
Per **AD-12 (Workspace and Binary Shape)**:
- Workspace shape:
  - `guardian-core` (pipeline, state, detection, ML)
  - `guardian-proxy` (axum server, MITM, handlers, AppState)
  - `guardian-cli` (entrypoint, CLI execution, config)
- Dependency direction:
  - `guardian-cli` -> `guardian-proxy` -> `guardian-core`
  - `guardian-cli` -> `guardian-core`

### Testing Commands
```bash
cargo check -p guardian-cli
cargo test -p guardian-cli
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Dev Agent Record

### Agent Model Used
Gemini 3.7 Flash

### Debug Log References
- `cargo check -p guardian-cli`: Passed with 0 errors.
- `cargo test -p guardian-cli`: 8/8 unit tests passed.
- `cargo check --workspace`: Passed cleanly in 0.39s.
- `cargo test --workspace`: 30/30 tests passed (16 in `guardian-core`, 6 in `guardian-proxy`, 8 in `guardian-cli`).
- `cargo clippy --workspace -- -D warnings`: 0 warnings.

### Completion Notes List
- Initialized `crates/guardian-cli` with `Cargo.toml`, `src/lib.rs`, and `src/main.rs`.
- Migrated logging setup, environment variable parsing (`PORT`, `UPSTREAM_URL`, `MODEL_DIR`), and `run_server()` function to `guardian-cli`.
- Migrated port and upstream URL parsing unit tests to `guardian-cli/src/lib.rs`.
- Configured root `src/main.rs` to delegate cleanly to `guardian_cli::run_server()`.
- Updated root `Cargo.toml` with `guardian-cli` in workspace members, dependencies, and profile optimization sections.
- Verified 100% test pass rate (30/30) and zero clippy warnings across the workspace.

### File List
- `Cargo.toml` (modified)
- `Cargo.lock` (modified)
- `crates/guardian-cli/Cargo.toml` (created)
- `crates/guardian-cli/src/lib.rs` (created)
- `crates/guardian-cli/src/main.rs` (created)
- `src/main.rs` (modified)
- `docs/implementation-artifacts/sprint-status.yaml` (modified)
- `docs/implementation-artifacts/1-3-extract-guardian-cli-and-verify-mvp-integrity.md` (modified)
