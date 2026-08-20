# Story 1.2: Extract Guardian-Proxy Crate

Status: done
baseline_commit: be90d1ff1176847a7e6371ea80fcebc32b90d5fb

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want to extract the Axum web server and HTTP routing into a `guardian-proxy` crate that depends on `guardian-core`,
so that the MITM proxy layer is separated from the underlying detection algorithms.

## Acceptance Criteria

1. **AC1: guardian-proxy Crate Initialization**
   - `crates/guardian-proxy/` exists as an independent library crate with its own `Cargo.toml` (edition 2021, rust-version 1.85.0).
   - `Cargo.toml` declares `guardian-core = { path = "../guardian-core" }` plus all Axum/HTTP dependencies.
   - `crates/guardian-proxy/src/lib.rs` is the library root that re-exports all public handler and state types needed by the CLI binary.

2. **AC2: Migration of Proxy Logic**
   - All proxy logic from `src/proxy.rs` is cleanly migrated to `crates/guardian-proxy/src/proxy.rs`.
   - Migrated code includes: `SyncStream`, `merge_queries`, `proxy_handler`, `chat_completions_handler`, `HOP_BY_HOP_HEADERS`, `is_hop_by_hop`, `extract_hop_headers`, `extract_res_hop_headers`, `copy_request_headers`, `copy_response_headers`, `ProxyError` and its `IntoResponse`/`From<CoreError>` impls.
   - `guardian-proxy` imports from `guardian_core` (not inline definitions).

3. **AC3: AppState Migration**
   - `AppState` struct (containing `client: reqwest::Client`, `upstream_url: reqwest::Url`, `model: Option<Arc<SharedModel>>`) is defined in `guardian-proxy` and re-exported from its `lib.rs`.
   - The root binary (`src/main.rs`) imports `AppState` and route handler functions from `guardian_proxy`.
   - `src/main.rs` no longer defines `AppState` or imports `mod proxy`.

4. **AC4: Root Binary Adaptation**
   - `src/main.rs` is simplified to import from `guardian_proxy`.
   - `src/proxy.rs` is deleted; `mod proxy;` is removed from `src/main.rs`.
   - `src/main.rs` retains `parse_port`, `parse_upstream_url`, `main()`, and pure unit tests.
   - Root `Cargo.toml` adds `guardian-proxy = { path = "crates/guardian-proxy" }` to dependencies.
   - Workspace `[workspace] members` includes `"crates/guardian-proxy"`.

5. **AC5: Integration Test Migration**
   - All 6 integration tests from `src/main.rs` are migrated to `crates/guardian-proxy/tests/integration_tests.rs`.
   - Each test imports `create_app` and `AppState` from `guardian_proxy`.
   - `cargo test -p guardian-proxy` passes 100% of tests.

6. **AC6: Zero Regression**
   - `cargo build --workspace` and `cargo test --workspace` both pass with zero errors.
   - `cargo clippy --workspace` produces zero warnings.

## Tasks / Subtasks

- [x] Task 1: Initialize `crates/guardian-proxy` Crate (AC: 1)
  - [x] Create directory `crates/guardian-proxy/src/`.
  - [x] Create `crates/guardian-proxy/Cargo.toml` with exact version pins matching workspace root.
  - [x] Create minimal `crates/guardian-proxy/src/lib.rs`.
  - [x] Update workspace root `Cargo.toml`: add `"crates/guardian-proxy"` to members and add dependency.
  - [x] Add profile opt-level entries for `guardian-proxy` matching the pattern for `guardian-core`.
  - [x] Verify: `cargo check -p guardian-proxy` compiles cleanly.

- [x] Task 2: Migrate AppState and proxy module to guardian-proxy (AC: 2, 3)
  - [x] Create `crates/guardian-proxy/src/proxy.rs` by migrating all logic from `src/proxy.rs`.
  - [x] Move `AppState` definition to `crates/guardian-proxy/src/lib.rs`.
  - [x] Move `create_app` function to `crates/guardian-proxy/src/lib.rs`.
  - [x] Export from `crates/guardian-proxy/src/lib.rs`: `AppState`, `create_app`, `proxy_handler`, `chat_completions_handler`, `ProxyError`.
  - [x] Verify `cargo check -p guardian-proxy` passes.

- [x] Task 3: Adapt Root Binary to Consume guardian-proxy (AC: 3, 4)
  - [x] Update `src/main.rs` to remove `mod proxy;`, remove `AppState` definition, remove `create_app` definition.
  - [x] Add `use guardian_proxy::{AppState, create_app};` imports.
  - [x] Delete `src/proxy.rs`.
  - [x] Verify: `cargo check --workspace` passes with zero errors.

- [x] Task 4: Migrate Integration Tests to guardian-proxy (AC: 5)
  - [x] Create `crates/guardian-proxy/tests/integration_tests.rs`.
  - [x] Migrate all 6 integration tests from `src/main.rs` into the integration test file.
  - [x] Update imports to use `guardian_proxy` types.
  - [x] Add dev-dependencies to `crates/guardian-proxy/Cargo.toml` for integration tests.
  - [x] Remove the 6 migrated integration tests from `src/main.rs` (keep the pure unit tests).
  - [x] Run `cargo test -p guardian-proxy` to confirm all tests pass.

- [x] Task 5: Full Workspace Verification (AC: 6)
  - [x] Run `cargo build --workspace` — 0 errors.
  - [x] Run `cargo test --workspace` — all tests pass.
  - [x] Run `cargo clippy --workspace` — 0 warnings.

## Dev Notes

### Architecture & Boundaries

Per **AD-12 (Workspace and Binary Shape)**: The project must have exactly these three crates:
- `guardian-core` — pure detection engine (DONE in Story 1.1)
- `guardian-proxy` — Axum server + MITM logic (this story)
- `guardian-cli` — clap entrypoint (Story 1.3)

**Dependency direction is strict**: `guardian-proxy` depends on `guardian-core`. It must NEVER import from `guardian-cli`.

### References

- `src/proxy.rs` — file migrated to `crates/guardian-proxy/src/proxy.rs`
- `src/main.rs` — adapted to consume `guardian_proxy`
- `crates/guardian-core/` — core engine dependency
- `docs/planning-artifacts/epics.md#Story 1.2`
- `docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md#AD-12`

## Dev Agent Record

### Agent Model Used
Gemini 3.7 Flash

### Debug Log References
- `cargo check -p guardian-proxy`: Clean pass with 0 errors.
- `cargo test -p guardian-proxy`: 6/6 integration tests passed.
- `cargo check --workspace`: 0 errors.
- `cargo test --workspace`: 30/30 tests passed (16 in `guardian-core`, 6 in `guardian-proxy`, 8 in `llm-firewall-rs`).
- `cargo clippy --workspace -- -D warnings`: Clean pass with 0 warnings.

### Completion Notes List
- Initialized `crates/guardian-proxy` library crate with `Cargo.toml`, `src/lib.rs`, and `src/proxy.rs`.
- Migrated `AppState`, `create_app`, `proxy_handler`, `chat_completions_handler`, and `ProxyError` to `guardian-proxy`.
- Migrated all 6 integration tests from `src/main.rs` to `crates/guardian-proxy/tests/integration_tests.rs`.
- Configured `make_test_client` with `.no_proxy()` to ensure robust execution across varied runtime environments.
- Simplified `src/main.rs` to import from `guardian_proxy` and removed `src/proxy.rs`.
- Added `guardian-proxy` to workspace `Cargo.toml` members, dependencies, and profile optimization sections.
- Verified full workspace compilation, linting, and tests passing with zero regressions.

### File List
- `Cargo.toml` (modified)
- `Cargo.lock` (modified)
- `crates/guardian-proxy/Cargo.toml` (created)
- `crates/guardian-proxy/src/lib.rs` (created)
- `crates/guardian-proxy/src/proxy.rs` (created)
- `crates/guardian-proxy/tests/integration_tests.rs` (created)
- `src/main.rs` (modified)
- `src/proxy.rs` (deleted)
- `docs/implementation-artifacts/sprint-status.yaml` (modified)
- `docs/implementation-artifacts/1-2-extract-guardian-proxy-crate.md` (modified)
