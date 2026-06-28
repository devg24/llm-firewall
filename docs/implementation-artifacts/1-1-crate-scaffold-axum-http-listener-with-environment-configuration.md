---
baseline_commit: NO_VCS
---
# Story 1.1: Crate Scaffold & Axum HTTP Listener with Environment Configuration

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a Client Application Developer,
I want the proxy to boot up on a configurable port and log server events asynchronously,
so that I can configure the network boundary and observe proxy startup and requests.

## Acceptance Criteria

1. **Environment Configuration:** The server reads the listening port from the `PORT` environment variable. It defaults to `3000` if the variable is unset or empty. If `PORT` is set but cannot be parsed as a valid port number, the application must print an error log and terminate immediately (fail-closed).
2. **Startup Logging:** Upon successful startup, the server prints a startup log using the `tracing` crate at the `info` level to stdout. The log configuration must utilize `tracing-subscriber`'s `EnvFilter` initialized from the `RUST_LOG` environment variable (defaulting to `info` level if unset) to support dynamic log level adjustments.
3. **HTTP Listener:** The server listens on the configured port bound to `0.0.0.0` (to support deployment in containerized environments) and responds to HTTP requests (e.g., returning a valid HTTP response on a test route like `GET /health`).
4. **Scaffolding Stack:** The crate is structured using the standard Cargo package layout, targeting Rust edition 2021 and Minimum Supported Rust Version (MSRV) `1.85.0`.

## Tasks / Subtasks

- [x] Task 1: Initialize Project Scaffold & Cargo Configuration (AC: 4)
  - [x] Create `.gitignore` to exclude `target/` and standard development artifacts.
  - [x] Create `Cargo.toml` at the workspace root, configuring target MSRV `1.85.0`, edition `2021`, and package name `llm-firewall-rs`.
  - [x] Add the following exact dependency definitions to `Cargo.toml`:
    ```toml
    [dependencies]
    axum = "0.8.9"
    tokio = { version = "1.52.3", features = ["full"] }
    tracing = "0.1"
    tracing-subscriber = { version = "0.3", features = ["env-filter"] }
    serde = { version = "1.0", features = ["derive"] }
    serde_json = "1.0"
    reqwest = { version = "0.13.4", features = ["json"] }
    candle-core = "0.10.2"
    candle-nn = "0.10.2"
    candle-transformers = "0.10.2"
    ```
- [x] Task 2: Implement Environment & Logging configuration (AC: 1, 2)
  - [x] Initialize `tracing-subscriber` using the default formatting subscriber logging to stdout, configured via `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))`.
  - [x] Parse the `PORT` environment variable. If it is set but invalid (e.g. non-numeric, out-of-range), log a fatal error and exit/panic immediately. If it is unset or empty, default to port `3000`.
- [x] Task 3: Setup Axum HTTP Router & TCP Listener (AC: 3)
  - [x] Create an Axum router with a basic test endpoint (`GET /health` returning a simple text/JSON response).
  - [x] Bind a `tokio::net::TcpListener` to `0.0.0.0:<PORT>`.
  - [x] Start the Axum web server using `axum::serve` and await request dispatch.
  - [x] Print a startup confirmation log at the `info` level using the `tracing` crate.
- [x] Task 4: Integration Verification (AC: 1, 2, 3, 4)
  - [x] Verify that `cargo check` and `cargo build` complete successfully.
  - [x] Run the server with `PORT=4000` and confirm using `curl` that it responds, logging request info to stdout.
  - [x] Run the server with `PORT=invalid` and confirm that it fails to start and outputs a descriptive log.

### Review Findings

- [x] [Review][Patch] Multiple subscriber initialization panic [src/main.rs:11]
- [x] [Review][Patch] Startup logs printed to stderr instead of stdout [src/main.rs:10-11]
- [x] [Review][Patch] Non-Unicode PORT values fail-open instead of fail-closed [src/main.rs:37]
- [x] [Review][Patch] Dynamically bound port 0 logs incorrect address [src/main.rs:44,90]
- [x] [Review][Patch] Race condition in HTTP health check integration test [src/main.rs:98-102]
- [x] [Review][Defer] Test background server task runs indefinitely [src/main.rs:93-95] — deferred, pre-existing
- [x] [Review][Defer] Missing graceful shutdown signal handling [src/main.rs:55-57] — deferred, pre-existing
- [x] [Review][Defer] std::process::exit bypasses drops in main [src/main.rs:39,49] — deferred, pre-existing

## Dev Notes

- **Architecture Standards:**
  - The project is entirely stateless. Keep any state-related features out of this scope.
  - Port config must fall back to 3000 when `PORT` is unset, but invalid values must cause immediate server termination.
  - Logging must be configured asynchronously using `tracing` crate.
- **Source Tree Components:**
  - To Create: `Cargo.toml`, `src/main.rs`, `.gitignore`
- **Testing Standards:**
  - Manually check standard output logs on startup.
  - Verify route response using `curl` or similar HTTP client.

### Project Structure Notes

- Keep `src/main.rs` simple and ready to serve as the application's entry point, which will later load the ML models, compile regexes, and configure middleware.

### References

- [PRD Functional Requirement FR-3: Configurable Port](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md#FR-3)
- [PRD Functional Requirement FR-7: Asynchronous Logging](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md#FR-7)
- [Architecture Spine Consistency Conventions](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md#Consistency-Conventions)

## Dev Agent Record

### Agent Model Used

Gemini 3.5 Flash (Medium)

### Debug Log References

- None

### Completion Notes List

- Initialized standard Rust Cargo workspace structure with MSRV 1.85.0, Edition 2021, and `.gitignore`.
- Set up logging filter using `tracing-subscriber::EnvFilter` defaulting to `info` level if `RUST_LOG` is unset.
- Parsed and validated the `PORT` environment variable (defaults to 3000, fails-closed on invalid values).
- Constructed an Axum router with `GET /health` route returning `"OK"`.
- Handled TcpListener binding on `0.0.0.0:<PORT>` and server startup logging.
- Created robust unit and integration tests using a local test listener and reqwest client. All verification gates passed.

### File List

- [Cargo.toml](file:///Users/devgoyal/desktop/llm-firewall-rs/Cargo.toml)
- [.gitignore](file:///Users/devgoyal/desktop/llm-firewall-rs/.gitignore)
- [src/main.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/src/main.rs)
