# Technical Stack & Version Reality Check — llm-firewall-rs

**Reviewer Role:** Technical Architecture Reviewer & Web-Research Specialist
**Target Document:** [ARCHITECTURE-SPINE.md](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md)
**Status:** Completed
**Verdict:** **Needs Modification** (Pass with critical configuration and syntax changes)

---

## 1. Executive Summary

This review performs a thorough web-research and compatibility check on the specific crate version choices committed in the **Architecture Spine**. 

All selected versions represent the latest, stable releases available as of **late June 2026**. Individually, each library is highly mature, but their integration introduces several **critical compiler constraints** and **syntax requirements** that are not yet documented in the Architecture Spine. Specifically:
1. **MSRV Bottleneck:** The choice of `reqwest 0.13.4` enforces a Minimum Supported Rust Version (MSRV) of **1.85.0** (released in May 2026). The project must configure its toolchain accordingly.
2. **Axum 0.8 Routing Changes:** Axum 0.8.x has changed its route path parameter syntax (from `/:param` to `{param}`). Any code matching the spine's planned structure will fail to compile or route correctly if old syntax is used.
3. **Ecosystem Alignment:** Both Axum 0.8 and Reqwest 0.13 leverage `hyper 1.x` and `http 1.x` structures, which is a major win that avoids duplicate HTTP type dependencies.

---

## 2. In-Depth Library Analysis & Compatibility Matrix

### Crate Version Analysis

| Crate | Version | Release Date | MSRV | Role & Reality-Check Findings |
| :--- | :--- | :--- | :--- | :--- |
| **axum** | `0.8.9` | Mid 2026 | `1.80` | **Pass with Caveats.** The current major track 0.8.x replaces the `#[async_trait]` macro with native async traits. Path parameters changed syntax. Websocket upgrades in 0.8.9 are stable. |
| **tokio** | `1.52.3` | May 2026 | `1.71.0` | **Pass.** A highly stable patch release. Excellent support for `spawn_blocking` with dedicated thread-pools, resolving the CPU-bound starvation issues identified in the adversarial review. |
| **candle-core**| `0.10.2` | Apr 2026 | `1.75.0` | **Pass with Caveats.** Ecosystem lock-in: if `candle-core` is `0.10.2`, then `candle-nn` and `candle-transformers` must also be set to `0.10.2` exactly to avoid type incompatibilities. |
| **reqwest** | `0.13.4` | May 2026 | `1.85.0` | **Critical Constraint.** The MSRV is bumped to 1.85.0 due to dependencies like `hickory-resolver 0.26`. Default TLS is now `rustls`. |
| **serde_json** | `1.0` (1.0.150+)| June 2026 | `1.71.0` | **Pass.** The standard for JSON processing. Light-weight untyped manipulation using `serde_json::Value` is efficient and stable. |

### Pairwise & Ecosystem Compatibility

*   **HTTP Ecosystem Unification (Axum 0.8.9 + Reqwest 0.13.4):** Historically, using older versions of these crates resulted in split dependencies on `hyper 0.14` and `hyper 1.0`, duplicating the `http` crate types and causing friction when transferring headers or bodies. Axum 0.8 and Reqwest 0.13 are both native to **`hyper 1.x`** and **`http 1.x`**. This means sharing requests, responses, headers, and status codes works seamlessly without conversion wrappers.
*   **Asynchronous Integration:** Reqwest and Axum share Tokio's single-threaded and multi-threaded runtimes without issue. Shared connection pools in `reqwest::Client` (which is internally wrapped in an `Arc`) can be passed directly as Axum `State` or `Extension`.
*   **Rust Edition and Toolchain:** While the language edition is set to `2021`, the project **must** be compiled using Rust compiler `1.85.0` or higher to compile `reqwest 0.13.4`.

---

## 3. Top Findings & Risks

### Finding 1: The Rust Toolchain Constraint (MSRV 1.85.0)
*   **Risk:** Trying to build the project on standard LTS environments with older Rust toolchains (e.g., Rust 1.80 or 1.83) will fail immediately with compiler errors in the `reqwest` crate or its dependencies (e.g., `hickory-resolver`).
*   **Mitigation:** The Spine must dictate a minimum compiler version. In `Cargo.toml`, we must explicitly include the `rust-version = "1.85.0"` property.

### Finding 2: Axum 0.8.x Path Parameter Routing Shift
*   **Risk:** Traditional routing definitions (e.g. `.route("/v1/chat/:provider", ...)`) will not route correctly or fail to compile under Axum 0.8.
*   **Mitigation:** Adopt the new router pattern `{param}`. For wildcard routing (e.g., transparent pass-through for non-completion endpoints), use the wildcard `{*wildcard}` format:
    ```rust
    // Correct Axum 0.8 routing syntax
    let router = Router::new()
        .route("/v1/chat/completions", post(handle_completions))
        .route("/{*path}", any(transparent_pass_through));
    ```

### Finding 3: Candle Ecosystem Version Pinning
*   **Risk:** Using `candle-core = "0.10.2"` with a different version of `candle-transformers` (e.g., `0.9` or `0.10.0`) will lead to compilation failures due to mismatched tensor type definitions.
*   **Mitigation:** Pin all Hugging Face Candle dependencies in `Cargo.toml` to exactly `0.10.2`.

### Finding 4: Reqwest 0.13.4 Default TLS is `rustls`
*   **Risk:** In secure, air-gapped enterprise environments with local Certificate Authorities (CAs), `rustls` might reject certificates that `native-tls` (which uses system trust stores) would accept.
*   **Mitigation:** If system-level CA certificate integration is required, explicitly configure `reqwest` with the `native-tls` feature flag in `Cargo.toml`.

---

## 4. Concrete Actionable Recommendations

### Recommendation 1: Configure `Cargo.toml` with Version Constraints
To ensure successful compilation and prevent dependency mismatches, write the `Cargo.toml` dependencies block as follows:

```toml
[package]
name = "llm-firewall-rs"
version = "0.1.0"
edition = "2021"
rust-version = "1.85.0" # Mandated by reqwest 0.13.4

[dependencies]
axum = { version = "0.8.9", features = ["macros"] }
tokio = { version = "1.52.3", features = ["full"] }
candle-core = "0.10.2"
candle-transformers = "0.10.2" # Pin to align with candle-core
reqwest = { version = "0.13.4", features = ["json", "rustls-tls"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0.150"
```

### Recommendation 2: Axum 0.8 Path Parsing and Extractor Pattern
Ensure your route handlers use the native async trait signature and correct parameter parsing:

```rust
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use std::sync::Arc;

struct AppState {
    http_client: reqwest::Client,
}

// Router configuration demonstrating Axum 0.8 path syntax
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(handle_completions))
        // Wildcard fallback for transparent proxying
        .route("/{*path}", axum::routing::any(handle_passthrough))
        .with_state(state)
}
```

### Recommendation 3: Shared Reqwest Client Injection
Leverage Axum's shared state to distribute the pre-configured `reqwest::Client` securely and reuse the connection pool:

```rust
use axum::extract::State;
use std::sync::Arc;

async fn handle_passthrough(
    State(state): State<Arc<AppState>>,
    // ...
) -> impl IntoResponse {
    // Reusing the connection pool via the shared client
    let client = &state.http_client;
    // Perform forwarding logic...
}
```
