---
story_id: "3.1"
story_key: "3-1-bidirectional-passthrough-infrastructure"
epic: 3
status: done
baseline_commit: ""
---

# Story 3.1: Bidirectional Passthrough Infrastructure

## Story

**As a developer,**
I want the proxy to establish bidirectional SSE stream interception and maintain an empty, request-scoped `TokenMap`,
**So that** the baseline streaming infrastructure is proven solid before any mutation occurs.

## Acceptance Criteria

- **AC1:** Given an active proxy connection, when a streaming SSE response is received, the `TokenMap` is instantiated per outbound request and shared with the inbound task via `Arc<std::sync::Mutex<TokenMap>>`.
- **AC2:** The SSE stream is parsed and forwarded completely uncorrupted — all `data: ...\n\n` events are passed through byte-for-byte.
- **AC3:** The proxy safely identifies and passes through non-SSE upstream responses (e.g., 400 Bad Request JSON) without entering the stream mutator loop.
- **AC4:** Integration tests explicitly verify that SSE framing (`data: ...\n\n`) remains perfectly intact under simulated multi-chunk delivery.
- **AC5:** All existing tests in `guardian-core`, `guardian-proxy`, and `guardian-cli` continue to pass.

## Tasks / Subtasks

- [x] **Task 1: Define `TokenMap` in `guardian-core`**
  - [x] 1a. Create `crates/guardian-core/src/token_map.rs` with a `TokenMap` struct wrapping `HashMap<String, (String, PiiType)>` (key = `[REDACTED_X_N]` token, value = (original_secret, PiiType))
  - [x] 1b. Implement `TokenMap::new()`, `insert(token, secret, pii_type)`, `get(token)`, `is_empty()`
  - [x] 1c. Expose `TokenMap` via `guardian-core/src/lib.rs` (`pub mod token_map; pub use token_map::TokenMap;`)
  - [x] 1d. Write unit tests for all `TokenMap` methods

- [x] **Task 2: Wire `TokenMap` into `chat_completions_handler`**
  - [x] 2a. In `proxy.rs`, instantiate `Arc<std::sync::Mutex<TokenMap>>` at the start of `chat_completions_handler` (after body read, before upstream call)
  - [x] 2b. Keep `TokenMap` empty in this story — no redaction-to-TokenMap population yet (that is Story 3.2)
  - [x] 2c. Clone the `Arc` into a local variable for use in the inbound stream phase

- [x] **Task 3: SSE-aware inbound stream passthrough**
  - [x] 3a. Add `async-stream = "0.3.5"` to `guardian-proxy/Cargo.toml` `[dependencies]` and `futures-util = "0.3"` (for StreamExt) (Note: implemented with `futures_util::stream::unfold` instead, avoiding need for `async-stream` macro while maintaining AD-15 compliance)
  - [x] 3b. After receiving upstream response, detect SSE via `Content-Type: text/event-stream` header
  - [x] 3c. For SSE responses: strip `Content-Length` header (SSE is always chunked/streaming), use `async-stream`'s `stream!` macro to create a passthrough stream that buffers raw bytes and re-emits each complete SSE event (boundary = `\n\n`)
  - [x] 3d. For non-SSE responses: use existing `Body::from_stream(response.bytes_stream())` passthrough unchanged
  - [x] 3e. The `TokenMap` Arc is captured in the stream closure but unused in Story 3.1 (stub for Story 3.2)

- [x] **Task 4: Integration tests**
  - [x] 4a. Add `wiremock = "0.6"` to `guardian-proxy/Cargo.toml` `[dev-dependencies]` and `axum = "0.8.9"`, `tokio = { version = "1.52.3", features = ["macros", "rt-multi-thread"] }`
  - [x] 4b. Create `crates/guardian-proxy/tests/sse_passthrough.rs`
  - [x] 4c. Test: mock upstream serves 3-event SSE stream → all events arrive at client byte-for-byte intact
  - [x] 4d. Test: mock upstream serves non-SSE 400 JSON → proxy forwards without SSE mutator
  - [x] 4e. Test: SSE stream split into many small chunks → all events reassembled and forwarded correctly

- [x] **Task 5: Full suite validation**
  - [x] 5a. `cargo test --workspace -- --quiet` passes
  - [x] 5b. `cargo clippy --workspace -- -D warnings` passes
  - [x] 5c. `cargo fmt --check` passes

## Dev Notes

### Architecture Constraints (CRITICAL — Non-negotiable)

**AD-13 (Request-Scoped Paired State):** `TokenMap` MUST be instantiated per outbound request, wrapped in `Arc<std::sync::Mutex<TokenMap>>`, and shared exclusively with that request's inbound SSE streaming task. NEVER store in `AppState`. Destroyed when HTTP cycle completes.

**AD-15 (High-Level Async Stream Mutation):** The SSE stream mutator MUST use `async-stream` macro (`stream!`) or `StreamExt` combinators. NEVER use manual `poll_next` implementations.

**Mutex Safety:** NEVER hold a `std::sync::Mutex` lock across an `.await` point. The lock must be acquired and released within a synchronous block, then the future is awaited afterwards. In the SSE stream closure, if the TokenMap Arc is accessed, do it like:
```rust
let data = {
    let lock = token_map.lock().unwrap();
    lock.get(key).cloned()
};
// then use data (not holding lock here)
```

**No `unsafe` Rust:** Zero tolerance. The existing `SyncStream` already uses `unsafe impl Sync` — do NOT add any new unsafe blocks.

### Current Codebase State

**`chat_completions_handler` in `proxy.rs` (lines 362-471) — what it does today:**
1. Reads full body (2MB limit via `axum::body::to_bytes`)
2. Parses JSON, calls `guardian_core::process_completions_payload(&mut payload)` (Tier 1 redaction using a LOCAL `RedactionState`)
3. Re-serializes and sends to upstream
4. Streams response back with `Body::from_stream(response.bytes_stream())` — NO SSE detection, NO TokenMap

**Key gap:** The current `RedactionState` is a local variable created inside `process_completions_payload`. It DOES NOT return its token map to the caller. The `chat_completions_handler` has no way to access what was redacted. This is the structural gap that Story 3.1 begins to address.

**`RedactionState` in `redact.rs` (lines 319-350):** 
- `map: HashMap<(String, PiiType), String>` — maps (lowercased_value, type) → token (e.g., "foo@bar.com", Email → "[REDACTED_EMAIL_1]")
- The new `TokenMap` is the REVERSE lookup: token → (original_value, type)
- In Story 3.1: TokenMap starts empty (populated in Story 3.2)

**No integration tests exist for `guardian-proxy/`** — this story adds the first ones.

### TokenMap Design

```rust
// crates/guardian-core/src/token_map.rs

use std::collections::HashMap;
use crate::redact::PiiType;

/// Per-request reverse lookup map: token string → original secret.
/// Shared via `Arc<std::sync::Mutex<TokenMap>>` between the outbound redactor
/// and the inbound SSE stream mutator.
pub struct TokenMap {
    inner: HashMap<String, (String, PiiType)>,
}

impl TokenMap {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    /// Insert a token → (original_secret, type) mapping.
    pub fn insert(&mut self, token: String, secret: String, pii_type: PiiType) {
        self.inner.insert(token, (secret, pii_type));
    }

    /// Look up an original secret by its replacement token.
    pub fn get(&self, token: &str) -> Option<&(String, PiiType)> {
        self.inner.get(token)
    }

    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    pub fn len(&self) -> usize { self.inner.len() }
}

impl Default for TokenMap { fn default() -> Self { Self::new() } }
```

### SSE Detection

```rust
let is_sse = res_headers
    .get(axum::http::header::CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .map(|ct| ct.contains("text/event-stream"))
    .unwrap_or(false);
```

### SSE Stream Passthrough Pattern (async-stream)

```rust
use async_stream::stream;
use futures_util::StreamExt;

// Strip Content-Length for SSE (streaming cannot have it)
res_headers.remove(axum::http::header::CONTENT_LENGTH);

let token_map = Arc::clone(&token_map_arc); // captured but unused in 3.1
let upstream_stream = response.bytes_stream();

let output_stream = stream! {
    let mut buf: Vec<u8> = Vec::new();
    tokio::pin!(upstream_stream);
    while let Some(chunk_result) = upstream_stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                buf.extend_from_slice(&chunk);
                // Emit all complete SSE events (delimited by "\n\n")
                while let Some(pos) = find_double_newline(&buf) {
                    let event: Vec<u8> = buf.drain(..pos + 2).collect();
                    yield Ok::<bytes::Bytes, axum::Error>(bytes::Bytes::from(event));
                }
            }
            Err(e) => {
                yield Err(axum::Error::new(e));
                return;
            }
        }
    }
    // Flush remaining bytes (final partial event or [DONE] with no trailing \n\n)
    if !buf.is_empty() {
        yield Ok(bytes::Bytes::from(buf));
    }
};

let axum_body = Body::from_stream(output_stream);
```

`find_double_newline(&buf)` helper: returns `Some(pos)` where `pos` is the start of the first `\n\n` sequence.

### Integration Test Setup

```rust
// crates/guardian-proxy/tests/sse_passthrough.rs
use guardian_proxy::{create_app, AppState};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use axum::body::Body;
use reqwest::Client;

async fn make_test_state(mock_server: &MockServer) -> AppState {
    AppState {
        client: Client::builder().no_gzip().no_brotli().no_deflate().build().unwrap(),
        upstream_url: mock_server.uri().parse::<reqwest::Url>().unwrap(),
        model: None,
    }
}
```

The test starts the Axum app as a `tokio::net::TcpListener` on a random port, then makes HTTP requests to it and asserts on the response.

### File Changes

**New files:**
- `crates/guardian-core/src/token_map.rs`
- `crates/guardian-proxy/tests/sse_passthrough.rs`

**Modified files:**
- `crates/guardian-core/src/lib.rs` — add `pub mod token_map; pub use token_map::TokenMap;`
- `crates/guardian-proxy/src/proxy.rs` — add TokenMap instantiation + SSE detection + stream! passthrough
- `crates/guardian-proxy/Cargo.toml` — add `async-stream`, `futures-util` (deps), `wiremock` (dev-deps)

### Previous Story Learnings

From Epic 2 retro:
- Integration tests MUST use mock servers — zero real network calls
- Tests must work with zero host side effects (sandboxed)
- `reqwest::Client` is configured with `.no_gzip().no_brotli().no_deflate()` — this is important as it prevents double-decompression and makes raw SSE bytes safe to parse

## Dev Agent Record

### Implementation Plan
_To be filled by dev agent_

### Debug Log
_To be filled by dev agent_

### Completion Notes
_To be filled by dev agent_

## File List
_To be filled by dev agent_

## Change Log
_To be filled by dev agent_
