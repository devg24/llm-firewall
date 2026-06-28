---
baseline_commit: NO_VCS
---
# Story 1.2: Wildcard Transparent Fallback Proxy Routing

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As an Enterprise Integration Engineer,
I want all HTTP requests sent to non-completions endpoints (e.g., `GET /v1/models`) to pass through unmodified,
so that auxiliary API calls do not break when routing client traffic through the firewall.

## Acceptance Criteria

1. **Upstream Target Resolution:** Read the target gateway base URL from the `UPSTREAM_URL` environment variable. If `UPSTREAM_URL` is unset or empty, default to `https://api.openai.com`. If the variable is present but contains an invalid URL (e.g., invalid scheme, missing host, or invalid characters), the application must print an error log and terminate immediately (fail-closed).
2. **Transparent Fallback Routing:** All incoming HTTP requests to endpoints other than `POST /v1/chat/completions` and the `/health` check route must be forwarded transparently to the upstream target. The path, query parameters, method, and body must be forwarded unmodified.
3. **HTTP Client Invariants:** The forwarder must use a single, thread-safe, pre-configured `reqwest::Client` shared across all requests to reuse connection pools. The client must be initialized once at startup with a connect timeout of 10s and a read timeout of 30s.
4. **Header Manipulation:** Before forwarding, the proxy client must:
   - Rewrite the `Host` header to match the domain of the upstream URL.
   - Drop all hop-by-hop headers to prevent proxy-specific header forwarding leaks (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`).
   - Copy the client's `Authorization` header and all other non-hop-by-hop headers unmodified.
5. **Response Return:** Return the exact upstream HTTP response status, headers (dropping upstream hop-by-hop headers), and body unmodified to the client.
6. **Asynchronous Logging:** Use the `tracing` crate to output structured, asynchronous logs at the `info` level logging the request method, path, round-trip duration, and HTTP status code or error outcome.

## Tasks / Subtasks

- [x] Task 1: Environment & Client Initialization (AC: 1, 3)
  - [x] Parse `UPSTREAM_URL` from the environment. Default to `https://api.openai.com` if not present. Validate that it is a valid URL, otherwise log a fatal error and exit/panic (fail-closed).
  - [x] Initialize a single `reqwest::Client` with a connection timeout of 10s and read timeout of 30s. Wrap client and upstream URL in a thread-safe `AppState` struct to share as Axum state.
- [x] Task 2: Implement Proxy Forwarder Module (AC: 2, 4, 5, 6)
  - [x] Create `src/proxy.rs` and define a handler/function to forward incoming requests.
  - [x] In the handler, convert the incoming Axum `Request` into a `reqwest::Request`. Ensure the method, path, query parameters, and body are preserved.
  - [x] Rewrite headers: copy incoming headers, rewrite the `Host` header to match the upstream URL domain, and drop hop-by-hop headers.
  - [x] Execute the request using the shared `reqwest::Client` and measure execution time using `std::time::Instant`.
  - [x] Convert the `reqwest::Response` back to an Axum `Response`, copying status code, response headers (dropping hop-by-hop headers), and streaming/passing through the response body.
  - [x] Log request method, path, duration (in ms), and HTTP status code or error outcome at `info` level using the `tracing` crate.
- [x] Task 3: Wire Router & Integrate into main (AC: 2)
  - [x] Modify `src/main.rs` to load the `UPSTREAM_URL` configuration, construct `AppState`, and initialize Axum router state.
  - [x] Add the wildcard fallback route to the Axum Router redirecting requests to the proxy handler in `src/proxy.rs`.
  - [x] Ensure `POST /v1/chat/completions` is stubbed or registered to return a placeholder or 501 Not Implemented (to keep it separate from wildcard fallback, preparing for Story 1.3).
- [x] Task 4: Integration Verification (AC: 1, 2, 3, 4, 5, 6)
  - [x] Verify that `cargo check` and `cargo test` pass successfully.
  - [x] Create integration tests verifying that requests sent to fallback paths (e.g. `/v1/models`) are proxied correctly to a mock server, keeping method, path, query, and body.
  - [x] Create tests to ensure hop-by-hop headers are stripped, `Host` header is rewritten, and invalid `UPSTREAM_URL` causes server startup failure.

### Review Findings

- [x] [Review][Decision] Unbounded Buffering & Response Streaming (DoS/OOM) — To handle LLM streaming (Server-Sent Events) and large payloads, do we enable the `stream` feature in `reqwest` and stream request/response bodies, or do we implement buffering size limits (e.g. 10MB) for request/response payloads? (Chosen: Option 1.2 - Full streaming)
- [x] [Review][Decision] Read Timeout for Long-Running Reasoning/Streaming requests — Should we increase the read timeout (currently 30s) or remove it entirely to prevent reasoning models or long stream generations from timing out? (Chosen: Option 2.1 - Increase read timeout to 300s)
- [x] [Review][Patch] Path Prefix Loss during Upstream URL Reconstruction [src/proxy.rs:23-25]
- [x] [Review][Patch] Multi-value Header De-duplication and Loss [src/proxy.rs:50-55, 92-97]
- [x] [Review][Patch] Non-POST Requests to Completions Endpoint Blocked (405 Method Not Allowed) [src/main.rs:67-70]
- [x] [Review][Patch] Unintended Transparent Response Decompression / Header Mismatch [src/main.rs:99-106]
- [x] [Review][Patch] Exposure of Sensitive Information in Error Responses [src/proxy.rs:72-85, 102-116]
- [x] [Review][Patch] Incomplete Hop-by-Hop Header Stripping [src/proxy.rs:151-154]
- [x] [Review][Patch] Invalid Host Header Formatting for IPv6 Upstream Addresses [src/proxy.rs:58-62]
- [x] [Review][Patch] Inverted Log Levels for Client vs. Server Errors [src/proxy.rs:32, 74, 104]
- [x] [Review][Defer] Blocking/Synchronous Logging Subscriber Writer [src/main.rs:9-12] — deferred, pre-existing
- [x] [Review][Defer] Missing Standard Forwarding Headers (X-Forwarded-*) [src/proxy.rs:49-67] — deferred, pre-existing

## Dev Notes

- **Architecture Standards:**
  - Standard stateless proxy architecture. No caching or persistence of request payloads.
  - Shared connection pool: A single `reqwest::Client` instantiated at startup and shared via Axum state.
  - wildcards matching: Axum 0.8 syntax `{*path}` matching instead of deprecated `*path` or `/*path`.
- **Source Tree Components:**
  - Create: `src/proxy.rs`
  - Modify: `src/main.rs`
- **Testing Standards:**
  - Integration tests using `wiremock` or spawning a mock Axum listener as in Story 1.1's tests.
  - Verify header transformation and path forwarding using `reqwest` client in tests.

### Project Structure Notes

- Add `mod proxy;` in `src/main.rs`. Keep routing configuration clean.

### References

- [PRD Functional Requirement FR-1: Transparent Fallback Routing](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md#FR-1)
- [PRD Functional Requirement FR-2: API Key Passthrough](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md#FR-2)
- [PRD Functional Requirement FR-7: Asynchronous Logging](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md#FR-7)
- [Architecture Spine Invariant AD-7: Upstream Gateway & Connection Invariants](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md#AD-7)
- [Architecture Spine Invariant AD-11: Proxy Header Rewriting](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md#AD-11)

## Dev Agent Record

### Agent Model Used

Gemini 3.5 Flash (Medium)

### Debug Log References

- Compiler type validations for `axum::body::Body` to `reqwest::Body` conversions.
- Solved via reading body bytes with `axum::body::to_bytes` and creating `reqwest::Body::from(bytes)`.

### Completion Notes List

- Parsed and validated `UPSTREAM_URL` from the environment with fail-closed behavior.
- Initialized a single, thread-safe pre-configured `reqwest::Client` with a 10s connect timeout and a 30s read timeout.
- Implemented transparent proxy handler in `src/proxy.rs` that forwards HTTP requests unmodified, rewrites the `Host` header to match the upstream, drops hop-by-hop headers, and streams back responses.
- Registered wildcard routing and stubbed `POST /v1/chat/completions` as 501 Not Implemented in `src/main.rs`.
- Created comprehensive integration tests verifying transparent fallback proxying, header manipulation, hop-by-hop headers stripping, and stubbed completions endpoint.

### File List

- [src/main.rs](file:///Users/devgoyal/Desktop/llm-firewall-rs/src/main.rs)
- [src/proxy.rs](file:///Users/devgoyal/Desktop/llm-firewall-rs/src/proxy.rs)
