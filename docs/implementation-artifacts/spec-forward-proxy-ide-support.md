---
title: 'Forward Proxy IDE Support'
type: 'feature'
created: '2026-08-29'
status: 'ready-for-dev'
baseline_commit: '73b531f'
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy acts exclusively as a reverse proxy, so IDEs (Cursor, Claude Code) that require a forward proxy (`CONNECT` tunneling) cannot route through it, blocking native IDE integration before release.

**Approach:** Multiplex reverse proxy and forward proxy `CONNECT` traffic on a single port by peeking the first 7 bytes of each incoming TCP connection (`CONNECT` vs `GET/POST/…`), then either handing the socket to the existing Axum app or processing it as a MITM CONNECT tunnel with SNI-based routing and dynamic TLS termination.

## Boundaries & Constraints

**Always:**
- Single-port multiplexing: both reverse and forward proxy traffic share port 3000.
- TCP peeking to detect CONNECT must happen before any HTTP frame parsing.
- TLS MITM termination uses `LocalCA` (already in `guardian-cli/src/ca.rs`) to sign ephemeral leaf certs with `rcgen`.
- Known LLM domains (`api.anthropic.com`, `api.openai.com`, `api.cursor.sh` chat endpoint) → MITM decrypt → run through the existing Axum PII pipeline.
- Non-LLM domains (auth/telemetry: `authenticate.cursor.sh`, etc.) → blind byte-pump via `tokio::io::copy_bidirectional` without decryption.
- PII firewall blocks must dynamically determine if the intercepted request is a stream vs REST call, and which provider schema to use (OpenAI vs Anthropic) based on the target host and request headers/body. The block response must gracefully match the expected client format instead of returning HTTP 400/403.
- Drop all `std::sync::Mutex` locks before `.await`; no CPU-bound work on async threads. Offload cryptography (`rcgen`) to `spawn_blocking`.
- Include standard network timeouts (e.g. `tokio::time::timeout`) on all raw socket reads (like `peek` and header parsing) to prevent Slowloris attacks.
- Zero clippy warnings policy; all new code must pass `cargo fmt`.

**Ask First:**
- Any domain added to the SNI bypass list beyond `authenticate.cursor.sh` must be approved — the bypass list is a security boundary.
- If HTTP/2 support requires replacing `axum::serve` entirely (not just adding a TCP peek loop), ask before touching the Axum router.

**Never:**
- Do not build OS-level transparent proxy (pf/iptables/DNS spoofing).
- Do not attempt to bypass certificate pinning in binaries.
- Do not store per-CONNECT-tunnel state in global `AppState`.
- Do not use manual `poll_next` for stream processing (use `StreamExt` combinators or `async-stream`).
- Do not fail open on CA certificate loading errors; return an HTTP 502 to the CONNECT tunnel client if MITM cannot be performed securely.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Reverse proxy (existing) | `POST /v1/chat/completions` TCP connection | Axum routes to `chat_completions_handler` — unchanged behavior | Unchanged |
| CONNECT to LLM domain | `CONNECT api.anthropic.com:443 HTTP/1.1` | `200 Connection Established`, TLS-terminate, inspect, re-inject secrets | If upstream unreachable → write HTTP 502 to tunnel and close |
| CONNECT to bypass domain | `CONNECT authenticate.cursor.sh:443 HTTP/1.1` | `200 Connection Established`, raw byte-pump, no TLS termination | TCP error → close both sockets |
| CONNECT to unknown domain | `CONNECT example.com:443 HTTP/1.1` | `200 Connection Established` + blind byte-pump (fail-open for non-LLM domains) | TCP error → close both sockets |
| PII detected in CONNECT tunnel | PII in `messages[].content` inside CONNECT TLS tunnel | Intercept response and return mocked payload mimicking the requested format (SSE or JSON) | Stream error → close tunnel |
| Malformed CONNECT request | Missing or invalid `Host:port` in CONNECT line | Respond with `HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n` and close | Same |
| Dynamic cert signing fails | CA key unavailable or rcgen error | Write `HTTP/1.1 502 Bad Gateway\r\n\r\n` to client and log error | Same |
| Peek timeout / slow client | No bytes arrive within read timeout | Close socket silently (no error log for normal idle disconnects) | Same |

</frozen-after-approval>

## Code Map

- `crates/guardian-proxy/src/lib.rs` — `AppState`, `create_app` router; will gain `ca_key_pair` field for dynamic cert signing
- `crates/guardian-proxy/src/proxy.rs` — `proxy_handler`, `chat_completions_handler`, `ProxyError`; `chat_completions_handler` will be reused inside the CONNECT MITM branch and augmented to inject headers detecting MITM context
- `crates/guardian-proxy/src/connect.rs` — **new** — CONNECT tunnel accept loop, TCP peeking, SNI router, TLS MITM engine
- `crates/guardian-cli/src/lib.rs` — `run_server_internal` — TCP listener construction replaced with multiplexed accept loop; loads CA key pair into state
- `crates/guardian-cli/src/ca.rs` — `LocalCA` — will expose CA private key bytes for dynamic cert signing (currently only exposes `cert_path`)
- `crates/guardian-proxy/Cargo.toml` — add `tokio-rustls`, `rustls`, `hyper`, `hyper-util`, `tower` dependencies
- `crates/guardian-cli/Cargo.toml` — ensure `rcgen` features include key serialization needed by proxy
- `crates/guardian-proxy/tests/integration_tests.rs` — extend with CONNECT tunnel smoke test

## Tasks & Acceptance

**Execution:**
- [ ] `crates/guardian-proxy/Cargo.toml` — Add dependencies: `tokio-rustls = "0.26"`, `rustls = "0.23"`, `hyper = { version = "1", features = ["server", "client", "http1", "http2"] }`, `hyper-util = { version = "0.1", features = ["tokio", "server-auto"] }`, `tower = "0.5"` — Required for low-level HTTP driving inside decrypted TLS tunnels
- [ ] `crates/guardian-cli/src/ca.rs` — Add `pub fn load_key_pair(cert_dir: &Path) -> Result<rcgen::KeyPair, Box<dyn std::error::Error>>` that reads `llm-firewall-ca.key` from disk and parses it — Needed so the proxy can sign ephemeral leaf certs per CONNECT
- [ ] `crates/guardian-proxy/src/lib.rs` — Add `pub ca_key_pair: Option<Arc<rcgen::KeyPair>>` and `pub ca_cert_der: Option<Arc<Vec<u8>>>` fields to `AppState`; update `create_app` signature to allow passing these through — Makes CA available to the CONNECT handler without re-reading from disk per-connection
- [ ] `crates/guardian-proxy/src/connect.rs` — **create new module** implementing:
  - `pub const LLM_MITM_DOMAINS: &[&str]` — list of domains to MITM (`api.anthropic.com`, `api.openai.com`)
  - `pub const SNI_BYPASS_DOMAINS: &[&str]` — list of bypass domains (`authenticate.cursor.sh`)
  - `pub async fn accept_loop(listener: TcpListener, app: Router, state: AppState, shutdown: impl Future<Output = ()>)` — peeks first 7 bytes; routes CONNECT vs reverse proxy
  - `async fn handle_connect(stream: TcpStream, state: AppState)` — parses CONNECT target, sends 200, routes by SNI. Must use timeouts and return 502 on CA errors.
  - `async fn mitm_tunnel(client_stream, target_host, target_port, state)` — terminates TLS with dynamic cert (using `spawn_blocking`), runs HTTP/2 or HTTP/1.1 request through Axum pipeline, injecting a `X-Firewall-Mitm` header so `proxy.rs` knows it's inside a tunnel.
  - `async fn blind_tunnel(client_stream, target_host, target_port)` — raw `copy_bidirectional` passthrough
- [ ] `crates/guardian-proxy/src/proxy.rs` — Update `chat_completions_handler` to read the `X-Firewall-Mitm` header and request headers/body to dynamically format PII blocks for MITM traffic (OpenAI vs Anthropic, Stream vs REST).
- [ ] `crates/guardian-proxy/src/lib.rs` — Export `connect` module: `pub mod connect;` — Keeps module tree clean
- [ ] `crates/guardian-cli/src/lib.rs` — In `run_server_internal`: load CA key pair from `.llm-firewall-certs/`; build `AppState` with the key pair; replace `axum::serve(listener, app)` call with `connect::accept_loop(listener, app, state, shutdown_signal())` — Core integration point
- [ ] `crates/guardian-proxy/tests/integration_tests.rs` — Add regression tests for multiplexed accept loop and dynamic SSE mock response formatting.

**Acceptance Criteria:**
- Given the server is running on port 3000, when a client sends `POST /v1/chat/completions` with PII, then PII is redacted and secrets are re-injected in the SSE stream (existing behaviour preserved, no regression).
- Given the server is running and a `LocalCA` cert is trusted, when Cursor is configured to use `http://127.0.0.1:3000` as its HTTP proxy and sends a `CONNECT api.anthropic.com:443` request, then the proxy responds `200 Connection Established` and successfully establishes a TLS-terminated tunnel.
- Given the MITM tunnel is established for an LLM domain, when a request is blocked, the proxy dynamically returns a mock response matching the client's requested format (REST or SSE, Anthropic or OpenAI) instead of returning an HTTP 400.
- Given the server handles a `CONNECT authenticate.cursor.sh:443` request, then the proxy responds `200 Connection Established` and blindly relays bytes via `tokio::io::copy_bidirectional` without TLS termination.
- Given a `CONNECT` request with a malformed or missing `host:port`, then the proxy responds `HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n` and closes the connection without crashing.
- Given `cargo clippy -p guardian-proxy -p guardian-cli` is run, then it produces zero warnings.

## Spec Change Log

- Reverted to `ready-for-dev` from `in-review`. Added dynamic mock response generation for stream/REST and Anthropic/OpenAI compatibility. Added timeout and spawn_blocking requirements to fix Slowloris and CPU exhaustion risks. Reverted original implementation due to `intent_gap` and `bad_spec` identified in step-04 peer review.

## Verification

**Commands:**
- `cargo check -p guardian-proxy -p guardian-cli` — expected: zero errors
- `cargo clippy -p guardian-proxy -p guardian-cli -- -D warnings` — expected: zero warnings
- `cargo test -p guardian-proxy -- --nocapture 2>&1 | tail -20` — expected: all tests pass
- `cargo fmt --check` — expected: no formatting changes needed
