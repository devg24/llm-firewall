---
name: llm-firewall-rs
type: architecture-spine
purpose: build-substrate
altitude: system
paradigm: Intercepting Filter Proxy
scope: Guardian-AI system proxy and security pipeline
status: final
created: 2026-06-26
updated: 2026-06-26
binds: []
sources: []
companions: []
---

# Architecture Spine — llm-firewall-rs

## Design Paradigm

Guardian-AI is built as a **Stateless Intercepting Filter Proxy**. It acts as a transparent network boundary that sits between enterprise applications and external LLM APIs. The design decouples downstream transport interception from the security redaction pipeline. All incoming requests are examined: non-intercepted endpoints are passed through unmodified, while completions payloads are routed through sequential Regex and ML filters before being rebuilt and forwarded.

Unified usage of `hyper 1.x` and `http 1.x` by both Axum and Reqwest allows for zero-copy header and request/response body translation, minimizing proxy overhead.

```mermaid
graph TD
    Client["Enterprise Client App"] -->|POST /v1/chat/completions| Proxy["Guardian-AI Interception Engine"]
    Proxy -->|1. Parse Payload| JSONFilter["JSON Interceptor (serde_json::Value)"]
    JSONFilter -->|2. Regex Scan| RegexFilter["Tier 1: Regex Filter (OnceLock)"]
    RegexFilter -->|3. NER Inference| MLFilter["Tier 2: NER ML Filter (tokio::task::spawn_blocking)"]
    MLFilter -->|4. Map Offsets| Redactor["Co-Reference Redactor"]
    Redactor -->|5. Rebuild JSON| Forwarder["Upstream Forwarder (Pooled reqwest::Client)"]
    Forwarder -->|HTTP POST| Upstream["Upstream LLM API (UPSTREAM_URL)"]
    Proxy -.->|Other Endpoints: Transparent Pass-Through {*path}| Forwarder
```

---

## Invariants & Rules

### AD-1 — ML Inference Isolation
- **Binds:** `src/ml.rs` and Axum completions route handler
- **Prevents:** CPU-bound Candle-core inference (BERT forward passes) from starving Tokio's asynchronous IO executor threads under load.
- **Rule:** Wrap all Hugging Face Candle tokenization and inference forward-passes in a `tokio::task::spawn_blocking` block and await the join handle to offload CPU-intensive operations from the main async worker pool. (See AD-8 for resource safety).

### AD-2 — Forwards-Compatible JSON Interception
- **Binds:** `src/proxy.rs` and `src/redact.rs`
- **Prevents:** Proxy failures, schema drift, or lost optional parameters when upstream LLM completions APIs add new payload options.
- **Rule:** Intercept requests using untyped JSON parsing (`serde_json::Value`). Locate, extract, and mutate only the target prompt text values inside the `messages` array in-place, keeping all other fields unmodified and forwarding them as-is. (See AD-9 for mutation safety).

### AD-3 — Regex Compilation & Lifecycle
- **Binds:** `src/redact.rs` Tier 1 engine
- **Prevents:** High latency overhead caused by compiling complex regex patterns repeatedly on every request.
- **Rule:** Compile all Tier 1 regex patterns exactly once at server startup. Store the compiled patterns in thread-safe, read-only structures using `std::sync::OnceLock` or share them using Axum's shared state.

### AD-4 — Local Model Loading with Configurable Paths
- **Binds:** `src/ml.rs` model initialization
- **Prevents:** Network dependencies at server startup, external API calls, and startup failures in secure, air-gapped enterprise environments.
- **Rule:** Read filesystem paths for the `.safetensors` model weights and `tokenizer.json` configuration from environment variables (`MODEL_DIR`), falling back to a relative `./model/` folder for local development. Provide a standalone `scripts/setup_model.sh` script to pull model assets from Hugging Face Hub during local development setup.

### AD-5 — Fail-Closed Security Policy
- **Binds:** Request middleware and error handlers
- **Prevents:** Accidental exposure or leakage of raw, un-redacted PII to external APIs when the redaction pipeline encounters parsing, memory, timeout, or model errors.
- **Rule:** Return an HTTP `500 Internal Server Error` containing a generic security pipeline message immediately if any step in the pipeline (JSON parsing, regex evaluation, or ML inference) fails or times out.

### AD-6 — Co-Reference Preserving 1-Way Redaction
- **Binds:** `src/redact.rs` string replacement logic
- **Prevents:** Loss of relational context (e.g., entity co-reference) inside the prompt forwarded to the upstream LLM.
- **Rule:** Maintain an ephemeral, per-request translation map of original PII entity strings to indexed semantic tokens (e.g., `John Doe` -> `[REDACTED_NAME_1]`). Replace identical values with the same indexed token throughout the request. Destroy the map immediately upon request completion to prevent cross-request state leakage. (See AD-10 for concurrency safety).

### AD-7 — Upstream Gateway & Connection Invariants
- **Binds:** `src/proxy.rs` forwarder
- **Prevents:** Protocol lock-in and connection establishment latency overhead.
- **Rule:** Read target gateway base URL from the `UPSTREAM_URL` environment variable (defaulting to `https://api.openai.com`). Perform transparent proxy routing for all non-completions endpoints. Share a single, thread-safe, pre-configured `reqwest::Client` (initialized once at startup) across all requests to reuse connection pools. (See AD-11 for header rewriting).

### AD-8 — Concurrency Bounding for Blocking Tasks
- **Binds:** `tokio::task::spawn_blocking` pipeline (AD-1)
- **Prevents:** OS thread-pool exhaustion and Denial of Service (DoS) under high concurrent load when request-level wait limits are exceeded.
- **Rule:** Limit the maximum number of concurrent active ML inference jobs running inside the blocking thread pool using a static `tokio::sync::Semaphore` initialized to match the system's physical CPU core count. Reject requests immediately with an HTTP 500 fail-closed response if the semaphore acquisition times out.

### AD-9 — Analysis-First Single-Pass Text Mutation
- **Binds:** Tier 1 and Tier 2 filters (AD-2, AD-3, and AD-6)
- **Prevents:** Rust slice indexing panics (UTF-8 character boundary errors) and misaligned replacements caused by character shifts when mutating strings in place sequentially.
- **Rule:** Run Regex scanning (Tier 1) and NER classification (Tier 2) against the original, unmodified request text. Gather all character index spans of detected PII entities, resolve overlapping spans, offset-resolve sequential items, and only *then* apply the co-reference preserving substitutions in a single, final string replacement pass.

### AD-10 — Ephemeral Map Concurrency
- **Binds:** Ephemeral translation maps (AD-6)
- **Prevents:** Multi-threaded ownership conflicts and compilation failures under Rust's borrow checker when processing multiple conversation messages.
- **Rule:** Redact the messages within a single incoming completions payload sequentially on the blocking thread pool worker, ensuring single-threaded exclusive ownership of the ephemeral translation map.

### AD-11 — Proxy Header Rewriting
- **Binds:** HTTP forwarder (AD-7)
- **Prevents:** TLS SNI handshake failures, connection dropouts, and request hangs due to mismatched payload sizes.
- **Rule:** When forwarding requests, the proxy client must rewrite the `Host` header to match the upstream domain, drop hop-by-hop headers, recalculate the `Content-Length` header to reflect the redacted payload size, and forward the client's `Authorization` header unmodified.

---

## Consistency Conventions

| Concern | Convention |
| --- | --- |
| Naming | Use clean modules (`src/proxy.rs`, `src/ml.rs`, `src/redact.rs`). Endpoint routes use standard Axum routing macros. Struct names suffix with the role (e.g., `ProxyState`). |
| Routing Parameters | Transparent proxy wildcard routes must use the Axum 0.8.x syntax: `{*path}` matching instead of the deprecated `*path` or `/*path`. |
| Data & formats | Return standard HTTP status codes. Security failures must return HTTP `500` with JSON body `{"error": "Security pipeline failure"}`. Redacted tokens must follow `[REDACTED_TYPE_INDEX]` format. |
| State & cross-cutting | The proxy must remain entirely stateless; no request payload data or mapping may be persisted on disk or cached beyond the request's thread execution scope. |

---

## Stack

| Name | Version |
| --- | --- |
| Rust (Edition) | 2021 (MSRV 1.85.0) |
| axum | 0.8.9 |
| tokio | 1.52.3 |
| candle-core | 0.10.2 |
| candle-nn | 0.10.2 (Pinned match) |
| candle-transformers | 0.10.2 (Pinned match) |
| reqwest | 0.13.4 |
| serde_json | 1.0 |

---

## Structural Seed

```text
llm-firewall-rs/
  src/
    main.rs        # Configures logging, compiles regexes, loads model, builds Axum router, starts listener
    proxy.rs       # Transparent proxy routing engine, header copy, reqwest client forwarding
    ml.rs          # Candle model configurations, tokenizer wrapper, blocking execution boundaries
    redact.rs      # Regex scanners, co-reference translation maps, JSON path replacement logic
  docs/
    planning-artifacts/
      architecture/
  scripts/
    setup_model.sh # Helper script to download safetensors and configs for local testing
  Cargo.toml
```

---

## Deferred

- **Multi-Provider Payload Schemas:** Supporting schemas that deviate from OpenAI-compatible completion structures (e.g. Anthropic Messages, Google Gemini) is deferred to version 1.1.
- **Dynamic Rule Configuration:** Modifying regex patterns or ML entity lists at runtime without re-compiling the binary is deferred.
- **Stateful Two-Way Redaction:** Re-injecting original PII values back into the upstream LLM responses is deferred; client applications must handle redacted tokens.
