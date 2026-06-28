---
stepsCompleted:
  - "Step 1: Validate Prerequisites and Extract Requirements"
  - "Step 2: Design Epic List"
  - "Step 3: Generate Epics and Stories"
inputDocuments:
  - "docs/planning-artifacts/prds/prd-llm-firewall-rs-2026-06-26/prd.md"
  - "docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md"
---

# llm-firewall-rs - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for llm-firewall-rs, decomposing the requirements from the PRD, UX Design if it exists, and Architecture requirements into implementable stories.

## Requirements Inventory

### Functional Requirements

FR-1: Transparent Fallback Routing - The system must pass requests to endpoints other than `POST /v1/chat/completions` through to the upstream API unmodified.
FR-2: API Key Passthrough - The system must extract the OpenAI API key from the incoming request's `Authorization` header and forward it transparently to the LLM API provider. No centralized key management is maintained.
FR-3: Configurable Port - The system must read its listening port from the `PORT` environment variable, defaulting to `3000` if unset.
FR-4: Tier 1 Regex Redaction - The system must use a hardcoded regex engine to identify and replace strict PII formats (US SSNs, Credit/Debit Cards, Email Addresses, Phone Numbers, and IP Addresses) with semantic tokens (e.g., `[REDACTED_SSN]`).
FR-5: Tier 2 ML Semantic Redaction - The system must use a locally hosted, highly quantized standard NER model (e.g., `dslim/bert-base-NER`) running via `candle-core` to redact contextual PII (Names, Organizations).
FR-6: 1-Way Payload Rebuilding - The system must rebuild the `POST /v1/chat/completions` JSON payload with the redacted string and forward it to OpenAI using `reqwest`.
FR-7: Asynchronous Logging - The system must use the `tracing` crate to output structured, asynchronous logs at `info`, `debug`, and `error` levels.

### NonFunctional Requirements

NFR-1: Low Latency Overhead (SM-1) - The P99 latency overhead introduced by the proxy must be < 25ms.
NFR-2: Best-Effort PII Recall (SM-2) - The combined Tier 1 and Tier 2 engines must prioritize zero semantic loss and minimize false positives.
NFR-3: Statelessness - The proxy must retain no memory, cache, or state of the requests it processes, allowing for infinite horizontal scaling.

### Additional Requirements

- AD-1 (ML Inference Isolation): Wrap all Hugging Face Candle tokenization and inference forward-passes in a `tokio::task::spawn_blocking` block and await the join handle to offload CPU-intensive operations from the main async worker pool.
- AD-2 (Forwards-Compatible JSON Interception): Intercept requests using untyped JSON parsing (`serde_json::Value`). Locate, extract, and mutate only the target prompt text values inside the `messages` array in-place, keeping all other fields unmodified and forwarding them as-is.
- AD-3 (Regex Compilation & Lifecycle): Compile all Tier 1 regex patterns exactly once at server startup. Store patterns in thread-safe, read-only structures using `std::sync::OnceLock` or share using Axum's shared state.
- AD-4 (Local Model Loading with Configurable Paths): Read filesystem paths for the `.safetensors` weights and `tokenizer.json` configuration from environment variables (`MODEL_DIR`), falling back to `./model/` for local development. Provide `scripts/setup_model.sh` to pull model assets.
- AD-5 (Fail-Closed Security Policy): Return HTTP 500 containing a generic security pipeline message if any step in the pipeline (JSON parsing, regex evaluation, or ML inference) fails or times out.
- AD-6 (Co-Reference Preserving 1-Way Redaction): Maintain an ephemeral, per-request translation map of original PII entity strings to indexed semantic tokens (e.g., `John Doe` -> `[REDACTED_NAME_1]`). Replace identical values with the same indexed token.
- AD-7 (Upstream Gateway & Connection Invariants): Read target gateway base URL from `UPSTREAM_URL` (defaulting to `https://api.openai.com`). Share a single, thread-safe, pre-configured `reqwest::Client` across requests.
- AD-8 (Concurrency Bounding for Blocking Tasks): Limit maximum concurrent active ML inference jobs in blocking thread pool using a static `tokio::sync::Semaphore` matched to physical CPU cores.
- AD-9 (Analysis-First Single-Pass Text Mutation): Run Regex and ML scans against the original text, gather spans, resolve overlaps, offset-resolve sequential items, and then apply substitutions in a single replacement pass.
- AD-10 (Ephemeral Map Concurrency): Redact messages within a completions payload sequentially on the blocking worker to ensure single-threaded exclusive ownership of the ephemeral map.
- AD-11 (Proxy Header Rewriting): Rewrite Host header to match upstream, drop hop-by-hop headers, recalculate Content-Length to reflect redacted size, and forward client's Authorization header unmodified.

### UX Design Requirements

None (Stateless backend-only reverse proxy without a UI component).

### FR Coverage Map

- FR-1: Epic 1 - Transparent Fallback Routing
- FR-2: Epic 1 - API Key Passthrough
- FR-3: Epic 1 - Configurable Port
- FR-4: Epic 2 - Tier 1 Regex Redaction
- FR-5: Epic 3 - Tier 2 ML Semantic Redaction
- FR-6: Epic 2 & Epic 3 - 1-Way Payload Rebuilding
- FR-7: Epic 1 - Asynchronous Logging

## Epic List

### Epic 1: Transparent Proxy & Interception Scaffolding
Client applications can point their OpenAI client library to Guardian-AI instead of direct OpenAI endpoints, allowing transparent request routing, API key forwarding, and structured tracing logging.
**FRs covered:** FR-1, FR-2, FR-3, FR-7

### Epic 2: Tier 1 Regex Redaction (Rigid PII)
Outbound completions requests are secured against structured/rigid PII leaks (such as SSNs, Credit Cards, Emails, Phone Numbers, and IP Addresses) using a thread-safe, compile-once regex engine.
**FRs covered:** FR-4, FR-6

### Epic 3: Tier 2 ML Semantic Redaction (Contextual PII)
Conversational and contextual PII (like Names and Organizations) are detected and redacted using a local, quantized BERT NER model running inside a resource-safe thread pool.
**FRs covered:** FR-5, FR-6

## Epic 1: Transparent Proxy & Interception Scaffolding

Client applications can point their OpenAI client library to Guardian-AI instead of direct OpenAI endpoints, allowing transparent request routing, API key forwarding, and structured tracing logging.

### Story 1.1: Crate Scaffold & Axum HTTP Listener with Environment Configuration

As a Client Application Developer,
I want the proxy to boot up on a configurable port and log server events asynchronously,
So that I can configure the network boundary and observe proxy startup and requests.

**Acceptance Criteria:**

**Given** the proxy binary is started with the environment variable `PORT=4000` (defaulting to `3000` if unset)
**When** the server starts successfully
**Then** it prints a startup log using the `tracing` crate at the `info` level to stdout
**And** it listens and responds to HTTP requests on port `4000`.

### Story 1.2: Wildcard Transparent Fallback Proxy Routing

As an Enterprise Integration Engineer,
I want all HTTP requests sent to non-completions endpoints (e.g., `GET /v1/models`) to pass through unmodified,
So that auxiliary API calls do not break when routing client traffic through the firewall.

**Acceptance Criteria:**

**Given** `UPSTREAM_URL` is set (defaulting to `https://api.openai.com` if unset) and the proxy is running
**When** a client sends a `GET /v1/models` request to the proxy
**Then** the proxy forwards the request to the upstream target using a shared `reqwest::Client`
**And** the shared client is configured with a connect timeout of 10s and a read timeout of 30s
**And** returns the exact upstream HTTP response status, headers, and body unmodified
**And** logs the request duration and outcome.

### Story 1.3: Chat Completions Route Interception and Request Forwarding

As an Application Developer,
I want the proxy to explicitly intercept the `POST /v1/chat/completions` endpoint and forward it to upstream with corrected headers,
So that I can authenticate against the upstream LLM and get completions responses back.

**Acceptance Criteria:**

**Given** a client sends a `POST /v1/chat/completions` payload with an optional `Authorization: Bearer <token>` header
**When** the proxy intercepts the request
**Then** it rewrites the `Host` header to match the upstream domain
**And** it drops any connection-specific hop-by-hop headers
**And** it forwards the client's payload and copies the `Authorization` header if present (but does not panic or fail if missing, leaving the auth check to the upstream API)
**And** returns the upstream completions JSON response back to the client
**And** under no circumstances prints the value of the `Authorization` header to logs
**And** returns HTTP 500 containing a generic security pipeline message if the upstream request fails or times out
**And** implements a custom error enum `ProxyError` that implements `axum::response::IntoResponse` to automatically serialize internal failures (networking, serialization, and ML pipelines) into this uniform HTTP 500 response
**And** rejects any request payload exceeding 2MB with an HTTP `413 Payload Too Large` error to prevent resource exhaustion attacks.

## Epic 2: Tier 1 Regex Redaction (Rigid PII)

Outbound completions requests are secured against structured/rigid PII leaks (such as SSNs, Credit Cards, Emails, Phone Numbers, and IP Addresses) using a thread-safe, compile-once regex engine.

### Story 2.1: Untyped JSON Interception & Content Extraction

As a Security Gateway,
I want to parse incoming requests into untyped JSON and extract prompt messages,
So that we can inspect text without dropping new or unexpected API parameters.

**Acceptance Criteria:**

**Given** an incoming completions payload JSON
**When** parsed by the proxy
**Then** it must extract and inspect the `"content"` fields of ALL messages in the `"messages"` array, regardless of their `"role"` (system, user, assistant, or tool)
**And** it must handle `"content"` fields whether they are formatted as a raw JSON string OR as an array of nested text/image objects, using `serde_json::Value` to recursively extract all text blocks for redaction
**And** it rebuilds the JSON payload with a dummy replacement to verify serialization works.

### Story 2.2: Compile-Once Regex Matcher (`OnceLock`)

As a High-Performance Firewall,
I want regex patterns (SSN, CC, Email, Phone, IP) compiled exactly once at startup,
So that request-level latency is minimized.

**Acceptance Criteria:**

**Given** the server starts up
**When** initialized, it compiles the 5 rigid PII patterns (US SSN, Credit Cards, Emails, Phone Numbers, and IP Addresses) into thread-safe `OnceLock` structures
**Then** requests query the compiled patterns without re-compiling.

### Story 2.3: Single-Pass Regex Redaction with Co-Reference Mapping

As a Client,
I want my SSNs and Emails redacted using indexed tokens (e.g. `[REDACTED_SSN_1]`),
So that identical items share the same token and my text is mutated without UTF-8 boundary panics.

**Acceptance Criteria:**

**Given** a text string with multiple identical or different rigid PII items
**When** prepared, the engine normalizes the text to strip zero-width spaces (`\u200B`), control codes, and normalize unicode normalization forms (NFC/NFKC) before scanning
**And** when scanned, the engine records match byte offsets, resolves overlaps, maintains a request-level co-reference map, and performs replacements in a single byte-copy pass
**Then** the resulting string has no raw PII
**And** no UTF-8 slice boundary panics are thrown.

## Epic 3: Tier 2 ML Semantic Redaction (Contextual PII)

Conversational and contextual PII (like Names and Organizations) are detected and redacted using a local, quantized BERT NER model running inside a resource-safe thread pool.

### Story 3.1: Hugging Face Candle Model Loader & Scaffolding

As a System Administrator,
I want the proxy to load quantized BERT NER model weights and configurations from local files (`MODEL_DIR`),
So that the gateway starts up in air-gapped environments without network calls.

**Acceptance Criteria:**

**Given** `MODEL_DIR` points to valid `.safetensors` and `tokenizer.json` files
**When** the proxy boots
**Then** it loads these structures into memory
**And** it exposes a thread-safe `Arc` handle for inference
**And** a helper script `scripts/setup_model.sh` is provided and verified to download the target Safetensors model assets into `MODEL_DIR` when run.

### Story 3.2: Async-Isolated CPU Inference Worker (`spawn_blocking`)

As a Web Server,
I want ML tokenization and inference executed on a dedicated blocking thread pool bounded by system CPU cores,
So that high-traffic async IO network threads are never starved.

**Acceptance Criteria:**

**Given** concurrent HTTP completions requests
**When** routed, tokenization and BERT classification passes are executed inside `tokio::task::spawn_blocking`
**And** the tokenizer checks token counts, chunking/sliding-window partitioning the input if tokens exceed the model's maximum sequence length (512 tokens) to prevent model execution panics
**And** concurrency is capped using a `tokio::sync::Semaphore` matching CPU core count
**Then** async network endpoints remain responsive and low-latency.

### Story 3.3: Offset Mapping & Combined Single-Pass Redactor

As a Security Gateway,
I want token-classification outputs mapped back to character byte indices and merged with Regex offsets,
So that all PII is redacted in a single, safe replacement pass.

**Acceptance Criteria:**

**Given** both Regex (Tier 1) and Candle NER (Tier 2) outputs
**When** combined, overlapping spans are resolved, offsets are mapped back to the original `String` byte indices, and a final string substitution pass is run
**Then** all Names, Orgs, and rigid PII are redacted
**And** the combined pipeline's P99 latency overhead is profiled and verified to be within the < 25ms boundary.
