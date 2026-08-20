# Adversarial Structural Review — llm-firewall-rs

**Reviewer Role:** Adversarial Structural Reviewer
**Target Document:** [ARCHITECTURE-SPINE.md](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-2026-06-26/ARCHITECTURE-SPINE.md)
**Status:** Completed
**Verdict:** **Needs Modification**

---

## 1. Executive Summary

An adversarial analysis of the `llm-firewall-rs` Architecture Spine reveals that while each individual Architecture Decision (AD) is logically sound in isolation, several components build incompatibly when integrated. By designing "one level down" implementations that follow each AD to the letter, we expose critical gaps where the system would suffer from thread starvation under load, UTF-8 parsing/slicing panics, cross-message state leakage, and protocol failures.

To close these security and reliability holes, the Spine requires tightened constraints on concurrency limits, character offset tracking, request-scoped context propagation, and header mappings.

---

## 2. Incompatible Pairwise Clashes

### Clash 1: ML Inference Isolation (AD-1) vs. Fail-Closed Timeout Policy (AD-5)
* **Components:** `src/ml.rs` (Inference Engine) vs. `src/proxy.rs` (Axum Completion Route Handler & Timeout Middleware)
* **The Case for AD Compliance:**
  - `src/ml.rs` offloads CPU-bound Candle tokenization and inference forward passes to `tokio::task::spawn_blocking` and awaits the join handle (fully obeying **AD-1**).
  - `src/proxy.rs` implements request-level timeout middleware (using `tokio::time::timeout`) and immediately returns a `500 Internal Server Error` containing a generic security pipeline message if the limit is exceeded (fully obeying **AD-5**).
* **The Failure Mode (Thread Starvation & Uncancellable CPU Leaks):**
  - In Tokio, once a task is offloaded to a thread in the `spawn_blocking` thread pool, **it cannot be aborted or cancelled** from the outside.
  - Under heavy load, Candle inferences on CPU slow down. The timeout in `src/proxy.rs` triggers, and the proxy returns HTTP 500 (Fail-Closed).
  - However, the synchronous thread in `spawn_blocking` continues executing the BERT model forward pass to completion, wasting CPU resources on an already-abandoned client request.
  - As more requests time out, the entire `spawn_blocking` thread pool is consumed by zombie tasks. New requests cannot allocate a thread to perform inference, leading to cascading thread starvation and a denial of service (DoS) of the proxy.
* **The Hole:** The Spine does not define backpressure, request queuing, or concurrency limits for the blocking inference engine.
* **Resolution (New/Tightened AD):** Define a concurrency limit for the ML inference block using a bounded channel or semaphore. If the queue is full, reject requests early with HTTP `429 Too Many Requests` or `503 Service Unavailable` before spawning blocking threads.

---

### Clash 2: Multi-Stage Redaction Sequence (AD-2 & AD-3) vs. Co-Reference Offsets (AD-6)
* **Components:** `src/redact.rs` Tier 1 (Regex Engine) vs. `src/redact.rs` Tier 2 (ML/NER Engine)
* **The Case for AD Compliance:**
  - `src/redact.rs` performs sequential redaction: Tier 1 Regex using precompiled patterns (**AD-3**) followed by Tier 2 ML inference (**AD-1**).
  - Both stages mutate prompt values in-place inside `serde_json::Value` (**AD-2**).
  - Both stages record replacements in an ephemeral translation map to preserve co-references (**AD-6**).
* **The Failure Mode (UTF-8 Slicing Panics & Semantic Degraded Recall):**
  - If Tier 1 (Regex) runs first and replaces a string (e.g., a phone number `555-1234` is replaced with `[REDACTED_PHONE_1]`), the overall length of the text shifts, invalidating the byte offsets of the remaining text.
  - If Tier 2 (ML) is run:
    - **Scenario A (Inference on Original Text):** The ML model outputs character spans based on the original prompt (e.g., name `John Doe` at index 25-33). When `src/redact.rs` tries to apply these spans to the already-mutated string, the indexes no longer align. This results in **UTF-8 character slicing panics** (slicing in the middle of a multi-byte character) or corruption (redacting the wrong text).
    - **Scenario B (Inference on Mutated Text):** The ML model processes the text containing `[REDACTED_PHONE_1]`. The model's neural network, trained on natural language, cannot parse these artificial redaction tokens, destroying the surrounding context and leading to degraded PII detection recall.
* **The Hole:** The Spine lacks an invariant on how character offset mapping is synchronized across multiple sequential redaction engines.
* **Resolution (New/Tightened AD):** Require that all redaction passes (Regex and ML) perform detection on the *immutable original* input string to accumulate raw offset spans. Merge and sort these spans in descending order, then apply the replacements in a single backward pass.

---

### Clash 3: Untyped JSON Interception (AD-2) vs. Ephemeral Translation Map Lifetime (AD-6)
* **Components:** `src/proxy.rs` (Interception Router) vs. `src/redact.rs` (Co-Reference Redactor)
* **The Case for AD Compliance:**
  - `src/proxy.rs` parses untyped JSON payload structures via `serde_json::Value` and iterates through the `messages` array in-place (**AD-2**).
  - `src/redact.rs` maintains an ephemeral per-request translation map `HashMap<String, String>` to replace identical PII strings with identical tokens (**AD-6**).
* **The Failure Mode (Borrow Checker Incompatibility vs. Cross-Message Leakage):**
  - To handle multiple message payloads efficiently, `src/proxy.rs` may attempt to parallelize the redaction of different messages in the array using `tokio::join!` or thread pools.
  - However, to satisfy the co-reference requirement (**AD-6**), all message redactions *across the entire request* must share the same translation map.
  - Since Rust's borrow checker prohibits sharing a mutable reference (`&mut HashMap`) across parallel asynchronous tasks, the developer must either:
    - Run the redaction sequentially, increasing latency linearly with the number of messages.
    - Wrap the translation map in an `Arc<Mutex<HashMap>>`, introducing lock contention and potential deadlocks under async load.
    - Create a new map per message, which directly violates **AD-6** by losing co-reference links across different messages in the same chat history.
* **The Hole:** The Spine does not define the data ownership model or concurrent access patterns for the request-scoped translation map.
* **Resolution (New/Tightened AD):** Define a thread-safe `RequestContext` wrapper that encapsulates the translation map (e.g., using `Arc<RwLock<TranslationMap>>` or a sequential worker design) to govern message processing.

---

### Clash 4: Transparent Proxy Routing (AD-7) vs. Fail-Closed Header Mismatches (AD-5 / AD-2)
* **Components:** `src/proxy.rs` (Upstream Forwarder) vs. `src/main.rs` (Routing and Middleware)
* **The Case for AD Compliance:**
  - `src/proxy.rs` forwards non-completion endpoints transparently to `UPSTREAM_URL` (**AD-7**).
  - Completion payloads are parsed, redacted, and reconstructed in-place (**AD-2**).
* **The Failure Mode (Mismatched Content-Length & Hop-by-Hop Header Clashing):**
  - For non-completion endpoints, if `src/proxy.rs` copies all HTTP headers from the incoming Axum request directly to the outgoing `reqwest::Request`, it will include hop-by-hop headers (e.g., `Connection`, `Keep-Alive`, `Transfer-Encoding`). This conflicts with `reqwest`'s connection pooling and causes requests to hang or fail.
  - For completions endpoints, redacting PII modifies the length of the JSON payload. If the incoming `Content-Length` header is forwarded unchanged, the upstream LLM gateway will either reject the request as malformed (`400 Bad Request`) or hang waiting for the remaining bytes that will never arrive.
  - Furthermore, forwarding the `Host` header unmodified causes upstream servers (like OpenAI) to reject the request due to TLS SNI mismatches.
* **The Hole:** The Spine specifies "transparent routing" without defining a hop-by-hop header removal policy or a header sanitization contract.
* **Resolution (New/Tightened AD):** Add an explicit rule to **AD-7**: "Strip all hop-by-hop headers (e.g. `Host`, `Connection`, `Keep-Alive`, `Transfer-Encoding`, `Content-Length`) and rewrite the `Host` header to match `UPSTREAM_URL` before forwarding. Recalculate `Content-Length` for all mutated payloads."

---

## 3. Actionable Recommendations for Closing the Holes

1. **Tighten AD-5 & AD-1:** Add a concurrency limiting policy for ML execution:
   > "Implement a bounded concurrency semaphore for all `tokio::task::spawn_blocking` inference calls. If the queue limit is reached, return HTTP `429 Too Many Requests` immediately without starting blocking CPU operations."
2. **Tighten AD-6:** Specify the multi-stage token replacement strategy:
   > "All redaction engines must operate on the immutable original string during the detection phase. All matches must be consolidated into a single descending-sorted index map of offset ranges before mutating the string in a single reverse pass."
3. **Tighten AD-7:** Define HTTP header mapping and stripping:
   > "When forwarding requests (both completion and pass-through), filter out hop-by-hop headers (including `Host`, `Connection`, `Transfer-Encoding`, and `Content-Length`). The forwarder must dynamically compute the payload size and apply a fresh `Content-Length` header."
