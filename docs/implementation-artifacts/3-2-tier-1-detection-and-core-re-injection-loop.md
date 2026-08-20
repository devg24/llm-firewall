---
story_id: "3.2"
story_key: "3-2-tier-1-detection-and-core-re-injection-loop"
epic: 3
status: done
baseline_commit: ""
---

# Story 3.2: Tier 1 Detection & Core Re-injection Loop

## Story

**As a developer,**
I want to integrate the deterministic Tier 1 Regex engine and mutate the inbound stream to restore caught secrets,
**So that** the core end-to-end "swap and restore" loop is fully functional.

## Acceptance Criteria

- **AC1:** Given an outbound request containing deterministic PII (e.g., an email or SSN), when the request passes through the proxy, then the PII is replaced with a token outbound and stored in the `TokenMap`.
- **AC2:** The inbound mutator uses high-level async stream combinators to perfectly re-inject the secret into the LLM's response.
- **AC3:** The proxy injects a system prompt instruction (via AD-11) commanding the LLM not to mutate or lowercase `[REDACTED_*]` tokens.
- **AC4:** The mutator restricts its token search strictly to the `content` JSON fields, safely ignoring raw binary or base64 data.
- **AC5:** The mutator correctly buffers overlapping SSE chunks to handle fragmented tokens (e.g., `[REDACTE` in chunk 1, `D_SSN_1]` in chunk 2).
- **AC6:** Tests explicitly verify 1-way payload redaction and exact inbound restoration.

## Tasks / Subtasks

- [x] **Task 1: Populate `TokenMap` from `RedactionState` in the outbound phase**
  - [x] 1a. Modify `process_completions_payload` (or create a new `process_and_map` variant) to accept a mutable `TokenMap` and populate it with reverse mappings (token → original value) alongside the existing `RedactionState` forward mapping
  - [x] 1b. The signature should be: `pub fn process_completions_payload_with_map(payload: &mut Value, token_map: &mut TokenMap) -> Result<(), CoreError>`
  - [x] 1c. Keep the existing `process_completions_payload` working (backward-compat) OR replace it — check which is cleaner given Story 3.1's changes
  - [x] 1d. Update `chat_completions_handler` to call the new function, passing the `Arc<Mutex<TokenMap>>`'s locked reference
  - [x] 1e. Write unit tests verifying that after processing, `TokenMap` contains correct reverse mappings for each redacted PII

- [x] **Task 2: Inject system prompt guard instruction (AD-11)**
  - [x] 2a. Before forwarding the request, prepend a system message to the `messages` array: `{"role": "system", "content": "IMPORTANT: Do not alter, mutate, lowercase, or reformulate any token matching the pattern [REDACTED_*]. These tokens are placeholders and must be preserved exactly as-is."}`
  - [x] 2b. Only inject if a system message does not already exist at index 0 — if one does, PREPEND the instruction to its content
  - [x] 2c. If the user's messages array is empty, skip injection (defensive)
  - [x] 2d. Tests verify the system prompt is injected correctly in both cases (existing system msg vs. none)

- [x] **Task 3: Implement inbound SSE token re-injection**
  - [x] 3a. Add `aho-corasick = "1.1.3"` to `guardian-proxy/Cargo.toml` [dependencies] (for multi-pattern search)
  - [x] 3b. In the SSE `stream!` closure (from Story 3.1), after buffering/emitting each SSE event's bytes, extract the JSON `content` field from `data: {...}\n\n` events
  - [x] 3c. Use `aho-corasick` (or string scanning) to find any `[REDACTED_*]` tokens in the content field
  - [x] 3d. For each found token, look up the original value in `TokenMap` (lock, get, drop lock — no await while holding lock)
  - [x] 3e. Replace the token with the original value in the content field
  - [x] 3f. Re-serialize the modified event and yield it
  - [x] 3g. Events that fail JSON parse (e.g., `data: [DONE]`) must be passed through unchanged

- [x] **Task 4: Fragmented token reassembly**
  - [x] 4a. Maintain a `fragment_buf: String` of the last ~64 bytes of text content seen across SSE events
  - [x] 4b. When scanning for `[REDACTED_*]` tokens, check if the current event begins mid-token (i.e., fragment_buf ends with `[REDACT` or similar)
  - [x] 4c. Use a "lookforward buffer": if event content contains an opening `[REDACT` without a closing `]`, buffer the partial token and combine with the next event's content
  - [x] 4d. Tests explicitly cover: full token in one chunk, token split across two chunks, token split across three chunks

- [x] **Task 5: Integration tests for end-to-end swap-and-restore**
  - [x] 5a. In `crates/guardian-proxy/tests/sse_passthrough.rs` (or a new file), add tests:
  - [x] 5b. Test: outbound request with email → token in upstream-facing request; inbound SSE echoes token → original email in client response
  - [x] 5c. Test: SSN redacted outbound, token in LLM response split across 2 SSE chunks → original SSN fully restored in client response
  - [x] 5d. Test: `data: [DONE]\n\n` event passes through unchanged
  - [x] 5e. Test: system prompt injection present in forwarded request

- [x] **Task 6: Full suite validation**
  - [x] 6a. `cargo test --workspace -- --quiet` passes
  - [x] 6b. `cargo clippy --workspace -- -D warnings` passes
  - [x] 6c. `cargo fmt --check` passes

## Dev Notes

### Architecture Context

**AD-9 (Analysis-First Mutation):** Collect ALL spans first, then mutate. Do not mutate while scanning — the outbound `process_completions_payload_with_map` function already handles this correctly via `collect_regex_matches` → `resolve_overlaps` → `redact_text`.

**AD-15 (High-Level Async Stream Mutation):** The inbound re-injection MUST happen inside the `stream!` macro — same pattern established in Story 3.1. Never use manual `poll_next`.

**Mutex Safety:** In the SSE `stream!` closure, to read from TokenMap:
```rust
let replacement = {
    let lock = token_map.lock().unwrap();
    lock.get(token_str).map(|(secret, _)| secret.clone())
};
// Use `replacement` here without holding the lock
```

### Existing Infrastructure (from Story 3.1)

After Story 3.1, `chat_completions_handler` will:
1. Read body, call `process_completions_payload` (outbound redaction with LOCAL RedactionState)
2. Instantiate `Arc<Mutex<TokenMap>>`
3. Detect SSE, use `stream!` for SSE passthrough

Story 3.2 changes step 1 to populate the `TokenMap` with reverse mappings, then the `stream!` closure in step 3 uses the `TokenMap` for re-injection.

### `process_completions_payload_with_map` Design

The cleanest approach: modify `process_completions_payload` to additionally accept a `&mut TokenMap` parameter, and inside `redact_text` (or at the `get_or_create_token` call site), insert the reverse mapping:

```rust
// In redact.rs, modify redact_text or RedactionState to accept a &mut TokenMap
pub fn redact_text_with_map(
    text: &str,
    matches: &[PiiMatch],
    state: &mut RedactionState,
    token_map: &mut TokenMap,
) -> String {
    // ... for each match:
    let token = state.get_or_create_token(&m.value, m.pii_type);
    token_map.insert(token.clone(), m.value.clone(), m.pii_type); // reverse mapping
    // ...
}
```

Or alternatively, expose `RedactionState.map` and derive the TokenMap from it after processing.

### SSE Content Extraction

SSE events look like:
```
data: {"id":"...","choices":[{"delta":{"content":"Hello"}}]}\n\n
data: {"id":"...","choices":[{"delta":{"content":" World"}}]}\n\n
data: [DONE]\n\n
```

To extract content for token scanning:
1. Strip `data: ` prefix
2. Attempt `serde_json::from_str::<Value>(line_without_prefix)`
3. If parse succeeds: access `.choices[0].delta.content` (or `.choices[0].message.content`)
4. If parse fails (e.g., `[DONE]`): pass through unchanged
5. ONLY scan/replace inside `content` fields — never in raw JSON keys, IDs, etc. (AC4)

### Aho-Corasick for Token Scanning

```rust
use aho_corasick::AhoCorasick;

// Build the automaton from all known tokens in the TokenMap
// (Do this lazily or per-event since TokenMap grows as PII is found)
let tokens: Vec<String> = {
    let lock = token_map.lock().unwrap();
    lock.keys().cloned().collect()
    // keys() would need to be added to TokenMap
};
if !tokens.is_empty() {
    let ac = AhoCorasick::new(&tokens).unwrap();
    // Use ac.replace_all(content, &replacements)
}
```

Note: `AhoCorasick::new` is cheap for small token sets (typically < 20 tokens per request).

### Fragmented Token Buffer

The max token length is `[REDACTED_BEARER_99]` = ~22 chars. A 64-byte fragment buffer is sufficient.

```rust
// State maintained in the stream! closure across events:
let mut partial_token: String = String::new(); // accumulates partial [REDACT... tokens

// When processing content:
let to_scan = partial_token.clone() + &content;
if let Some(incomplete_start) = to_scan.rfind("[REDACT") {
    // Check if this potential token has a closing ]
    if !to_scan[incomplete_start..].contains(']') {
        partial_token = to_scan[incomplete_start..].to_string();
        content = to_scan[..incomplete_start].to_string();
    } else {
        partial_token.clear();
        // use full to_scan for replacement
    }
}
```

### File Changes

**Modified:**
- `crates/guardian-core/src/redact.rs` — add `redact_text_with_map` or modify `process_completions_payload` to accept `&mut TokenMap`
- `crates/guardian-core/src/token_map.rs` — add `keys()` or `iter()` method
- `crates/guardian-core/src/lib.rs` — export any new functions
- `crates/guardian-proxy/src/proxy.rs` — update `chat_completions_handler` for system prompt injection and re-injection
- `crates/guardian-proxy/Cargo.toml` — add `aho-corasick = "1.1.3"`
- `crates/guardian-proxy/tests/sse_passthrough.rs` — add re-injection tests

## Dev Agent Record

### Implementation Plan
_To be filled by dev agent_

### Debug Log
_To be filled by dev agent_

### Completion Notes
_To be filled by dev agent_

## File List
- `crates/guardian-core/src/lib.rs`
- `crates/guardian-core/src/redact.rs`
- `crates/guardian-core/src/token_map.rs`
- `crates/guardian-proxy/Cargo.toml`
- `crates/guardian-proxy/src/proxy.rs`
- `crates/guardian-proxy/tests/integration_tests.rs`
- `crates/guardian-proxy/tests/sse_passthrough.rs`

## Change Log
- Modified `TokenMap` to expose `keys()`
- Added `process_completions_payload_with_map` to `redact.rs` and exported it via `lib.rs`
- Updated `proxy.rs` to populate `TokenMap` on outbound request
- Injected system prompt guard instruction in outbound request payload
- Added `aho-corasick` dependency to `guardian-proxy/Cargo.toml`
- Implemented SSE inbound token re-injection in `proxy.rs` inside stream loop, with fragmented token reassembly
- Fixed `test_proxy_chat_completions_complex` in `integration_tests.rs` to accommodate injected system prompt
- Added E2E swap-and-restore and fragmented token reassembly tests in `sse_passthrough.rs`
