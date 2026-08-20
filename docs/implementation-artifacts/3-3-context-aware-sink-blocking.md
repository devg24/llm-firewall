---
story_id: "3.3"
story_key: "3-3-context-aware-sink-blocking"
epic: 3
status: done
baseline_commit: ""
---

# Story 3.3: Context-Aware Sink Blocking (Lookbehind Buffer)

## Story

**As a developer,**
I want the inbound mutator to analyze a rolling buffer of decoded text before re-injecting secrets,
**So that** prompt-injected LLM exfiltration attempts into dangerous sinks (like `curl`) are blocked.

## Acceptance Criteria

- **AC1:** Given an LLM generating a response that attempts to use a redacted secret in a dangerous context (e.g., a `curl` command), when the inbound mutator processes the stream, then it analyzes a ~512-byte rolling lookbehind buffer against heuristics.
- **AC2:** Heuristics account for evasion techniques (e.g., whitespace injection) and overlap resolution prevents boundary-splitting attacks.
- **AC3:** When a dangerous sink is detected in the lookbehind buffer, the secret is quarantined (replaced with `[QUARANTINED]` or simply the token) instead of re-injected.
- **AC4:** Explicit unit tests cover dangerous sink detection across chunk boundaries and overlapping chunks.

## Tasks / Subtasks

- [x] **Task 1: Define dangerous sink heuristics in `guardian-core`**
  - [x] 1a. Create `crates/guardian-core/src/sink.rs` with `DangerousSinkDetector` struct.
  - [x] 1b. Define Aho-Corasick patterns for: `curl`, `wget`, `fetch(`, `http://`, `https://`, `subprocess`, `eval(`, `exec(`, `os.system`
  - [x] 1c. Implement `is_dangerous_context(&self, buf: &str) -> bool` with whitespace/case normalization.
  - [x] 1d. Expose via `guardian-core/src/lib.rs`.

- [x] **Task 2: Integrate lookbehind buffer into SSE stream mutator**
  - [x] 2a. Add a `lookbehind: String` variable to the `stream!` closure state.
  - [x] 2b. Append the new content to `lookbehind`.
  - [x] 2c. Trim `lookbehind` to keep only the last ~512 bytes safely.
  - [x] 2d. Pass `&lookbehind` to `DangerousSinkDetector`.
  - [x] 2e. If dangerous context detected: emit `tracing::warn!` and SKIP the substitution.

- [x] **Task 3: Ensure evasion-resistant matching**
  - [x] 3a. Ensure `is_dangerous_context` lowers the case of the input buffer.
  - [x] 3b. Ensure `is_dangerous_context` collapses/strips whitespace.

- [x] **Task 4: Fragmented token boundary splitting**
  - [x] 4a. Because `lookbehind` is updated across SSE events, ensure that a sink command split across two events is detected.

- [x] **Task 5: Full suite validation & Tests**
  - [x] 5a. Unit tests in `sink.rs`
  - [x] 5b. Integration test in `sse_passthrough.rs`
  - [x] 5c. `cargo test --workspace -- --quiet` passes.
  - [x] 5d. `cargo clippy --workspace -- -D warnings` passes.

- [ ] **Task 6: Full suite validation**
  - [ ] 6a. `cargo test --workspace -- --quiet` passes
  - [ ] 6b. `cargo clippy --workspace -- -D warnings` passes
  - [ ] 6c. `cargo fmt --check` passes

## Dev Notes

### Architecture Constraint AD-16

**AD-16 (Lookbehind Context Scanning):** Before re-injecting a secret on the inbound stream, the mutator MUST analyze a rolling lookbehind buffer (~512 bytes) of decoded output against dangerous sink heuristics. Dangerous sinks trigger quarantine instead of re-injection.

### Sink Detection Design

The sink detector must be:
1. **Fast**: runs per-event on every token match — must be sub-millisecond
2. **Evasion-resistant**: whitespace collapse, case-insensitive
3. **Not regex**: use `aho-corasick` for multi-pattern matching (already a dependency after Story 3.2)

```rust
// In guardian-core/src/sink.rs

pub const DANGEROUS_SINK_PATTERNS: &[&str] = &[
    "curl", "wget", "fetch(", "http://", "https://",
    "subprocess", "eval(", "exec(", "os.system", "powershell",
    "cmd.exe", "bash -c", "sh -c",
];

pub struct DangerousSinkDetector {
    ac: AhoCorasick,
}

impl DangerousSinkDetector {
    pub fn new() -> Self {
        Self {
            ac: AhoCorasick::new(DANGEROUS_SINK_PATTERNS).unwrap(),
        }
    }
    
    pub fn is_dangerous_context(&self, text: &str) -> bool {
        let normalized = normalize_for_sink_check(text);
        self.ac.is_match(&normalized)
    }
}

fn normalize_for_sink_check(text: &str) -> String {
    // Lowercase, collapse whitespace
    let lowercased = text.to_lowercase();
    lowercased.split_whitespace().collect::<Vec<_>>().join(" ")
}
```

### Lookbehind Buffer Management

```rust
// In stream! closure state:
let mut lookbehind = String::new();
const LOOKBEHIND_MAX: usize = 512;

// After extracting content from SSE event:
lookbehind.push_str(&decoded_content);
// Trim to last LOOKBEHIND_MAX bytes (UTF-8 safe)
if lookbehind.len() > LOOKBEHIND_MAX {
    let excess = lookbehind.len() - LOOKBEHIND_MAX;
    // Find a safe UTF-8 boundary to drain from
    let split_at = lookbehind
        .char_indices()
        .find(|(i, _)| *i >= excess)
        .map(|(i, _)| i)
        .unwrap_or(lookbehind.len());
    lookbehind.drain(..split_at);
}
```

### Quarantine Behavior

When dangerous context is detected, the token is NOT replaced:
- The stream emits the text with the `[REDACTED_*]` token still in place
- A warning is logged (with token name, NOT the secret value — never log secrets)
- This behavior protects against prompt injection attacks where LLM tries to exfiltrate via shell commands

### File Changes

**New:**
- `crates/guardian-core/src/sink.rs`

**Modified:**
- `crates/guardian-core/src/lib.rs` — export `DangerousSinkDetector`
- `crates/guardian-proxy/src/proxy.rs` — integrate lookbehind buffer into stream! closure
- `crates/guardian-proxy/tests/sse_passthrough.rs` — add sink blocking tests

### Previous Story Dependencies

This story DEPENDS on Story 3.2's `TokenMap` re-injection being complete. The lookbehind check is inserted as a gate BEFORE the re-injection step established in Story 3.2.

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
