---
story_id: "3.4"
story_key: "3-4-advanced-detection-pipeline"
epic: 3
status: backlog
baseline_commit: ""
---

# Story 3.4: Advanced Detection Pipeline (Entropy, NER, Contextual)

## Story

**As a developer,**
I want to add the advanced Tiers (Entropy, NER, and Contextual Classification) adhering to the `Detector` trait,
**So that** complex, unstructured secrets are caught with high accuracy and low latency.

## Acceptance Criteria

- **AC1:** Given the orchestrator cascading through the detection tiers, when high-entropy strings or contextual PII are evaluated, then the orchestrator applies overlap resolution and confidence thresholds accurately.
- **AC2:** Tier 4 (Contextual/ONNX) executes ONLY on borderline confidence spans (0.5–0.7) to preserve sub-millisecond p99 latency.
- **AC3:** All tiers implement the `Detector` trait returning `Vec<Span>` with confidence scores.
- **AC4:** Automated benchmarks verify correct detection behavior against a golden test dataset (F1 ≥ 0.95 against carefully curated test cases).

## Tasks / Subtasks

- [x] **Task 1: Define `Detector` trait and `Span` type in `guardian-core`**
  - [x] 1a. Create `crates/guardian-core/src/detect.rs`
  - [x] 1b. Define `Span` struct: `{ start: usize, end: usize, text: String, confidence: f32, label: PiiType }`
  - [x] 1c. Define `Detector` trait: `fn detect(&self, text: &str) -> Vec<Span>` — synchronous for Tier 1/2 (must be fast), `async fn detect_async(&self, text: &str) -> Result<Vec<Span>, CoreError>` for Tier 3/4
  - [x] 1d. Export `Span`, `Detector` trait from `guardian-core/src/lib.rs`

- [x] **Task 2: Implement `RegexDetector` (Tier 1 wrapper)**
  - [x] 2a. In `detect.rs`, implement `RegexDetector` that wraps the existing `collect_regex_matches` function
  - [x] 2b. Maps `PiiMatch` → `Span` with `confidence = 1.0` (deterministic matches)
  - [x] 2c. Implements the `Detector` trait's `detect` method
  - [x] 2d. Unit tests verify `RegexDetector::detect("my email is test@example.com")` returns the correct span

- [x] **Task 3: Implement `EntropyDetector` (Tier 2)**
  - [x] 3a. In `detect.rs`, implement `EntropyDetector` struct
  - [x] 3b. Shannon entropy calculation function: H = -Σ(p_i * log2(p_i)) over character frequencies
  - [x] 3c. Slide a window of 20-32 chars across the text; compute entropy for each window
  - [x] 3d. Apply base64-alphabet heuristic: if charset is a-z, A-Z, 0-9, +, /, =, boost confidence
  - [x] 3e. Return spans where entropy > 4.0 bits/char (configurable threshold, default 4.0)
  - [x] 3f. Confidence = (entropy - 4.0) / 4.0, clamped to [0.0, 1.0]
  - [x] 3g. Minimum span length: 20 chars (short high-entropy strings are noise)
  - [x] 3h. Label: PiiType::Bearer (best available catch-all for high-entropy secrets)
  - [x] 3i. Unit tests: AWS key-like string (high entropy) → detected; normal words (low entropy) → not detected

- [x] **Task 4: Implement `NerDetector` (Tier 3 — BERT wrapper)**
  - [x] 4a. In `detect.rs`, implement `NerDetector` wrapping `run_inference` from `ml.rs`
  - [x] 4b. Implements `detect_async` (since `run_inference` is async)
  - [x] 4c. Maps `TokenClassification` → `Span`: B-PERSON, I-PERSON → PiiType::Email (closest available, or add PiiType::Person if needed), B-ORG, etc.
  - [x] 4d. The model is optional (`Option<Arc<SharedModel>>`); if None, returns empty Vec
  - [x] 4e. Confidence = `TokenClassification.score`
  - [x] 4f. Unit test: if model is not loaded, detect_async returns Ok(vec![]) — no panic

- [x] **Task 5: Implement Orchestrator with cascading logic**
  - [x] 5a. Create `crates/guardian-core/src/orchestrator.rs`
  - [x] 5b. `DetectionOrchestrator` struct holds: `RegexDetector`, `EntropyDetector`, `Option<NerDetector>`, threshold configs
  - [x] 5c. `orchestrate(text: &str, model: Option<Arc<SharedModel>>) -> Result<Vec<Span>, CoreError>` async function:
    1. Run `RegexDetector::detect(text)` → collect tier1_spans (confidence = 1.0)
    2. Run `EntropyDetector::detect(text)` → collect tier2_spans
    3. Run `NerDetector::detect_async(text)` if model available → collect tier3_spans
    4. Merge all spans, run `resolve_overlaps` (adapted for `Span` instead of `PiiMatch`)
    5. Filter: keep spans with confidence ≥ tier threshold (Tier 1: 1.0, Tier 2: 0.5, Tier 3: 0.6)
    6. Tier 4 (contextual): NOT implemented in this story (deferred, feature-flagged per Architecture Spine consistency convention)
  - [x] 5d. Export orchestrator from `lib.rs`
  - [x] 5e. Update `chat_completions_handler` to use `DetectionOrchestrator` instead of directly calling `process_completions_payload` (if model is present)

- [x] **Task 6: Wire orchestrator into `chat_completions_handler`**
  - [x] 6a. When `AppState.model` is `Some(model)`: use `DetectionOrchestrator::orchestrate` on the full message text
  - [x] 6b. The orchestrator output spans are passed to a new `redact_text_from_spans(text, spans, state, token_map)` function
  - [x] 6c. When `AppState.model` is `None`: fall back to existing `process_completions_payload_with_map` (Tier 1 only)
  - [x] 6d. All ML inference MUST be in `tokio::task::spawn_blocking` (already handled by `run_inference`)

- [x] **Task 7: Benchmark tests (golden dataset)**
  - [x] 7a. Create `crates/guardian-core/tests/detection_benchmarks.rs`
  - [x] 7b. Define a golden dataset of 20+ test cases:
    - True positives: emails, SSNs, AWS keys, high-entropy API keys, names (if NER available)
    - True negatives: normal text, code snippets, common words
  - [x] 7c. Compute precision, recall, F1 for `RegexDetector` and `EntropyDetector`
  - [x] 7d. Assert F1 ≥ 0.95 for `RegexDetector` on its golden cases
  - [x] 7e. `EntropyDetector` F1 ≥ 0.80 on entropy-specific golden cases (lower bar acceptable given probabilistic nature)

- [x] **Task 8: Full suite validation**
  - [x] 8a. `cargo test --workspace -- --quiet` passes
  - [x] 8b. `cargo clippy --workspace -- -D warnings` passes
  - [x] 8c. `cargo fmt --check` passes

## Dev Notes

### Architecture Context

**AD-14 (Trait-Based Detection Pipeline):** Every detection tier MUST implement a `Detector` trait returning `Vec<Span>`. The orchestrator owns tier ordering, cascade logic, threshold application, and overlap resolution. No individual tier applies its own threshold.

**AD-1 (ML Inference Isolation):** `NerDetector::detect_async` MUST call `run_inference` which already offloads to `tokio::task::spawn_blocking`. This constraint is already satisfied by the existing `ml.rs` implementation.

**AD-8 (Concurrency Bounding):** The semaphore in `SharedModel.inference_semaphore` already bounds BERT concurrency to 1. Do not add additional bounding layers.

**Tier 4 (Contextual/ONNX):** Per Architecture Spine, Tier 4 should be feature-flagged. Mark it as deferred with a `// TODO: Tier 4 (ONNX contextual classifier) - feature-flagged, see Architecture Spine` comment in orchestrator.rs. Do NOT implement it in this story.

### `Span` Design

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub text: String,       // The sensitive text being detected
    pub confidence: f32,    // 0.0 to 1.0
    pub label: PiiType,     // Best match type
}
```

### Shannon Entropy Implementation

```rust
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes { freq[b as usize] += 1; }
    let len = bytes.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}
```

### Tier 2 Window Sliding

```rust
const WINDOW_SIZE: usize = 28;  // length of a typical API key segment
const ENTROPY_THRESHOLD: f32 = 4.0;
const MIN_SPAN_LEN: usize = 20;

pub fn detect_entropy_spans(text: &str) -> Vec<Span> {
    let chars: Vec<char> = text.chars().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i + WINDOW_SIZE <= chars.len() {
        let window: String = chars[i..i + WINDOW_SIZE].iter().collect();
        let entropy = shannon_entropy(&window);
        if entropy > ENTROPY_THRESHOLD {
            // Expand to find full high-entropy region
            let mut end = i + WINDOW_SIZE;
            while end < chars.len() {
                let next_char = chars[end];
                if next_char.is_alphanumeric() || "+/=_-".contains(next_char) {
                    end += 1;
                } else { break; }
            }
            let span_text: String = chars[i..end].iter().collect();
            if span_text.len() >= MIN_SPAN_LEN {
                let confidence = ((entropy - ENTROPY_THRESHOLD) / 4.0).min(1.0);
                spans.push(Span { start: i, end, text: span_text, confidence, label: PiiType::Bearer });
            }
            i = end;
        } else { i += 1; }
    }
    spans
}
```

### Orchestrator Overlap Resolution

Extend `resolve_overlaps` to work with `Span` instead of `PiiMatch`, or convert between them. The sort and sweep algorithm is identical:
```rust
spans.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| {
    b.confidence.partial_cmp(&a.confidence).unwrap_or(Ordering::Equal)
}));
// Then greedy sweep as in resolve_overlaps
```

### Backward Compatibility

Story 3.4 changes the outbound detection path in `chat_completions_handler`. The existing `process_completions_payload` function must still compile and pass existing tests. The new orchestrator path is additive when `AppState.model` is `Some(...)`.

### NER → PiiType Mapping

NER entity types map to `PiiType`:
- `B-PERSON`, `I-PERSON` → need to add `PiiType::Person` (new variant) or use `PiiType::Email` as closest approximation. RECOMMENDATION: Add `PiiType::Person` to avoid incorrect type labels.
- `B-ORG`, `I-ORG` → `PiiType::Bearer` (generic catch-all)
- `B-GPE`, `I-GPE` (locations) → skip (not PII for our purposes)
- `O` → skip

### File Changes

**New:**
- `crates/guardian-core/src/detect.rs`
- `crates/guardian-core/src/orchestrator.rs`
- `crates/guardian-core/tests/detection_benchmarks.rs`

**Modified:**
- `crates/guardian-core/src/redact.rs` — add `redact_text_from_spans` function
- `crates/guardian-core/src/lib.rs` — export new modules
- `crates/guardian-proxy/src/proxy.rs` — use orchestrator when model available

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
