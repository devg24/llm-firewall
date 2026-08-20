# Detection Pipeline — Guardian-AI v2

Companion to [SPEC.md](./SPEC.md). Details the 4-tier cascading detection architecture referenced by CAP-2, CAP-3, and CAP-9.

## Pipeline Architecture

```
Input text
  │
  ▼
┌─────────────────────────────────┐
│ Tier 1: Pattern Matching        │  ← Aho-Corasick automaton + regex
│ Cost: ~0.01ms per KB            │     Known formats only
│ Confidence: 1.0 (deterministic) │     Bypasses threshold entirely
└──────────────┬──────────────────┘
               │ unmatched spans
               ▼
┌─────────────────────────────────┐
│ Tier 2: Contextual Entropy      │  ← Shannon entropy + context
│ Cost: ~0.05ms per KB            │     heuristics + domain profile
│ Threshold: per-domain (0.6 def) │     adjustment
└──────────────┬──────────────────┘
               │ unmatched spans
               ▼
┌─────────────────────────────────┐
│ Tier 3: Named Entity Recognition│  ← Quantized BERT NER via Candle
│ Cost: ~2–5ms per KB (blocking)  │     Person, Org, Location, Misc
│ Threshold: per-tier (0.7 def)   │     Confidence from model logits
└──────────────┬──────────────────┘
               │ borderline spans only (0.5–0.7)
               ▼
┌─────────────────────────────────┐
│ Tier 4: Context-Aware Classifier│  ← Tree model or quantized encoder
│ Cost: 10–25ms per span          │     via ort (ONNX Runtime)
│ Input: filepath + AST + context │     Only executes on ambiguous spans
└──────────────┬──────────────────┘
               │
               ▼
        Per-tier threshold check
     (each tier uses own threshold)
               │
               ▼
     Overlap merge (tie-breaker:
     highest relative confidence gap
     above per-tier threshold)
               │
               ▼
        Redaction pass
```

## Tier 1: Pattern Matching (Aho-Corasick + Regex)

**Upgrade from current:** Replace sequential regex evaluation with an Aho-Corasick automaton for O(n) simultaneous multi-pattern matching across all known secret formats.

**Patterns:**
- US Social Security Numbers (strict format)
- Credit card numbers (Luhn-validated)
- Email addresses
- Phone numbers (US/international)
- IP addresses (IPv4/IPv6)
- Known API key prefixes (`sk-`, `AKIA`, `ghp_`, `glpat-`, `xoxb-`, etc.)
- Connection strings (`postgres://`, `mongodb://`, `redis://`)
- Private key headers (`-----BEGIN RSA PRIVATE KEY-----`)

**Confidence:** Fixed at 1.0. Deterministic patterns bypass the threshold system entirely. If Aho-Corasick matches and Luhn validates, redaction is unconditional.

## Tier 2: Contextual Entropy Analysis

**The differentiator.** Catches secrets with no known format by combining information-theoretic scoring with local context awareness.

**Algorithm:**
1. Slide a character window (default: 16–64 chars) across input text.
2. Compute Shannon entropy per window. Flag windows exceeding threshold (default: 4.5 bits/char for alphanumeric, 3.5 for hex).
3. For each flagged window, read surrounding context (±50 chars):

| Context Signal | Confidence Adjustment |
|---|---|
| Adjacent to `api_key=`, `secret:`, `password`, `token`, `credential` | +0.4 |
| Inside `.env`, `config.yml`, `*.toml` `[secrets]` section | +0.3 |
| Matches UUID format (`8-4-4-4-12`) | → Suppress (set 0.05) |
| Inside `data:image/*;base64,` URI | → Suppress (set 0.05) |
| Inside a known hash column in SQL migration | → Suppress (set 0.1) |
| No contextual signal | Baseline 0.5 |

4. Assign final confidence score (0.0–1.0). Redact if above per-tier threshold.

**Domain-sensitive thresholds (via CAP-9):**

| Detected Domain | Default Tier 2 Threshold | Rationale |
|---|---|---|
| Standard web app | 0.6 | High-entropy strings are likely secrets |
| Crypto / blockchain (`ethers`, `solana`, `web3`) | 0.85 | Codebases full of public keys, test hashes, hex dumps |
| Data science / ML (`numpy`, `torch`, `tensorflow`) | 0.7 | Model weight hashes, encoded tensors are common |
| Healthcare (`hl7`, `fhir`) | 0.5 | Extra caution — PHI patterns are high-value targets |

**Benchmarking target:** ≥90% recall on unknown-format secrets, ≤5% false positive rate on safe high-entropy strings.

## Tier 3: Named Entity Recognition (Quantized BERT)

**Current implementation:** Already exists via `candle-core` with `dslim/bert-base-NER`. Runs as CPU-bound blocking task isolated from async workers via `tokio::task::spawn_blocking`.

**Upgrade path:**
- Extract confidence scores from model logits instead of binary classification.
- Benchmark quantized vs. full-precision F1 tradeoff.
- Profile and optimize tokenization overhead.

**Entity types:** PERSON, ORGANIZATION, LOCATION, MISCELLANEOUS.

**Inference runtime:** `candle-core` (already integrated). No change to runtime for this tier.

## Tier 4: Context-Aware Classifier

**Execution condition:** Only executes on spans that pass lower tiers with borderline confidence (0.5–0.7). This limits inference to a small fraction of total spans, keeping the latency impact bounded.

**Model architecture options (in priority order):**
1. **Tree-based model (XGBoost/LightGBM)** — trained in Python, exported to ONNX, run via `ort` in Rust. Fastest inference (~1–5ms), smallest binary size.
2. **Quantized encoder (DeBERTa-v3-mini / ModernBERT)** — exported to ONNX, run via `ort`. Higher accuracy on nuanced cases, 10–25ms budget.

**Inference runtime:** `ort` (ONNX Runtime for Rust). Preferred over `xgboost` Rust crate (thin FFI wrapper, limited ecosystem maturity). Train in Python → export ONNX → run in Rust. Single runtime for both tree and encoder models.

**Feature input (structured, not raw text):**

| Feature | Source | Example |
|---|---|---|
| `filepath` | Request context | `config/production.yml` vs `tests/auth.rs` |
| `ast_node_type` | `tree-sitter` parsing | `let mock_token = ...` vs `export API_KEY=...` |
| `context_text` | ±128 chars around span | Surrounding code/comments |
| `file_extension` | Filepath | `.env`, `.yml`, `.rs`, `.md` |
| `directory_signal` | Filepath components | `tests/`, `fixtures/`, `docs/`, `examples/` |

**Training dataset strategy:**
- **Positive samples (real secrets):** Mine CodeSearchNet / Stack v2 for commits quickly followed by key-rotation or "remove secret" commits.
- **Negative samples (safe contexts):** Extract high-entropy strings from known test directories (`tests/`, `spec/`), documentation (`README.md`, `docs/`), and mock JSON fixtures.
- **Augmentation:** Synthetic secrets injected into safe contexts and vice versa to test boundary discrimination.

**Latency budget:** 10–25ms per borderline span. Does not block the async event loop (runs via `tokio::task::spawn_blocking`).

## Streaming Re-injection (Inbound Direction)

LLM providers stream responses via Server-Sent Events (SSE). Placeholder tokens like `[GUARDIAN_UUID_1]` may span SSE event boundaries.

**Algorithm: Stateful Streaming Aho-Corasick with Hold-back Window**

1. Parse each SSE event and extract the `data:` payload. Operate on parsed payloads, never raw TCP bytes (preserves SSE framing integrity).
2. Feed payload bytes into a stateful Aho-Corasick automaton tracking all active placeholder tokens.
3. If the automaton reaches a partial match state at the end of an SSE event:
   - **Withhold** the partially-matched bytes from the outbound stream.
   - Buffer them in a fixed-size ring buffer (sized to maximum placeholder token length).
4. When the next SSE event arrives:
   - Continue feeding the automaton.
   - **Match completes:** Swap placeholder for the real secret from the in-memory token index. Flush to stream.
   - **Match fails:** Flush the withheld bytes immediately (they were not a placeholder).
5. Re-serialize the modified payload back into SSE `data:` format before forwarding.

**Zero-allocation guarantee:** The ring buffer is stack-allocated at the maximum placeholder token length. No dynamic memory allocation on the hot path.

## Per-Tier Threshold Architecture

```rust
struct ThresholdConfig {
    tier2_entropy: f64,     // default: 0.6, domain-adjusted
    tier3_ner: f64,         // default: 0.7
    tier4_classifier: f64,  // default: 0.6
    tier4_trigger_range: (f64, f64), // default: (0.5, 0.7) — borderline zone
}
```

- **Tier 1:** No threshold. Deterministic match → unconditional redaction.
- **Tier 2:** Domain-sensitive (see domain table above). Auto-adjusted by CAP-9.
- **Tier 3:** Per-tier default 0.7. Logit-derived confidence from BERT.
- **Tier 4:** Only invoked when prior tiers produce scores in `tier4_trigger_range`. Its own threshold (default 0.6) determines final redaction.

**Overlap merge (tie-breaker):** When multiple tiers flag the same span, use the boundary defined by the tier with the highest *relative confidence gap above its own threshold*. Example: Tier 2 scores 0.75 (gap = 0.15 above 0.6) vs Tier 3 scores 0.80 (gap = 0.10 above 0.7) → Tier 2 wins the boundary decision.

## Golden Dataset Requirements

A versioned test corpus (`tests/golden/`) containing:
- Known-format secrets (Tier 1 targets): ≥50 examples per pattern type
- Unknown-format secrets (Tier 2 targets): ≥30 generated API keys, tokens, passwords
- Named entities (Tier 3 targets): ≥50 names, orgs, addresses in code comments and strings
- Contextually ambiguous spans (Tier 4 targets): ≥30 real-vs-mock secret pairs in different file contexts
- Safe high-entropy strings (false-positive candidates): UUIDs, base64 images, bcrypt hashes, hex digests
- Domain-specific safe strings: crypto public keys, ML model hashes, blockchain test fixtures
- Realistic code context: `.env` files, `config.yml`, README examples, SQL migrations, test fixtures

Each entry labeled with expected detection tier, expected confidence range, ground-truth classification (secret/safe), and domain tag.
