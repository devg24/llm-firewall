# PRD Quality Review — Guardian-AI

## Overall verdict
The PRD presents a clear, opinionated thesis for a stateless, high-performance PII redaction proxy. However, it is held back by a lack of testable boundaries (metrics, explicit acceptance criteria) and unacknowledged trade-offs (hardcoded configurations). It reads more like a strong technical pitch than an implementation-ready contract.

## Decision-readiness — thin
The document makes firm decisions (1-way redaction, hardcoded regex) but fails to surface the trade-offs honestly. It frames choices only by their benefits, leaving potential objections unaddressed.

### Findings
- **[high]** Unacknowledged trade-off in configuration (§ 3.2) — Hardcoding regex patterns is justified for "speed and simplicity", but the cost (requiring recompilation to update rules) is not named. *Fix:* Explicitly state the trade-off and confirm it's acceptable for the MVP.
- **[medium]** Downstream impact of 1-way redaction (§ 1, § 3.2) — The choice of 1-way redaction means the LLM's response won't have original PII re-injected. The PRD doesn't address how this affects the calling application's downstream logic. *Fix:* Add a note acknowledging this limitation and why it's accepted.

## Substance over theater — adequate
The PRD largely avoids theater, focusing on concrete technical components. However, its performance claims border on NFR theater without hardware context.

### Findings
- **[medium]** Unbounded latency claims (§ 2.1) — Claims "sub-10ms latency" alongside a BERT ML model in the loop. Without specifying the hardware (CPU vs GPU) or precision, this reads as an aspiration rather than an earned NFR. *Fix:* Bind the latency claim to a specific hardware profile and model quantization target.

## Strategic coherence — thin
The PRD has a strong thesis: Python is too slow and stateful, while Rust + Candle solves this. However, it completely lacks the Success Metrics needed to validate that thesis.

### Findings
- **[critical]** Missing Success Metrics (§ 2, § 3) — The entire value proposition rests on speed and accuracy, yet there are no metrics defined for latency (e.g., P99 overhead limit) or NER accuracy/recall. *Fix:* Add a Success Metrics section with specific, measurable targets for latency and PII catch rate.

## Done-ness clarity — thin
An engineer would struggle to know exactly when the features are "done" because the boundaries and acceptance criteria are too loose.

### Findings
- **[high]** Unspecified regex bounds (§ 3.2) — "Credit Cards, SSNs" is listed, but there are no verifiable conditions for which exact formats must be caught. *Fix:* Provide explicit acceptance criteria or standard format examples for the regex engine.
- **[medium]** Model ambiguity (§ 3.2) — Specifying "e.g., dslim/bert-base-NER or dslim/distilbert-NER" defers a crucial architectural decision to the engineer. *Fix:* Pick a specific model as the MVP target.
- **[low]** Subjective adjectives (§ 1, § 3.2) — Uses unmeasurable terms like "blazing-fast" and "zero-overhead". *Fix:* Replace with testable performance bounds.

## Scope honesty — thin
The PRD relies on the reader to infer omissions based on the architecture, rather than explicitly protecting the scope.

### Findings
- **[high]** Missing Non-Goals section — It is implied that stateful 2-way redaction, custom model training, and dynamic configuration are out of scope, but they are not documented as such. *Fix:* Add an explicit Non-Goals section to prevent scope creep.

## Downstream usability — adequate
As a standalone technical spec for an infrastructure tool, this PRD doesn't need heavy traceability. However, it lacks basic identifiers for its requirements.

### Findings
- **[low]** Missing FR Identifiers (§ 3.1, § 3.2) — Requirements are bullet points rather than tagged IDs (e.g., FR-01), making it harder to reference them in downstream tasks. *Fix:* Add contiguous IDs to all functional requirements.

## Shape fit — strong
The technical capability spec shape fits an infrastructure/proxy tool perfectly. User Journeys (UJs) are correctly omitted in favor of network flow descriptions and protocol support. No findings needed.

## Mechanical notes
- No Glossary present (terms like "1-way redaction" or "stateless" could use formal definitions).
- Missing assumption tags for things like expected request load.
