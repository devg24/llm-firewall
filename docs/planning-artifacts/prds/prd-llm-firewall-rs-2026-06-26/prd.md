---
title: Guardian-AI (MVP / v1 - ARCHIVED)
created: 2026-06-26
updated: 2026-08-25
status: superseded
superseded_by: docs/specs/spec-guardian-ai-v2/SPEC.md
---

> [!WARNING]
> **ARCHIVED / SUPERSEDED DOCUMENT**
> This document describes the initial v1 MVP (one-way stateless PII proxy). It has been superseded by the v2 specification: [SPEC-guardian-ai-v2](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/specs/spec-guardian-ai-v2/SPEC.md). Please refer to the v2 specification for current product requirements and capabilities.

# PRD: Guardian-AI (v1 MVP)

## 0. Document Purpose
This document specifies the requirements for the initial v1 MVP of Guardian-AI.

## 1. Vision
Guardian-AI is a blazing-fast, zero-overhead reverse proxy written in Rust designed to sit between enterprise applications and Large Language Model (LLM) APIs. Its primary purpose is to intercept network traffic and perform stateless 1-way redaction of sensitive data (PII) using a locally quantized token-classification model. This ensures no sensitive data ever reaches external APIs like OpenAI or Anthropic, unblocking GenAI adoption for strict compliance environments.

## 2. Target User

### 2.1 Jobs To Be Done
- Provide developers a drop-in replacement for OpenAI endpoints that automatically strips PII.
- Ensure security and compliance teams that no direct PII leaves the enterprise boundary.
- Process requests fast enough that end-users do not perceive any added latency.

### 2.2 Non-Users (v1)
- End-users requiring 2-way stateful redaction (where the LLM response re-injects the original PII).
- Teams needing dynamic, hot-swappable redaction rules without binary recompilation.

### 2.3 Network Flows
*Note: Standard User Journeys are omitted in favor of network protocol flows for this infrastructure product.*

- **Flow 1. Transparent Proxying**: An enterprise app sends an HTTP request to an endpoint other than `POST /v1/chat/completions`. Guardian-AI acts as a transparent proxy, forwarding the request unmodified and returning the response.
- **Flow 2. PII Redaction Pipeline**: An enterprise app sends a `POST /v1/chat/completions` request. Guardian-AI intercepts it, extracts the OpenAI API key from the `Authorization` header, applies Tier 1 Regex and Tier 2 ML redaction to the payload, rebuilds the JSON, and forwards it to OpenAI. The redacted response is sent back to the app.

## 3. Glossary
- **1-way redaction** — A process where sensitive data is replaced with semantic tokens (e.g., `[REDACTED_NAME]`) before sending to an LLM, and the original data is *not* restored when the LLM responds.
- **Stateless** — The proxy retains no memory, cache, or state of the requests it processes, allowing for infinite horizontal scaling.
- **Direct PII** — Information that directly identifies an individual (e.g., SSN, Email, Phone Number).
- **Indirect PII** — Information that can be linked to an individual (e.g., IP Address).

## 4. Features

### 4.1 The Interception Engine
**Description:** The core HTTP server that listens for incoming traffic, manages API keys, and routes requests either through the firewall pipeline or directly to the upstream LLM API.

**Functional Requirements:**

#### FR-1: Transparent Fallback Routing
The system must pass requests to endpoints other than `POST /v1/chat/completions` through to the upstream API unmodified.

#### FR-2: API Key Passthrough
The system must extract the OpenAI API key from the incoming request's `Authorization` header and forward it transparently to the LLM API provider. No centralized key management is maintained.

#### FR-3: Configurable Port
The system must read its listening port from the `PORT` environment variable, defaulting to `3000` if unset.

### 4.2 Security Pipeline (The "Firewall")
**Description:** The two-tier redaction engine that sanitizes JSON payloads before forwarding them.

**Functional Requirements:**

#### FR-4: Tier 1 Regex Redaction
The system must use a hardcoded regex engine to identify and replace strict PII formats (US SSNs, Credit/Debit Cards, Email Addresses, Phone Numbers, and IP Addresses) with semantic tokens (e.g., `[REDACTED_SSN]`).

#### FR-5: Tier 2 ML Semantic Redaction
The system must use a locally hosted, highly quantized standard NER model (e.g., `dslim/bert-base-NER`) running via `candle-core` to redact contextual PII (Names, Organizations).

#### FR-6: 1-Way Payload Rebuilding
The system must rebuild the `POST /v1/chat/completions` JSON payload with the redacted string and forward it to OpenAI using `reqwest`.

### 4.3 Observability
**Description:** Logging and tracing for the proxy.

**Functional Requirements:**

#### FR-7: Asynchronous Logging
The system must use the `tracing` crate to output structured, asynchronous logs at `info`, `debug`, and `error` levels.

## 5. Non-Goals (Explicit)
- **Stateful 2-way redaction:** Re-injecting original PII into the LLM's response is strictly out of scope. The downstream app must handle `[REDACTED_*]` tokens.
- **Dynamic rule configuration:** Reading regex patterns from external databases or config files at runtime is out of scope. Rules are hardcoded for speed.
- **Custom model training:** Fine-tuning or training custom NER models is out of scope. We will use standard, lightweight off-the-shelf models.

## 6. MVP Scope

### 6.1 In Scope
- Axum HTTP server with transparent routing and API key passthrough.
- Hardcoded Tier 1 Regex engine targeting strict formats (SSN, CC, Email, Phone, IP).
- Tier 2 ML engine using `candle-core` and `.safetensors`.
- 1-way payload rebuilding and forwarding.

### 6.2 Out of Scope for MVP
- Admin dashboard or UI.
- Support for Anthropic and Gemini LLM APIs (these are v1.1 stretch goals; MVP strictly targets OpenAI-compatible `/v1/chat/completions`).

## 7. Success Metrics
**Primary**
- **SM-1: Latency Overhead**: The P99 latency overhead introduced by the proxy must be < 25ms (flexible target). Validates FR-4, FR-5.
- **SM-2: PII Catch Rate (Recall)**: The combined Tier 1 and Tier 2 engines must achieve "best-effort" recall for MVP, prioritizing zero semantic loss and minimizing false positives over perfect coverage. Validates FR-4, FR-5.

## 8. Open Questions
- None.

## 9. Assumptions Index
- None.
