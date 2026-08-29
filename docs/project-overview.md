# Project Overview

## LLM Firewall
An intelligent proxy for intercepting and redacting sensitive PII from requests made to LLM APIs (e.g., OpenAI's `/v1/chat/completions`).

## Executive Summary
LLM Firewall provides a seamless security layer by acting as a Man-in-the-Middle (MITM) proxy for LLM clients. It uses local machine learning (via Candle) to perform token-level entity recognition and redaction, ensuring that sensitive data never leaves the local network while preserving the format and flow of server-sent events (SSE).

## Tech Stack Summary
| Category | Technology | Version | Justification |
|----------|------------|---------|---------------|
| Language | Rust       | 1.85.0  | Performance, safety |
| Proxy | Axum / Hyper | - | Robust async HTTP handling |
| ML / Inference | Candle | 0.10.2 | Local in-memory inference |
| TLS | rustls | 0.23 | Fast, safe TLS termination |

## Architecture Classification
- **Type**: Backend Proxy Service
- **Pattern**: Service/API-centric MITM

## Repository Structure
- **Type**: Monolith (Cargo Workspace)
- Composed of `guardian-core`, `guardian-proxy`, and `guardian-cli` crates.

## Documentation Links
- [Architecture](./architecture.md)
- [Source Tree Analysis](./source-tree-analysis.md)
- [Development Guide](./development-guide.md)
- [Deployment Guide](./deployment-guide.md)
- [API Contracts](./api-contracts-root.md)
- [Data Models](./data-models-root.md)
