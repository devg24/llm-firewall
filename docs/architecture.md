# Architecture

## Executive Summary
LLM Firewall is a backend Rust application that acts as a MITM proxy to intercept, detect, and redact PII in LLM API calls, specifically targeting the `/v1/chat/completions` endpoint. It leverages Candle ML for in-memory inference to perform token-level classification without relying on external services.

## Technology Stack
- **Language**: Rust 1.85.0
- **Frameworks**: Axum, Hyper, Tower for proxy and routing.
- **ML/Inference**: Candle (core, nn, transformers).
- **Runtime**: Tokio async runtime.
- **Network**: rustls for TLS interception, rcgen for certificate generation.

## Architecture Pattern
Service/API-centric architecture functioning as a MITM Proxy. It intercepts requests, decrypts them, applies streaming transformations (modifying SSE streams on the fly), and re-encrypts the connection to the upstream target.

## Data Architecture
Core structures model configurations, security policies, and ML classifications. No relational database ORM is present.
- `GuardianConfig`, `RegexConfig`, `AllowlistConfig`
- `SharedModel`, `TokenClassification` (ML)
- `Span`, `PiiMatch`, `RedactionState`

## API Design
- `GET /health` : Liveness check
- `POST /v1/chat/completions` : The primary intercepted route for redaction
- `ANY /{*path}` : Passthrough route for non-chat endpoints

## Source Tree
- `crates/guardian-core/`: ML, detection, core models
- `crates/guardian-proxy/`: HTTP Proxy routing, stream transformation
- `crates/guardian-cli/`: Command line interface, stats

## Development Workflow
- Typical Cargo workflow: `cargo build`, `cargo test`, `cargo run`.
- Format and lint via `cargo fmt` and `cargo clippy`.

## Deployment Architecture
- Deployed as a standalone Rust binary (`guardian-proxy`), acting as a forward proxy.
- CI/CD managed via GitHub Actions for testing and release.

## Testing Strategy
- Cargo integration and unit tests (`cargo test`).
- The test suite includes full integration testing of the proxy behavior by spawning mock upstream and downstream clients.
