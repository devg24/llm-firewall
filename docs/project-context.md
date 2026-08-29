---
project_name: 'llm-firewall-rs'
user_name: 'Dev Goyal'
date: '2026-08-29'
sections_completed: ['technology_stack', 'language_rules', 'framework_rules', 'testing_rules', 'quality_rules', 'workflow_rules', 'anti_patterns']
status: 'complete'
rule_count: 20
optimized_for_llm: true
---

# Project Context for AI Agents

_This file contains critical rules and patterns that AI agents must follow when implementing code in this project. Focus on unobvious details that agents might otherwise miss._

---

## Technology Stack & Versions

- **Language**: Rust 1.85.0 (Edition 2021)
- **Async Runtime**: Tokio 1.52.3
- **Web Framework**: Axum 0.8.9
- **HTTP Client**: Reqwest 0.13.4
- **Logging & Telemetry**: Tracing 0.1 / Tracing-subscriber 0.3, custom non-blocking JSONL streaming for audit logs
- **Machine Learning**: ort 2.0 (Primary for Tier 4 Inference) & Candle (candle-core 0.10.2 for Tier 3 BERT NER)
- **Serialization**: Serde 1.0 / Serde_json 1.0
- **TLS/Crypto**: rustls 0.23, tokio-rustls 0.26, rcgen 0.14.7 (for MITM local CA generation)

## Critical Implementation Rules

_Documented after discovery phase_

### Language-Specific Rules

- **Error Handling**: Use `Result` and the `?` operator for fallible operations. **Preserve context when bubbling up errors** so async traces are meaningful. Never use `unwrap()` or `expect()` outside of test files (`#[cfg(test)]`).
- **Concurrency & Async Safety**: Use `std::sync::Arc` for shared state. **CRITICAL: NEVER hold a `std::sync::Mutex` lock across an `.await` point.** Furthermore, strongly avoid `tokio::sync::Mutex` unless absolutely necessary, as it severely bottlenecks async throughput. Instead, restructure the code to drop locks before awaiting.
- **Logging & Security**: Use the `tracing` crate, but **always ensure sensitive data (PII, raw LLM prompts) is redacted before logging**. Format errors explicitly (`tracing::error!(%e)`) but verify no sensitive payload is leaked in the error context.
- **Async Streams**: When mutating inbound SSE streams (e.g., re-injecting secrets), you must use high-level async stream combinators (e.g., `async-stream` macro or `StreamExt`). **NEVER** use manual `poll_next` implementations.

### Framework-Specific Rules

- **State Management (Axum)**: Inject shared global dependencies using `axum::extract::State`. **CRITICAL**: The `TokenMap` must NOT be in global `AppState`. It must be instantiated **per outbound request** and shared exclusively with that request's inbound SSE streaming task.
- **Extractor Order**: Axum extractors that consume the request body (e.g., `Json`, `Bytes`) must be the **last** argument in the handler signature, otherwise the code will not compile.
- **Response Handling**: Implement `IntoResponse` for custom error types to map application errors to proper HTTP status codes. Never leak internal error details to the client.
- **Body Streaming & Security**: When acting as a proxy, stream bodies using Axum's `Body` type to avoid buffering. **Always ensure `DefaultBodyLimit` is configured** to prevent memory exhaustion attacks.

### Testing Rules

- **Test Organization**: Write unit tests inline within the same file as the module being tested, enclosed in a `#[cfg(test)] mod tests { ... }` block. Keep integration tests in a separate `tests/` directory if needed.
- **Mocking External APIs**: When testing Axum handlers or downstream HTTP requests, use mock servers (like `wiremock` or Axum's built-in tools) instead of hitting real endpoints.
- **Machine Learning Tests**: Tests involving Candle models can be very slow. Use mock implementations of `ml::SharedModel` or very small dummy weight files to keep unit tests fast. 
- **Critical Paths**: Ensure data redaction logic (PII filtering) is comprehensively tested with rigorous edge cases (e.g., boundary overlaps, regex denial-of-service patterns).

### Code Quality & Style Rules

- **Linting & Formatting**: Ensure all code is formatted with standard `cargo fmt` and passes `cargo clippy`. Treat clippy warnings as errors during development.
- **Documentation**: Write documentation comments (`///`) for all public structures, enums, and functions. Explicitly document `# Errors` and `# Panics` sections for fallible functions.
- **Naming Conventions**: Strictly follow standard Rust naming conventions: `snake_case` for variables and functions, `PascalCase` for structs/enums, `SCREAMING_SNAKE_CASE` for constants.
- **Module Organization (Workspace)**: The project is a single published binary built from a Cargo workspace with three crates: `guardian-core` (pipeline/state), `guardian-proxy` (axum server/mitm), and `guardian-cli` (clap entrypoint). Respect these crate boundaries; do not build a single monolithic crate.

### Development Workflow Rules

- **Branching**: Use feature branches off `main` for all new features and bug fixes (e.g., `feature/add-model-loader`, `fix/proxy-timeout`).
- **Commit Messages**: Write semantic commit messages (e.g., `feat: ...`, `fix: ...`, `chore: ...`). Keep commits atomic and logically separated.
- **Review Requirements**: All new code must pass `cargo test` and `cargo clippy` without warnings before it can be considered ready.
- **Security Check**: Any modifications to the proxy pipeline or ML redactor must include a security review note in the PR detailing potential bypass vectors.
- **Tool & Context Hygiene**:
  - Use `replace_file_content` for code modifications; never use shell `cat` redirection or full rewrites for localized edits.
  - Slice file inspection with `StartLine`/`EndLine` ranges or targeted `grep_search`.
  - Bound terminal command output (pipe/filter verbose test logs).
  - Offload heavy multi-file exploration to subagents to preserve main session context.
  - Persist plans and architecture to BMAD `docs/` artifacts; reference them via markdown links rather than re-dumping content into chat.

### Critical Don't-Miss Rules

- **Blocking the Async Executor**: **NEVER** run heavy CPU-bound tasks (like Candle ML model inference or heavy regex redaction) directly on the Axum async worker thread. Always offload these to `tokio::task::spawn_blocking` to avoid stalling the entire proxy server.
- **PII Leakage in Error Responses**: Never echo back raw user input verbatim in HTTP error responses (e.g., 400 Bad Request). It may contain un-redacted sensitive data or prompt injections.
- **Server-Side Request Forgery (SSRF)**: When parsing `UPSTREAM_URL` or proxying requests, validate the destination. Do not blindly proxy to internal network addresses unless explicitly intended.
- **Header Forwarding**: When proxying requests, carefully strip sensitive headers (like `Authorization` if swapping keys, or `Host`) before forwarding to the upstream LLM provider to avoid security and routing issues.
- **MITM Certificate Generation**: Certificates minted on the fly via `rcgen` for domain spoofing must be properly cached and tied to the Local CA generated during first-run.
- **Configuration Fallbacks**: When parsing `.guardian.toml` or repository manifests (`Cargo.toml`, `package.json`), always provide fail-safe defaults. Never panic on a malformed workspace config.
- **Telemetry File I/O**: Audit logs and \"scare reports\" must use thread-safe, non-blocking asynchronous file writing (e.g., streaming JSONL). Avoid global locks on file descriptors.

---

## Usage Guidelines

**For AI Agents:**

- Read this file before implementing any code
- Follow ALL rules exactly as documented
- When in doubt, prefer the more restrictive option
- Update this file if new patterns emerge

**For Humans:**

- Keep this file lean and focused on agent needs
- Update when technology stack changes
- Review quarterly for outdated rules
- Remove rules that become obvious over time

Last Updated: 2026-08-29
