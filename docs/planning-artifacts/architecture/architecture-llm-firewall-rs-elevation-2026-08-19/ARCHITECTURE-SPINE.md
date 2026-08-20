---
name: 'llm-firewall-rs-elevation'
type: architecture-spine
purpose: build-substrate
altitude: initiative
paradigm: 'Request-Scoped Stateful MITM Proxy'
scope: 'Elevation of llm-firewall-rs from MVP to top-1% open-source project (CAP-1 through CAP-10)'
status: final
created: '2026-08-19'
updated: '2026-08-19'
binds: ['CAP-1', 'CAP-2', 'CAP-3', 'CAP-4', 'CAP-5', 'CAP-6', 'CAP-7', 'CAP-8', 'CAP-9', 'CAP-10', 'AD-1', 'AD-2', 'AD-3', 'AD-4', 'AD-5', 'AD-6', 'AD-7', 'AD-8', 'AD-9', 'AD-10', 'AD-11']
sources: ['SPEC-guardian-ai-v2']
companions: []
---

# Architecture Spine — Guardian-AI v2 Elevation

## Design Paradigm

Guardian-AI evolves from a purely stateless filter into a **Request-Scoped Stateful MITM Proxy**. 
The system operates as a single executable with subcommands. The proxy hot-path maintains bidirectional state scoped strictly to the lifecycle of a single HTTP request-response pair, enabling lossless re-injection on streaming responses without introducing long-lived sticky sessions or complex eviction logic.

## Inherited Invariants

| Inherited | From parent | Binds here |
| --- | --- | --- |
| AD-1 (ML Inference Isolation) | architecture-llm-firewall-rs-2026-06-26 | `guardian-core` tier 3/4 execution |
| AD-2 (Forwards-Compatible JSON) | architecture-llm-firewall-rs-2026-06-26 | `guardian-proxy` outbound interception |
| AD-3 (Regex Compilation) | architecture-llm-firewall-rs-2026-06-26 | `guardian-core` tier 1 |
| AD-4 (Local Model Loading) | architecture-llm-firewall-rs-2026-06-26 | `guardian-core` model init |
| AD-5 (Fail-Closed Policy) | architecture-llm-firewall-rs-2026-06-26 | `guardian-proxy` error handling |
| AD-7 (Upstream Gateway) | architecture-llm-firewall-rs-2026-06-26 | `guardian-proxy` forwarder |
| AD-8 (Concurrency Bounding) | architecture-llm-firewall-rs-2026-06-26 | `guardian-core` inference |
| AD-9 (Analysis-First Mutation) | architecture-llm-firewall-rs-2026-06-26 | `guardian-core` orchestrator |
| AD-11 (Proxy Header Rewriting) | architecture-llm-firewall-rs-2026-06-26 | `guardian-proxy` forwarder |

*Note: AD-6 (Ephemeral Map) and AD-10 (Ephemeral Map Concurrency) are evolved by AD-13 below to support bidirectional re-injection.*

## Invariants & Rules

### AD-12 — Workspace and Binary Shape
- **Binds:** Crate boundaries and dependency direction.
- **Prevents:** Circular dependencies and monolithic single-crate growth that blocks contributor onboarding.
- **Rule:** The project is a single published binary built from a crate workspace: `guardian-core` (detection pipeline, session state, redaction engine), `guardian-proxy` (axum server, SSE streaming, MITM logic), and `guardian-cli` (clap entrypoint, scare report, tool patching). The CLI depends on core and proxy; proxy depends on core.

### AD-13 — Request-Scoped Paired State
- **Binds:** `guardian-core` session state model and `guardian-proxy` handler lifecycle.
- **Prevents:** Memory leaks from orphaned sessions, crash-state-loss bugs, and the complexity of global session management.
- **Rule:** The translation map (`TokenMap`) is instantiated per outbound request, wrapped in an `Arc`, and shared exclusively with that request's inbound SSE streaming task. The map is destroyed when the HTTP request-response cycle completes.

### AD-14 — Trait-Based Detection Pipeline
- **Binds:** `guardian-core` detection API surface.
- **Prevents:** Tightly coupled detection stages and conflicting threshold/span format decisions across tiers.
- **Rule:** Every detection tier implements a `Detector` trait returning `Vec<Span>` with confidence scores. The pipeline orchestrator owns tier ordering, cascade logic (e.g., Tier 4 only runs on borderline spans), threshold application, and overlap resolution. No individual tier applies its own threshold.

### AD-15 — High-Level Async Stream Mutation
- **Binds:** `guardian-proxy` inbound response handling.
- **Prevents:** Unsafe `Pin`/`Waker` bugs, dropped SSE events, and unmaintainable state machine code.
- **Rule:** Inbound SSE stream mutation must use high-level async stream combinators (e.g., `async-stream` macro or `StreamExt`) rather than manual `poll_next` implementations.

### AD-16 — Lookbehind Context Scanning
- **Binds:** `guardian-proxy` stream mutator (CAP-8).
- **Prevents:** Breaking SSE streaming UX with bursty buffering, while mitigating prompt-injected LLM exfiltration vectors.
- **Rule:** Before re-injecting a secret on the inbound stream, the mutator must analyze a rolling lookbehind buffer (~512 bytes) of decoded output against dangerous sink heuristics (e.g., `curl`). Dangerous sinks trigger quarantine instead of re-injection. 

### AD-17 — Foreground Orchestrator
- **Binds:** `guardian-cli` process model (CAP-5).
- **Prevents:** Orphaned background daemon processes, broken network state on silent crashes, and complex PID tracking.
- **Rule:** `llm-firewall on` sets OS/tool proxy configurations and blocks to run the proxy server in the foreground. A graceful shutdown hook (Ctrl+C) must restore all settings and untrust the CA cert.

## Consistency Conventions

| Concern | Convention |
| --- | --- |
| Threat Model Bounds | Guardian-AI protects against accidental provider exfiltration and prompt-injected LLM exfiltration. It explicitly assumes the host developer is trusted. |
| Feature Flags | Experimental tiers (Tier 4 ONNX) should be feature-flagged during initial development. |

## Stack

| Name | Version |
| --- | --- |
| Rust (Edition) | 2021 (MSRV 1.85.0) |
| axum | 0.8.9 |
| tokio | 1.52.3 |
| candle-core | 0.10.2 |
| reqwest | 0.13.4 |
| async-stream | 0.3.5 |
| aho-corasick | 1.1.3 |
| ort | 2.0 (Tier 4 Inference) |
| clap | 4.5.4 |

## Structural Seed

```text
llm-firewall-rs/
  Cargo.toml               # Workspace root
  crates/
    guardian-core/         # Detection pipeline (Tiers 1-4), TokenMap, thresholds, orchestrator
    guardian-proxy/        # Axum router, bidirectional interception, SSE stream mutator
    guardian-cli/          # Clap subcommands (on, off, scan, stats), tool patching
```

## Capability → Architecture Map

| Capability / Area | Lives in | Governed by |
| --- | --- | --- |
| CAP-1 (Bidirectional proxy) | `guardian-proxy` | AD-13, AD-15 |
| CAP-2, CAP-3, CAP-9 (Pipeline) | `guardian-core` | AD-14 |
| CAP-4, CAP-7 (Scare report, Stats) | `guardian-cli` | AD-12 |
| CAP-5 (Zero-config CLI) | `guardian-cli` | AD-12, AD-17 |
| CAP-8 (Context-aware output) | `guardian-proxy` | AD-16 |
| CAP-10 (guardian.toml config) | `guardian-core` / `guardian-cli` | AD-12 |

## Deferred

- **HTTP/2 Full Support:** Cursor integration disables HTTP/2 temporarily (`cursor.general.disableHttp2: true`) to avoid ALPN negotiation complexities with local self-signed CA certs. Full HTTP/2 proxy support is deferred.
