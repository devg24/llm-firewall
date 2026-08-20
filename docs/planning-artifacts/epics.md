---
stepsCompleted: ['step-01-validate-prerequisites.md', 'step-02-design-epics.md', 'step-03-create-stories.md']
inputDocuments: 
  - docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md
  - docs/specs/spec-guardian-ai-v2/SPEC.md
---

# llm-firewall-rs - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for llm-firewall-rs, decomposing the requirements from the PRD, UX Design if it exists, and Architecture requirements into implementable stories.

## Requirements Inventory

### Functional Requirements

FR1: (CAP-1) Bidirectional stateful proxy - Intercept all LLM API traffic transparently, replacing detected secrets with indexed placeholder tokens outbound and re-injecting real values into LLM-generated output inbound.
FR2: (CAP-2) 4-tier cascading detection pipeline - Detect sensitive data across four complementary tiers: pattern matching, entropy analysis, named entity recognition, and contextual classification.
FR3: (CAP-3) Contextual entropy analysis - Identify high-entropy strings using Shannon entropy combined with surrounding-token context analysis, assigning confidence scores.
FR4: (CAP-4) First-run scare report - `llm-firewall scan` command to silently scan all files and display a summary of secrets that would leak.
FR5: (CAP-5) Zero-config CLI with auto-detection - `llm-firewall on` command to auto-discover installed AI tools, generate local CA cert, and patch proxy config without manual files.
FR6: (CAP-6) Pre-flight security plan - Before long-haul AI tasks, predict accessed files and request single bulk approval for redaction/mock strategies.
FR7: (CAP-7) Session audit and stats - Track lifetime and per-session detection statistics and generate compliance-ready reports (`llm-firewall stats`, `llm-firewall report`).
FR8: (CAP-8) Context-aware output scanning - Analyze destination context before re-injecting secrets on the inbound stream to prevent injection into dangerous sinks (e.g., `curl`).
FR9: (CAP-9) Domain profile auto-detection - Scan project dependency manifests to auto-detect domain and adjust per-tier confidence thresholds.
FR10: (CAP-10) Power-user configuration via `.guardian.toml` - Allow developers to configure per-tier thresholds, custom regex, allowlists, and domain overrides.

### NonFunctional Requirements

NFR1: Sub-millisecond p99 latency per interception on the proxy hot path (Tier 4 classifier permitted 10-25ms but only on borderline spans).
NFR2: Zero `unsafe` Rust.
NFR3: Fail-closed security posture - Any failure in parsing, detection, or proxy logic halts the request.
NFR4: Fully local execution - All detection runs on-device with no external API dependencies (air-gap deployable).
NFR5: Published, reproducible benchmarks - Every detection tier must have CI-verified F1 scores and latency measurements against a golden dataset.
NFR6: Local CA certificate generation - Generates local CA cert and trusts it in the OS trust store instead of disabling TLS verification.
NFR7: Streaming re-injection - Operates at the SSE event level without corrupting SSE framing.
NFR8: Per-tier confidence thresholds - Each tier evaluates against its own configured threshold.
NFR9: Graceful configuration fallback - If `.guardian.toml` is absent or malformed, default 100% to zero-config auto-detection safely.

### Additional Requirements

- **Workspace and Binary Shape** (AD-12): The project is a single published binary built from a crate workspace: `guardian-core` (pipeline, state), `guardian-proxy` (axum server, MITM), and `guardian-cli` (clap entrypoint).
- **Request-Scoped Paired State** (AD-13): `TokenMap` is instantiated per outbound request, wrapped in an `Arc`, and shared exclusively with that request's inbound SSE streaming task.
- **Trait-Based Detection Pipeline** (AD-14): Every detection tier implements a `Detector` trait returning `Vec<Span>` with confidence scores. Orchestrator owns cascade logic.
- **High-Level Async Stream Mutation** (AD-15): Inbound SSE stream mutation must use high-level async stream combinators (e.g., `async-stream` macro).
- **Lookbehind Context Scanning** (AD-16): Mutator must analyze a rolling lookbehind buffer (~512 bytes) of decoded output against dangerous sink heuristics before re-injecting.
- **Foreground Orchestrator** (AD-17): `llm-firewall on` blocks to run the proxy server in the foreground. Graceful shutdown restores all settings and untrusts the CA cert.
- **Architecture Invariants Inherited**: ML Inference Isolation (AD-1), Forwards-Compatible JSON (AD-2), Regex Compilation (AD-3), Local Model Loading (AD-4), Fail-Closed Policy (AD-5), Upstream Gateway (AD-7), Concurrency Bounding (AD-8), Analysis-First Mutation (AD-9), Proxy Header Rewriting (AD-11).

### UX Design Requirements

*(None. No UX design documents found.)*

### FR Coverage Map

- **AD-12:** Epic 1 - Workspace Restructure
- **FR4:** Epic 2 - First-run scare report scanning
- **FR5:** Epic 2 - Zero-config CLI and OS trust setup
- **FR1:** Epic 3 - Bidirectional proxy orchestration
- **FR2:** Epic 3 - 4-tier detection pipeline
- **FR3:** Epic 3 - Contextual entropy engine
- **FR8:** Epic 3 - Context-aware output scanning and dangerous sink blocking
- **FR9:** Epic 4 - Domain profile auto-detection
- **FR10:** Epic 4 - `.guardian.toml` configuration overrides
- **FR6:** Epic 5 - Pre-flight security plan approvals
- **FR7:** Epic 5 - Session audit and stats tracking

## Epic List

### Epic 1: Workspace Restructure & MVP Preservation
The monolithic codebase is cleanly migrated to the 3-crate workspace, and all MVP tests pass identically to ensure zero regression before v2 features begin.
**FRs covered:** AD-12

### Epic 2: Zero-Friction Onboarding & Local Discovery
Developers run a single command that auto-patches their tools and generates a scare report, proving immediate value with zero configuration.
**FRs covered:** FR4, FR5

### Epic 3: Fearless Bidirectional Proxy & Detection Pipeline
Developers code normally while secrets are safely swapped. Implementation is strictly sequenced (Infrastructure → Regex → Advanced ML) to prevent streaming corruption bugs.
**FRs covered:** FR1, FR2, FR3, FR8

### Epic 4: Domain Auto-Tuning & Power-User Customization
False positives drop automatically via domain detection, with `.guardian.toml` for manual overrides.
**FRs covered:** FR9, FR10

### Epic 5: Unattended Autonomy & Compliance Reporting
Developers can approve long-running tasks upfront and generate compliance-ready audit trails.
**FRs covered:** FR6, FR7

## Epic 1: Workspace Restructure & MVP Preservation

The monolithic codebase is cleanly migrated to the 3-crate workspace, and all MVP tests pass identically to ensure zero regression before v2 features begin.

### Story 1.1: Extract Guardian-Core Crate

As a developer,
I want to extract the detection engine, models, and state logic into an independent `guardian-core` crate,
So that the core firewall logic is fully decoupled from the web server and CLI.

**Acceptance Criteria:**

**Given** the current monolithic `llm-firewall-rs` project
**When** the workspace root and `guardian-core` crate are initialized
**Then** the core logic compiles successfully as a library
**And** all existing unit tests for the detection logic pass.

### Story 1.2: Extract Guardian-Proxy Crate

As a developer,
I want to extract the Axum web server and HTTP routing into a `guardian-proxy` crate that depends on `guardian-core`,
So that the MITM proxy layer is separated from the underlying detection algorithms.

**Acceptance Criteria:**

**Given** a working `guardian-core` crate
**When** the `guardian-proxy` crate is created and the Axum logic is migrated
**Then** the proxy logic compiles successfully
**And** it correctly resolves its dependency on `guardian-core`.

### Story 1.3: Extract Guardian-CLI and Verify MVP Integrity

As a developer,
I want to create a `guardian-cli` crate serving as the main entrypoint that depends on both core and proxy crates,
So that the full MVP functionality is restored under the new workspace architecture.

**Acceptance Criteria:**

**Given** the extracted core and proxy crates
**When** the CLI entrypoint is built and executed
**Then** the application runs identical to the v1 monolith
**And** all integration tests pass perfectly to prove zero regressions.

## Epic 2: Zero-Friction Onboarding & Local Discovery

Developers run a single command that auto-patches their tools and generates a scare report, proving immediate value with zero configuration.

### Story 2.1: Implement Local CA Trust Generator

As a developer,
I want the CLI to generate a local CA certificate and trust it in the OS trust store on activation,
So that TLS interception works seamlessly without forcing me to disable strict SSL in my tools.

**Acceptance Criteria:**

**Given** a developer starting `llm-firewall on`
**When** the proxy initializes
**Then** it generates a local CA certificate and runs the appropriate OS commands (e.g., macOS `security add-trusted-cert`)
**And** upon graceful shutdown (Ctrl+C), the certificate is cleanly removed from the OS trust store
**And** automated tests verify the certificate generation logic and that the OS commands are correctly formulated.

### Story 2.2: AI Harness Config Auto-Patcher

As a developer,
I want the CLI to auto-detect installed AI tools (Cursor, Copilot, Claude Code) and inject proxy settings,
So that I don't have to manually edit config files or environment variables.

**Acceptance Criteria:**

**Given** the proxy is starting up
**When** it detects Cursor `settings.json` or Copilot configs
**Then** it patches `http.proxy` and `http.proxyStrictSSL` properties (or exports `HTTP_PROXY` for Claude Code)
**And** it restores the original configurations perfectly upon shutdown
**And** the CLI detects running IDE processes and prompts the user to restart them to ensure proxy settings take effect
**And** integration tests explicitly verify that JSON configuration files are correctly parsed, modified, and restored without data loss or formatting corruption.

### Story 2.3: First-Run Scare Report Scanner

As a developer,
I want the `llm-firewall scan` command to quickly scan my local repository and print a formatted summary of detected secrets,
So that I can see the immediate value and risk exposure before I even activate the proxy.

**Acceptance Criteria:**

**Given** the user runs `llm-firewall scan` in a repository
**When** the command executes
**Then** it traverses all non-gitignored files (under 5 seconds for a 10K file repo)
**And** the scanner enforces explicit file-size limits and timeouts per file to prevent DoS from malicious repositories
**And** applies the detection engine to find secrets
**And** prints a human-readable terminal report detailing the findings and estimated breach cost
**And** unit tests verify the scanner correctly respects `.gitignore` rules and accurately formats the terminal report.

## Epic 3: Fearless Bidirectional Proxy & Detection Pipeline

Developers code normally while secrets are safely swapped. Implementation is strictly sequenced (Infrastructure → Regex → Advanced ML) to prevent streaming corruption bugs.

### Story 3.1: Bidirectional Passthrough Infrastructure

As a developer,
I want the proxy to establish bidirectional SSE stream interception and maintain an empty, request-scoped `TokenMap`,
So that the baseline streaming infrastructure is proven solid before any mutation occurs.

**Acceptance Criteria:**

**Given** an active proxy connection to an LLM API
**When** a streaming response (SSE) is received
**Then** the `TokenMap` is instantiated per outbound request and shared with the inbound task
**And** the stream is parsed and forwarded completely uncorrupted
**And** the proxy safely identifies and passes through non-SSE upstream responses (e.g., 400 Bad Request JSON) without entering the stream mutator loop
**And** integration tests explicitly verify that SSE framing (`data: ...\n\n`) remains perfectly intact under heavy load.

### Story 3.2: Tier 1 Detection & Core Re-injection Loop

As a developer,
I want to integrate the deterministic Tier 1 Regex engine and mutate the inbound stream to restore caught secrets,
So that the core end-to-end "swap and restore" loop is fully functional.

**Acceptance Criteria:**

**Given** an outbound request containing deterministic PII (e.g., an email or SSN)
**When** the request passes through the proxy
**Then** the PII is replaced with a token outbound and stored in the `TokenMap`
**And** the inbound mutator uses high-level async stream combinators to perfectly re-inject the secret into the LLM's response
**And** the proxy injects a system prompt instruction (via AD-11) commanding the LLM not to mutate or lowercase `[REDACTED_*]` tokens
**And** the mutator restricts its token search strictly to the `content` JSON fields, safely ignoring raw binary or base64 data
**And** the mutator correctly buffers overlapping SSE chunks to handle fragmented tokens (e.g., `[REDACTE` in chunk 1, `D_SSN]` in chunk 2)
**And** tests explicitly verify 1-way payload rebuilding and exact inbound restoration.

### Story 3.3: Context-Aware Sink Blocking (Lookbehind Buffer)

As a developer,
I want the inbound mutator to analyze a rolling buffer of decoded text before re-injecting secrets,
So that prompt-injected LLM exfiltration attempts into dangerous sinks (like `curl`) are blocked.

**Acceptance Criteria:**

**Given** an LLM generating a response that attempts to use a redacted secret in a dangerous context (e.g., a `curl` command)
**When** the inbound mutator processes the stream
**Then** it analyzes a ~512-byte rolling lookbehind buffer against heuristics
**And** heuristics account for evasion techniques (e.g., whitespace injection) and overlap resolution prevents boundary-splitting attacks
**And** quarantines the output instead of re-injecting the secret
**And** explicit unit tests cover dangerous sink detection across chunk boundaries and overlapping chunks.

### Story 3.4: Advanced Detection Pipeline (Entropy, NER, Contextual)

As a developer,
I want to add the advanced Tiers (Entropy, NER, and Contextual Classification) adhering to the `Detector` trait,
So that complex, unstructured secrets are caught with high accuracy and low latency.

**Acceptance Criteria:**

**Given** the orchestrator cascading through the detection tiers
**When** high-entropy strings or contextual PII are evaluated
**Then** the orchestrator applies overlap resolution and confidence thresholds accurately
**And** Tier 4 (Contextual) executes *only* on borderline confidence spans (0.5–0.7) to preserve sub-millisecond p99 latency
**And** automated benchmarks verify an F1 score ≥ 0.95 against the golden test dataset.

## Epic 4: Domain Auto-Tuning & Power-User Customization

False positives drop automatically via domain detection, with `.guardian.toml` for manual overrides.

### Story 4.1: Auto-Detect Project Domain from Manifests

As a developer,
I want the core orchestrator to scan my project's dependency manifests (e.g., `Cargo.toml`, `package.json`),
So that it can auto-detect the project domain (like "crypto" or "fintech") and automatically tune detection thresholds to prevent false positives.

**Acceptance Criteria:**

**Given** a project containing specific domain markers (e.g., `ethers` or `solana` dependencies)
**When** the proxy initializes
**Then** it detects the domain profile and automatically raises the Tier 2 Entropy threshold (e.g., from 0.6 to 0.85)
**And** the scanner supports monorepos by aggregating domain profiles across all discovered manifests in subdirectories
**And** unit tests verify the manifest parser correctly assigns domains without failing on malformed manifests.

### Story 4.2: Power-User `.guardian.toml` Configuration

As a developer,
I want to define custom regex rules, variable allowlists, and threshold overrides in a `.guardian.toml` file,
So that I have absolute, explicit control over the firewall's behavior in edge-case repositories.

**Acceptance Criteria:**

**Given** a repository with a `.guardian.toml` file at its root
**When** the proxy starts
**Then** it applies the custom rules and overrides the auto-detected domain settings
**And** custom regex rules are validated against catastrophic backtracking (ReDoS) vulnerabilities before compilation
**And** if the TOML file contains syntax errors, the proxy logs a warning and gracefully falls back to zero-config defaults instead of crashing (fail-safe initialization)
**And** integration tests verify custom allowlist spans correctly bypass all detection tiers.

## Epic 5: Unattended Autonomy & Compliance Reporting

Developers can approve long-running tasks upfront and generate compliance-ready audit trails.

### Story 5.1: Pre-Flight Security Plan Generation

As a developer,
I want the CLI to generate a bulk approval request predicting sensitive file access before I launch an unattended AI task,
So that I don't have to monitor the agent and approve individual redaction decisions mid-task.

**Acceptance Criteria:**

**Given** the user runs a pre-flight command (e.g., `llm-firewall preflight`)
**When** the command analyzes the intended task scope
**Then** it generates a unified plan of redaction/mock strategies for the sensitive zones
**And** upon user approval, the proxy securely stores this plan and operates entirely silently within those bounds
**And** the pre-flight plan strictly jails the AI to the current working directory, explicitly blocking absolute paths outside the repo boundary
**And** tests verify the pre-flight plan is correctly applied to the proxy's active state.

### Story 5.2: Compliance Audit and Stats Engine

As a developer,
I want the system to track detection statistics and generate compliance reports,
So that I can objectively prove to my team or security department that no sensitive data was leaked.

**Acceptance Criteria:**

**Given** a history of intercepted requests
**When** the user runs `llm-firewall stats` or `llm-firewall report`
**Then** the `stats` command outputs a terminal summary of cumulative detections (count, type, estimated cost saved)
**And** the `report` command generates a shareable, structured audit file
**And** integration tests verify that the proxy correctly persists detection metrics to an append-only JSONL file to maintain a 100% pure Rust dependency tree without C-bindings.
