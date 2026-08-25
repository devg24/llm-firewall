---
story_id: "4.1"
story_key: "4-1-auto-detect-project-domain-from-manifests"
epic: 4
status: done
baseline_commit: "3b1a19b"
---

# Story 4.1: Auto-Detect Project Domain from Manifests

## Story

**As a developer,**
I want the core firewall engine and proxy server to scan my project workspace's dependency manifests (e.g., `Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml`),
**So that** it automatically detects the project domain profile (such as `CryptoFintech` or `Healthcare`) and tunes per-tier detection thresholds (e.g. raising Tier 2 Entropy threshold from 3.84 to 4.28 Shannon bits) to eliminate domain-specific false positives without sacrificing security.

## Acceptance Criteria

- **AC1 (Manifest Domain Detection):** Given a project workspace containing dependency manifests with domain markers (e.g., `ethers`, `solana`, `web3`, `alloy`, `viem` for `CryptoFintech`; `fhir`, `hl7`, `medplum`, `bonfhir` for `Healthcare`), when `detect_domain_from_manifests` executes, then it identifies the matching `DomainProfile` and associates it with the quantitatively derived `ThresholdMatrix` (e.g., `CryptoFintech` entropy threshold = 4.28 bits, `Healthcare` entropy threshold = 4.16 bits, `Standard` = 3.84 bits).
- **AC2 (Multi-Ecosystem Manifest Support):** Given dependency manifests in various ecosystem formats (`Cargo.toml` dependencies/dev-dependencies/workspace.dependencies, `package.json` dependencies/devDependencies, `go.mod` require directives, and Python `requirements.txt`/`pyproject.toml`), when the manifest parser scans each file, then it accurately detects domain markers across all supported manifest formats.
- **AC3 (Monorepo Traversal & Aggregation):** Given a monorepo workspace containing nested subcrates or packages (e.g., `packages/*`, `crates/*`, `apps/*`), when directory scanning runs, then it traverses nested subdirectories up to a safe bounded depth (e.g., depth 5), skips ignored directories (`target`, `node_modules`, `.git`, `.venv`, `dist`, `build`, `vendor`, `.turbo`, `.next`, `coverage`), and aggregates domain markers across all discovered manifests. If domain-specific markers are found in any sub-package, the workspace is classified with that specialized domain profile.
- **AC4 (Fail-Safe Initialization & Zero Panic):** Given missing, unreadable, or malformed manifest files (invalid TOML/JSON syntax, permission errors, empty files, or circular symlinks), when domain detection runs, then it must never panic or crash the server. It logs a diagnostic warning via `tracing::warn!` and gracefully falls back to `DomainProfile::Standard`.
- **AC5 (Proxy State & Pipeline Integration):** Given an auto-detected `DomainProfile`, when the proxy server initializes, then `AppState` stores the `domain` profile and `chat_completions_handler` initializes the `DetectionOrchestrator` with `DetectionOrchestrator::with_domain(state.model.clone(), state.domain)` so all request payloads are evaluated against the domain-tuned thresholds.
- **AC6 (CLI Startup Auto-Tuning):** Given the CLI server commands (`run_server`, `run_server_with_trust`), when the proxy starts, then it detects the domain of the current working directory (`std::env::current_dir()`), logs the detected profile and active entropy/NER thresholds via `tracing::info!`, and injects the profile into `AppState`.
- **AC7 (Automated Testing & Benchmark Verification):** Given unit, integration, and benchmark tests, all manifest parsing edge cases, monorepo directory recursions, error fallbacks, and proxy suppression of safe crypto/healthcare high-entropy strings pass with 100% success and 0 clippy warnings.

---

## Tasks / Subtasks

- [x] **Task 1: Comprehensive Multi-Ecosystem Manifest Parser in `crates/guardian-core/src/manifest.rs`** (AC: #1, #2, #4)
  - [x] 1a. Expand domain marker dictionaries in `crates/guardian-core/src/manifest.rs` for `CryptoFintech` (`ethers`, `solana`, `web3`, `alloy`, `bitcoin`, `alloy-primitives`, `@solana/web3.js`, `viem`, `wagmi`, `web3.py`, `eth-account`, `bip39`, `secp256k1`, `go-ethereum`) and `Healthcare` (`fhir`, `hl7`, `medplum`, `bonfhir`, `dicom`, `python-hl7`, `fhirclient`, `healthgorilla`).
  - [x] 1b. Enhance `Cargo.toml` parser to inspect `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[workspace.dependencies]`, and `[target.*.dependencies]`.
  - [x] 1c. Enhance `package.json` parser to inspect `dependencies`, `devDependencies`, `peerDependencies`, and `optionalDependencies`.
  - [x] 1d. Add `go.mod` parser extracting module paths from `require` blocks and single-line `require` statements.
  - [x] 1e. Add Python manifest parsers for `requirements.txt` (line-by-line package name extraction) and `pyproject.toml` (`[project.dependencies]`, `[tool.poetry.dependencies]`).
  - [x] 1f. Ensure all parsers return `Option` / `Result` and handle malformed files gracefully without panicking.

- [x] **Task 2: Robust Monorepo Directory Walker & Domain Aggregator in `crates/guardian-core/src/manifest.rs`** (AC: #3, #4)
  - [x] 2a. Implement safe recursive directory traversal with bounded depth limit (max depth 5).
  - [x] 2b. Implement directory exclusion filter to immediately prune: `target`, `node_modules`, `.git`, `.venv`, `venv`, `env`, `dist`, `build`, `vendor`, `.turbo`, `.next`, `coverage`, `.cache`.
  - [x] 2c. Protect against circular symlinks by tracking visited canonical path `HashSet<PathBuf>`.
  - [x] 2d. Accumulate domain hits across all manifests discovered in the workspace tree.
  - [x] 2e. Apply priority resolution: explicit `.guardian.toml` domain override (Story 4.2 prep) > `CryptoFintech` / `Healthcare` marker detection > default `Standard`.

- [x] **Task 3: Thread `DomainProfile` into `AppState` in `crates/guardian-proxy`** (AC: #5)
  - [x] 3a. Update `AppState` struct in `crates/guardian-proxy/src/lib.rs` to include `pub domain: guardian_core::DomainProfile`.
  - [x] 3b. Update `create_app` and `AppState` constructors to accept or configure `domain: DomainProfile`.
  - [x] 3c. Update `chat_completions_handler` in `crates/guardian-proxy/src/proxy.rs` to construct the orchestrator using `guardian_core::orchestrator::DetectionOrchestrator::with_domain(state.model.clone(), state.domain)`.
  - [x] 3d. Update existing proxy integration tests in `crates/guardian-proxy/tests/integration_tests.rs` and `crates/guardian-proxy/tests/sse_passthrough.rs` to initialize `AppState` with `domain: DomainProfile::Standard` (or specialized domains where tested).

- [x] **Task 4: Wire Workspace Domain Detection into CLI Startup in `crates/guardian-cli/src/lib.rs`** (AC: #6)
  - [x] 4a. In `crates/guardian-cli/src/lib.rs` (`run_server_internal` and `run_server_with_trust`), resolve the current working directory (`std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))`).
  - [x] 4b. Execute `let detected_domain = guardian_core::manifest::detect_domain_from_manifests(&cwd);`.
  - [x] 4c. Log detection results: `tracing::info!(domain = ?detected_domain, entropy_threshold = detected_domain.thresholds().entropy_tier, "Auto-detected project domain profile");`.
  - [x] 4d. Instantiate `AppState` with `domain: detected_domain`.

- [x] **Task 5: Comprehensive Unit, Integration, and Benchmark Tests** (AC: #7)
  - [x] 5a. Unit tests in `crates/guardian-core/src/manifest.rs`:
    - `Cargo.toml` standard vs crypto (`ethers`, `solana`, `alloy`) vs healthcare (`fhir`).
    - `package.json` standard vs crypto (`viem`, `wagmi`, `@solana/web3.js`) vs healthcare (`medplum`, `bonfhir`).
    - `go.mod` crypto (`github.com/ethereum/go-ethereum`) and healthcare.
    - Python `requirements.txt` & `pyproject.toml`.
    - Monorepo nested subcrates with ignored `node_modules` and `target` directories.
    - Malformed TOML, malformed JSON, and non-existent directories returning `DomainProfile::Standard` without panic.
  - [x] 5b. Integration test in `crates/guardian-proxy/tests/integration_tests.rs`:
    - Set up test proxy with `DomainProfile::CryptoFintech`.
    - Verify request containing Ethereum address / Solana pubkey is NOT redacted (entropy threshold 4.28 bits avoids false positive).
    - Verify request containing real AWS secret key `AKIAIOSFODNN7EXAMPLE` IS redacted (Tier 1 regex continues to protect known secret formats unconditionally).
  - [x] 5c. Fix any dead code warning in `crates/guardian-core/tests/detection_benchmarks.rs`.

- [x] **Task 6: Workspace Quality & Zero-Warning Compliance** (AC: #7)
  - [x] 6a. Run `cargo test --workspace -- --quiet` and verify all tests pass.
  - [x] 6b. Run `cargo clippy --workspace -- -D warnings` and verify 0 warnings.
  - [x] 6c. Run `cargo fmt --check` and verify formatting.

---

## Dev Notes

### Architecture & Design Decisions

#### 1. Trait-Based Detection Pipeline & Per-Tier Threshold Matrix (AD-14, CAP-9)
Every detection tier runs under the `Detector` trait. The `DetectionOrchestrator` receives a `DomainProfile` and applies that domain's `ThresholdMatrix`:
- **Tier 1 (Pattern Matching / Regex):** Threshold = 1.0 (deterministic, unconditional redaction for known API keys, AWS tokens, SSNs, Private Keys).
- **Tier 2 (Shannon Entropy):**
  - `Standard`: `3.84` bits (F1 = 0.8554, optimal balance for general web applications).
  - `CryptoFintech`: `4.28` bits (F1 = 0.6953, raised threshold prevents flagging Ethereum hex addresses, Solana Base58 pubkeys, and transaction hashes).
  - `Healthcare`: `4.16` bits (F1 = 0.7943, high precision to prevent disrupting clinical workflows).
- **Tier 3 (NER via BERT):**
  - `Standard`: `0.70`
  - `CryptoFintech`: `0.80`
  - `Healthcare`: `0.60` (tightened threshold to catch patient names and clinical identifiers).
- **Tier 4 (Contextual Classifier via ORT):** Feature-flagged / deferred per Architecture Spine.

#### 2. Domain Marker Matrix
The manifest parser recognizes common domain libraries across languages:

| Domain | Ecosystem | Markers |
|---|---|---|
#### 3. Monorepo Discovery & Directory Traversal Invariants
- **Bounded Recursion Depth:** Max depth of 5 levels prevents traversing infinitely deep directory trees.
- **Directory Pruning:** Must prune `target/`, `node_modules/`, `.git/`, `.venv/`, `venv/`, `dist/`, `build/`, `vendor/`, `.next/`, `coverage/` before inspecting directory entries.
- **Symlink Cycle Guard:** Maintain a `HashSet<PathBuf>` of visited canonical directories.
- **Domain Aggregation Rule:** If any manifest in the monorepo exhibits `CryptoFintech` markers, the project domain is elevated to `CryptoFintech`. If `Healthcare` markers are found and no crypto markers, it is elevated to `Healthcare`. If no markers match, it defaults to `Standard`.
- **Fail-Safe Invariant:** If reading a directory or parsing any single manifest fails (I/O error, invalid syntax), the parser logs `tracing::warn!` and continues scanning without aborting or panicking.

#### 4. Axum State Management (AD-13)
- `DomainProfile` is `Copy`, `Clone`, `Send`, `Sync`.
- It is stored directly in `AppState.domain`.
- `chat_completions_handler` creates the `DetectionOrchestrator` with `DetectionOrchestrator::with_domain(state.model.clone(), state.domain)`.
- Locking safety is preserved: no `std::sync::Mutex` is held across `.await` points.

---

### Project Structure Notes

#### Files to Touch & Modify

- **Modify:** [`crates/guardian-core/src/manifest.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/manifest.rs)
  - Implement full manifest parsers: `Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml`.
  - Implement recursive directory traversal with directory pruning and symlink safety.
  - Implement domain aggregation logic.
  - Add comprehensive unit tests for all manifest formats, monorepos, and malformed files.

- **Modify:** [`crates/guardian-core/src/domain.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/domain.rs)
  - Ensure doc comments and threshold matrix values align with quantitative benchmarks.

- **Modify:** [`crates/guardian-proxy/src/lib.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/src/lib.rs)
  - Add `pub domain: guardian_core::DomainProfile` field to `AppState`.
  - Update any constructor or builder functions.

- **Modify:** [`crates/guardian-proxy/src/proxy.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/src/proxy.rs)
  - In `chat_completions_handler`, instantiate orchestrator using `DetectionOrchestrator::with_domain(state.model.clone(), state.domain)`.

- **Modify:** [`crates/guardian-cli/src/lib.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-cli/src/lib.rs)
  - In `run_server_internal` and `run_server_with_trust`, detect workspace domain from `std::env::current_dir()`.
  - Log detected domain and entropy/NER thresholds via `tracing::info!`.
  - Initialize `AppState` with `domain: detected_domain`.

- **Modify:** [`crates/guardian-proxy/tests/integration_tests.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/tests/integration_tests.rs) & [`crates/guardian-proxy/tests/sse_passthrough.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/tests/sse_passthrough.rs)
  - Update `AppState` initializations with `domain: DomainProfile::Standard`.
  - Add integration test for domain-tuned proxy behavior (Crypto domain suppressing crypto false positives while redacting AWS keys).

- **Modify:** [`crates/guardian-core/tests/detection_benchmarks.rs`](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/tests/detection_benchmarks.rs)
  - Clean up any unused field compiler warnings on `DomainItem`.

---

### Previous Story Intelligence & Learnings

From Epic 3 ([`docs/implementation-artifacts/epic-3-retro-2026-08-20.md`](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/implementation-artifacts/epic-3-retro-2026-08-20.md)) and Story 3.4 ([`docs/implementation-artifacts/3-4-advanced-detection-pipeline.md`](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/implementation-artifacts/3-4-advanced-detection-pipeline.md)):
1. **Entropy False Positives:** Normal entropy detectors falsely flag hex addresses, Solana Base58 strings, and transaction IDs. Epic 4's domain auto-detection directly solves this by raising the entropy threshold from 3.84 to 4.28 bits in crypto repos.
2. **Benchmark 7 (`benchmark_crypto_orchestrator_fp_guard`):** A dedicated benchmark already exists in `crates/guardian-core/tests/detection_benchmarks.rs` proving that `DetectionOrchestrator::with_domain(None, DomainProfile::CryptoFintech)` flags strictly fewer false positives than `DomainProfile::Standard`. Story 4.1 connects the workspace scanner directly to this mechanism.
3. **Fail-Safe Philosophy:** LLM firewall components must NEVER panic on dirty or strange inputs. Whether it is an SSE split across arbitrary byte boundaries or a malformed `Cargo.toml` with broken syntax, the firewall logs the issue and falls back to safe defaults.

---

### References

- [docs/project-context.md](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/project-context.md) — Rust, Axum, ML, and async safety conventions.
- [docs/planning-artifacts/epics.md#Story 4.1](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/epics.md#L252-L265) — Story 4.1 requirements and acceptance criteria.
- [docs/specs/spec-guardian-ai-v2/detection-pipeline.md](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/specs/spec-guardian-ai-v2/detection-pipeline.md#L87-L97) — Domain-sensitive thresholds & quantitative derivation.
- [docs/specs/spec-guardian-ai-v2/SPEC.md#CAP-9](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/specs/spec-guardian-ai-v2/SPEC.md#L54-L56) — Domain profile auto-detection capability definition.
- [crates/guardian-core/src/manifest.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/manifest.rs) — Existing manifest scanner foundation.
- [crates/guardian-core/src/domain.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/domain.rs) — `DomainProfile` and `ThresholdMatrix` definitions.
- [crates/guardian-core/src/orchestrator.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/src/orchestrator.rs) — `DetectionOrchestrator::with_domain` implementation.
- [crates/guardian-proxy/src/proxy.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/src/proxy.rs) — `chat_completions_handler`.
- [crates/guardian-cli/src/lib.rs](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-cli/src/lib.rs) — `run_server_internal` startup sequence.

---

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
