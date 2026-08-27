---
story_id: "5.1"
story_key: "5-1-pre-flight-security-plan-generation"
epic: 5
status: review
baseline_commit: "18c856d"
---

# Story 5.1: Pre-Flight Security Plan Generation

## Story

**As a developer,**
I want the CLI to scan my workspace and generate a bulk approval security plan predicting sensitive file zones and enforcing a strict directory sandbox before launching an unattended AI task,
**So that** I do not have to monitor the AI agent and approve individual redaction decisions mid-task, while remaining guaranteed that the agent cannot escape the repository boundary or access out-of-workspace secrets.

---

## Acceptance Criteria

- **AC1 (Pre-Flight Workspace Scan & Sensitive Zone Prediction):** Given a project workspace root directory, when `llm-firewall preflight` (or `guardian_core::plan::generate_preflight_plan`) executes:
  - It performs a bounded, non-blocking scan of the workspace using `ignore::WalkBuilder` (respecting `.gitignore`, `.ignore`, and standard directory exclusions `target`, `node_modules`, `.git`, `.venv`, `.cargo`, `dist`, `build`).
  - It scans files up to a configurable maximum size (default 5MB) within a per-file timeout (default 500ms).
  - It detects all sensitive secret tokens across Tier 1 patterns (AWS, GCP, GitHub, Bearer tokens, Private Keys, Database URIs, Passwords, etc.) and high-risk file types (`.env*`, `*.pem`, `*.key`, `credentials.*`, `id_rsa*`).
  - It aggregates matches into distinct `SensitiveZone` records identifying the relative file path, detected `PiiType` categories, total match count, and recommended mitigation strategy (`Redact`, `Mock`, or `Block`).

- **AC2 (Preflight Plan Data Model & Serialization):** Given discovered sensitive zones and sandbox configurations, when the plan data structure is constructed:
  - It instantiates a strongly typed, Serde-compatible `PreflightPlan` struct containing:
    - `version: u32` (schema version, default `1`).
    - `workspace_root: PathBuf` (canonicalized absolute root path).
    - `created_at: u64` (Unix epoch timestamp in seconds).
    - `sensitive_zones: Vec<SensitiveZone>`.
    - `sandbox: SandboxPolicy` (with `root: PathBuf`, `enforce_jailing: bool`, and optional `allow_subpaths: Vec<PathBuf>`).
    - `approved: bool`.
  - It provides serialization to and deserialization from JSON format (`.guardian-plan.json` / in-memory JSON string) with fail-safe error handling.

- **AC3 (Interactive CLI Flow & Bulk Approval State Machine):** Given the user running `llm-firewall preflight`:
  - The CLI outputs a structured, human-readable terminal table detailing:
    1. Workspace root and canonical sandbox boundary.
    2. Summary of sensitive files, secret types found, and recommended strategies.
    3. Total count of predicted sensitive zones.
  - In interactive mode (default), it presents a prompt: `Approve this pre-flight security plan for unattended session? [y/N]: `.
    - If approved (`y` / `Y`), it marks `approved = true`, saves the plan to `.guardian-plan.json` in the workspace root, and outputs confirmation `✅ Pre-flight plan approved. Proxy will operate silently within these bounds.`.
    - If rejected (`n` / `N` or aborted), it aborts without saving an approved plan and outputs `❌ Pre-flight plan rejected. No changes saved.`.
  - In non-interactive mode with `--yes` / `-y`, it automatically marks the plan as approved and saves `.guardian-plan.json`.
  - With `--dry-run`, it prints the formatted JSON plan to stdout without writing to disk.
  - With `--show`, it inspects and displays the current `.guardian-plan.json` status in the current working directory.
  - With `--clear`, it deletes `.guardian-plan.json` from the current working directory.

- **AC4 (Path Canonicalization & Strict Workspace Sandbox Boundary Engine):** Given a configured `SandboxPolicy` with `enforce_jailing = true` (resolving Epic 4 Retro Action Item 1):
  - All workspace paths are resolved using `std::fs::canonicalize` to produce absolute, physical paths free of symlinks and relative path indirection (`.` / `..`).
  - A dedicated validation function `guardian_core::plan::validate_sandbox_path(target_path: &Path, sandbox_root: &Path) -> Result<PathBuf, SandboxViolation>` verifies that `canonical_target.starts_with(canonical_sandbox_root)`.
  - For target paths that do not yet exist on disk (e.g. prospective new files created by the AI), the validator canonicalizes the nearest existing ancestor directory and lexically normalizes remaining child components, preventing breakout via paths like `/path/to/repo/../../etc/shadow`.
  - Any path attempting to reference locations outside `sandbox_root` is immediately flagged as a `SandboxViolation::OutsideWorkspaceBoundary { target: PathBuf, root: PathBuf }`.

- **AC5 (Symlink & Directory Traversal Breakout Mitigation):** Given symlinks within the repository pointing to external files (e.g. `repo/link_to_root -> /` or `repo/ssh_link -> ~/.ssh`):
  - The path canonicalizer resolves the true filesystem destination of symlinks before evaluating boundary constraints.
  - If a symlink points outside the canonical workspace root, any operation attempting to traverse or resolve that symlink is rejected as a sandbox violation.
  - Prompt payloads and tool call invocations containing traversal patterns (e.g. `../../`, `/etc/passwd`, `~/.aws/credentials`) are blocked or sanitized according to the sandbox policy.

- **AC6 (Proxy AppState Integration & Silent Unattended Operation):** Given an approved `.guardian-plan.json` present in the current working directory:
  - When `guardian-cli` launches the proxy server (`run_server_internal` / `run_server_with_trust`), it discovers `.guardian-plan.json`, verifies `approved == true`, and injects the `PreflightPlan` into `AppState.preflight_plan` wrapped in an `Arc`.
  - During request handling in `chat_completions_handler`:
    - Requests operating on files identified in `sensitive_zones` are processed silently using the pre-approved mitigation strategy (`Redact` replaces with token placeholders; `Mock` uses deterministic synthetic placeholders).
    - Outbound requests and inbound tool actions are validated against the `SandboxPolicy`; out-of-bounds file access attempts are blocked with a `403 Forbidden` / `SandboxViolation` response and logged.
    - Zero user prompts or manual interaction interrupts occur during proxy execution.

- **AC7 (Comprehensive Test Suite & Zero-Warning Compliance):** Given unit, integration, and security tests across all workspace crates:
  - Unit tests in `guardian-core` verify: plan generation, JSON serialization/deserialization, path canonicalization, non-existent path normalization, symlink breakout detection, and traversal rejection.
  - Unit tests in `guardian-cli` verify: CLI argument parsing for `preflight` (`--yes`, `--dry-run`, `--path`, `--show`, `--clear`), and terminal report formatting.
  - Integration tests in `guardian-proxy` verify: proxy initialization with active `PreflightPlan`, silent redaction of planned sensitive zones, and sandbox violation blocking for out-of-repo paths.
  - All workspace tests pass (`cargo test --workspace`) and `cargo clippy --workspace -- -D warnings` returns 0 warnings with 100% `cargo fmt` adherence.

---

## Tasks / Subtasks

- [x] **Task 1: Pre-Flight Plan & Sandbox Data Model in `crates/guardian-core/src/plan.rs`** (AC: #1, #2, #4)
  - [x] 1a. Create `crates/guardian-core/src/plan.rs` and export module in `crates/guardian-core/src/lib.rs`.
  - [x] 1b. Define `PreflightPlan`, `SensitiveZone`, `ZoneStrategy`, `SandboxPolicy`, and `SandboxViolation` structs/enums with Serde derive.
  - [x] 1c. Implement `PreflightPlan::from_json_str` and `PreflightPlan::to_json_string` with versioning support.
  - [x] 1d. Implement `PreflightPlan::load_from_file(path: &Path) -> Result<Option<PreflightPlan>, CoreError>` with fail-safe error handling and `tracing::warn!` on malformed files.
  - [x] 1e. Implement `PreflightPlan::save_to_file(path: &Path) -> Result<(), CoreError>` creating atomic parent directories if needed.

- [x] **Task 2: Path Canonicalization & Sandbox Jailing Engine in `crates/guardian-core/src/plan.rs`** (AC: #4, #5)
  - [x] 2a. Implement `canonicalize_path(path: &Path) -> Result<PathBuf, std::io::Error>`.
  - [x] 2b. Implement `normalize_virtual_path(path: &Path, root: &Path) -> Result<PathBuf, SandboxViolation>` to safely resolve non-existent target paths relative to canonical root.
  - [x] 2c. Implement `validate_sandbox_path(target: &Path, root: &Path) -> Result<PathBuf, SandboxViolation>` enforcing `canonical_target.starts_with(canonical_root)`.
  - [x] 2d. Implement symlink evaluation ensuring target dereferencing does not escape `sandbox_root`.
  - [x] 2e. Implement helper `is_path_within_sandbox(target: &Path, root: &Path) -> bool`.

- [x] **Task 3: Workspace Scanner & Pre-Flight Plan Generator in `crates/guardian-core/src/plan.rs`** (AC: #1, #2)
  - [x] 3a. Implement `generate_preflight_plan(workspace_root: &Path, max_file_size: u64, per_file_timeout_ms: u64) -> Result<PreflightPlan, CoreError>`.
  - [x] 3b. Use `ignore::WalkBuilder` to discover files respecting `.gitignore`, `.ignore`, and directory exclusion rules (`target`, `node_modules`, `.git`, `.venv`, `.cargo`, `dist`, `build`, `vendor`, `.turbo`, `.next`).
  - [x] 3c. Scan discovered file contents with `collect_regex_matches` (Tier 1 regex engine) to identify secret tokens.
  - [x] 3d. Identify high-risk configuration/secret files based on file naming heuristics (`.env*`, `*.pem`, `*.key`, `credentials.*`, `id_rsa*`).
  - [x] 3e. Map discovered items to `SensitiveZone` entries with relative paths and default `ZoneStrategy::Redact`.

- [x] **Task 4: Wire Pre-Flight Plan into `AppState` & Proxy Interception in `crates/guardian-proxy`** (AC: #6)
  - [x] 4a. Update `AppState` in `crates/guardian-proxy/src/lib.rs` to include `pub preflight_plan: Option<Arc<guardian_core::plan::PreflightPlan>>`.
  - [x] 4b. Update `create_app` and proxy constructors to support `preflight_plan`.
  - [x] 4c. Update `chat_completions_handler` in `crates/guardian-proxy/src/proxy.rs`:
    - When `preflight_plan` is present, log plan execution mode via `tracing::debug!`.
    - Apply silent redaction according to planned sensitive zones.
    - Validate any extracted file paths or references against the active `SandboxPolicy`, rejecting out-of-bounds requests with `ProxyError::Forbidden` (`403 Forbidden`).
  - [x] 4d. Update proxy integration tests in `crates/guardian-proxy/tests/integration_tests.rs` and `sse_passthrough.rs` to initialize `AppState` with `preflight_plan: None` (or mock plan).

- [x] **Task 5: CLI Subcommand Wiring & Interactive Approval Flow in `crates/guardian-cli`** (AC: #3, #6)
  - [x] 5a. Create `crates/guardian-cli/src/preflight.rs` with `PreflightCliArgs` (`path`, `yes`, `dry_run`, `output`, `show`, `clear`).
  - [x] 5b. Implement `run_preflight(args: PreflightCliArgs) -> Result<(), Box<dyn std::error::Error>>`.
  - [x] 5c. Implement formatted ANSI terminal table rendering (`print_preflight_plan_table`).
  - [x] 5d. Implement interactive confirmation prompt (`read_approval_from_stdin`).
  - [x] 5e. Wire `preflight` subcommand into `crates/guardian-cli/src/main.rs` and `crates/guardian-cli/src/lib.rs`.
  - [x] 5f. Update `run_server_internal` and `run_server_with_trust` to discover `.guardian-plan.json` in `cwd`, load if `approved == true`, and inject into `AppState`.

- [x] **Task 6: Comprehensive Unit, Integration, and Security Tests** (AC: #7)
  - [x] 6a. Unit tests in `crates/guardian-core/src/plan.rs`:
    - Plan generation on mock directories with planted secrets and `.env` files.
    - JSON serialization and round-trip deserialization.
    - `validate_sandbox_path` with valid relative and absolute paths within sandbox.
    - `validate_sandbox_path` detecting traversal breakouts (`../../etc/passwd`, `/var/log`).
    - Symlink breakout detection (symlink pointing outside workspace root).
    - Non-existent path normalization and boundary enforcement.
  - [x] 6b. Unit tests in `crates/guardian-cli/src/preflight.rs`:
    - Argument parsing and flag precedence (`--dry-run`, `--yes`, `--show`, `--clear`).
    - Formatted table rendering.
  - [x] 6c. Integration tests in `crates/guardian-proxy/tests/integration_tests.rs`:
    - Start proxy with approved `PreflightPlan`.
    - Verify silent redaction on requests matching planned zones.
    - Verify sandbox boundary enforcement with 403 Forbidden.
  - [x] 6d. Workspace verification: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo fmt --check`.

---

## Dev Notes

### Architecture & Design Decisions

#### 1. Preflight Plan Data Model (CAP-6, AD-12, AD-13)

The pre-flight security plan is stored locally at the project root as `.guardian-plan.json` (or `.guardian/preflight-plan.json`). It represents an explicit contract between the developer and the firewall proxy for unattended sessions:

```rust
// crates/guardian-core/src/plan.rs

use crate::redact::PiiType;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreflightPlan {
    pub version: u32,
    pub workspace_root: PathBuf,
    pub created_at: u64,
    pub sensitive_zones: Vec<SensitiveZone>,
    pub sandbox: SandboxPolicy,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensitiveZone {
    pub relative_path: PathBuf,
    pub secret_types: Vec<PiiType>,
    pub match_count: usize,
    pub strategy: ZoneStrategy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneStrategy {
    Redact,
    Mock,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxPolicy {
    pub root: PathBuf,
    pub enforce_jailing: bool,
    #[serde(default)]
    pub allow_subpaths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    OutsideWorkspaceBoundary { target: PathBuf, root: PathBuf },
    SymlinkBreakout { symlink: PathBuf, target: PathBuf, root: PathBuf },
    InvalidPath(String),
}
```

#### 2. Path Canonicalization & Sandbox Jailing Specification (Epic 4 Action Item 1)

AI agent harnesses (Claude Code, Cursor, Aider) often operate autonomously by generating terminal commands or file read/write API calls. A prompt injection or hallucination could cause the agent to inspect `/etc/passwd`, `~/.aws/credentials`, `~/.ssh/id_rsa`, or parent repositories.

To enforce deterministic workspace jailing:
1. **Canonicalization of Root:**
   The workspace root is canonicalized on plan creation and proxy startup using `std::fs::canonicalize(root)`.
2. **Canonicalization of Targets:**
   For any file target `P`:
   - If `P` exists on disk: `canonical_p = std::fs::canonicalize(P)?`.
   - If `P` does not exist (prospective write/creation): find the deepest existing ancestor directory `A`, canonicalize `A`, and append the remaining normalized relative path components `R`, ensuring no `..` components escape `A`.
3. **Boundary Invariant:**
   `canonical_p.starts_with(&canonical_root)` MUST be `true`.
4. **Symlink Resolution:**
   `std::fs::canonicalize` follows symlinks to their ultimate physical target. If a workspace contains `my_symlink -> /etc/hosts`, `canonicalize("my_symlink")` resolves to `/etc/hosts`, which fails `starts_with(canonical_root)` and is rejected with `SandboxViolation::SymlinkBreakout`.

```rust
// Sandbox validation algorithm
pub fn validate_sandbox_path(target: &Path, root: &Path) -> Result<PathBuf, SandboxViolation> {
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|e| SandboxViolation::InvalidPath(format!("Failed to canonicalize root: {}", e)))?;

    let absolute_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    };

    let canonical_target = if absolute_target.exists() {
        std::fs::canonicalize(&absolute_target)
            .map_err(|e| SandboxViolation::InvalidPath(format!("Failed to canonicalize target: {}", e)))?
    } else {
        normalize_virtual_path(&absolute_target, &canonical_root)?
    };

    if canonical_target.starts_with(&canonical_root) {
        Ok(canonical_target)
    } else {
        Err(SandboxViolation::OutsideWorkspaceBoundary {
            target: canonical_target,
            root: canonical_root,
        })
    }
}
```

#### 3. CLI Subcommand Design & User Experience (Epic 4 Action Item 3)

Command signature:
```bash
llm-firewall preflight [OPTIONS]
```

Flags and Options:
- `-p, --path <DIR>`: Target workspace directory (default: `.`)
- `-y, --yes`: Auto-approve plan without interactive prompt (for CI/CD and scripts)
- `--dry-run`: Output JSON plan to stdout without writing `.guardian-plan.json`
- `-o, --output <FILE>`: Custom plan file path (default: `.guardian-plan.json`)
- `--show`: Display the active plan status for the current directory
- `--clear`: Remove existing `.guardian-plan.json`

Example Interactive Terminal Output:
```text
================================================================================
           LLM FIREWALL — PRE-FLIGHT SECURITY PLAN GENERATION
================================================================================
Workspace Root: /Users/devgoyal/desktop/my-saas-app
Sandbox Status: ENFORCED (Jailed to workspace root)
--------------------------------------------------------------------------------
Found 4 sensitive file zones:

  FILE PATH                   SECRET TYPES                  MATCHES   STRATEGY
  -----------------------------------------------------------------------------
  .env.production             [AwsKey, BearerToken, Url]    6         Redact
  config/database.json        [DatabaseUri, Password]       2         Redact
  certs/server.key            [PrivateKey]                  1         Redact
  src/config/jwt.ts           [JwtSecret]                   1         Redact

Sandbox Boundaries:
  - All file access outside /Users/devgoyal/desktop/my-saas-app will be BLOCKED.
  - Symlink breakouts pointing outside workspace root will be QUARANTINED.
--------------------------------------------------------------------------------
Approve this pre-flight security plan for unattended session? [y/N]: y

✅ Pre-flight plan approved and saved to .guardian-plan.json.
   Proxy will operate silently within these pre-approved bounds.
```

#### 4. Thread-Safe AppState Sharing (AD-13)

- `AppState` in `crates/guardian-proxy/src/lib.rs` stores:
  ```rust
  pub preflight_plan: Option<Arc<guardian_core::plan::PreflightPlan>>,
  ```
- When `run_server_internal` starts:
  1. It checks `cwd.join(".guardian-plan.json")`.
  2. If found and `plan.approved == true`, it wraps the plan in `Arc::new(...)` and passes to `AppState`.
  3. `chat_completions_handler` accesses `state.preflight_plan` without acquiring async locks (read-only immutable `Arc`).

---

## Project Structure Notes

### Existing Modules to Modify
- `crates/guardian-core/src/lib.rs` (Export `plan` module and `PreflightPlan` / `SandboxPolicy` types).
- `crates/guardian-proxy/src/lib.rs` (Add `preflight_plan` field to `AppState`).
- `crates/guardian-proxy/src/proxy.rs` (Enforce silent mode and sandbox validation).
- `crates/guardian-cli/src/main.rs` (Add `preflight` subcommand dispatch).
- `crates/guardian-cli/src/lib.rs` (Load `.guardian-plan.json` during server startup).

### New Modules to Create
- `crates/guardian-core/src/plan.rs` (Core data models, scanner, path canonicalizer, sandbox jailing engine).
- `crates/guardian-cli/src/preflight.rs` (CLI command handler, table renderer, interactive prompt).

---

## Testing Requirements

### Unit Tests
- `crates/guardian-core/src/plan.rs`:
  - `test_preflight_plan_serialization_roundtrip`: JSON serialization and deserialization.
  - `test_generate_preflight_plan_detects_secrets`: Discovers secrets across files in mock directory.
  - `test_validate_sandbox_path_inside_workspace`: Accepts valid paths within root.
  - `test_validate_sandbox_path_rejects_traversal`: Blocks `../../etc/passwd` and absolute `/etc/shadow`.
  - `test_validate_sandbox_path_symlink_breakout`: Blocks symlinks pointing outside workspace.
  - `test_validate_sandbox_path_nonexistent_file`: Resolves virtual non-existent target within sandbox.
- `crates/guardian-cli/src/preflight.rs`:
  - `test_preflight_cli_args_defaults`: Verifies default options.
  - `test_print_preflight_plan_table`: Verifies ANSI table formatting output without panic.

### Integration Tests
- `crates/guardian-proxy/tests/integration_tests.rs`:
  - `test_proxy_with_approved_preflight_plan`: Starts test proxy with pre-flight plan; verifies silent redaction on sensitive zone endpoints and sandbox blocking on out-of-bounds paths.

---

## References

- [Architecture Spine v2](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md) — AD-12 (Workspace Shape), AD-13 (Request-Scoped State), AD-17 (Foreground Orchestrator).
- [SPEC-guardian-ai-v2](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/specs/spec-guardian-ai-v2/SPEC.md) — CAP-6 (Pre-flight security plan).
- [Epics Document](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/planning-artifacts/epics.md#L281-L299) — Epic 5: Unattended Autonomy & Compliance Reporting, Story 5.1.
- [Epic 4 Retrospective](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/implementation-artifacts/epic-4-retro-2026-08-27.md) — Action Item 1 (Sandbox Boundary Spec) and Action Item 3 (CLI Commands).
- [Project Context Rules](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/project-context.md) — Rust, Axum, Concurrency, and Context Hygiene Invariants.

---

## Dev Agent Record
 
 ### Agent Model Used
-- `gemini-2.5-pro` (via `bmad-create-story`)
+- `gemini-2.5-pro` (via `bmad-dev-story`)
 
-### Debug Log References
-- No runtime debug logs generated during story creation.
+### Test Results
+- Workspace Tests: 91 passed; 0 failed; 0 filtered out (`cargo test --workspace`)
+  - `guardian-core`: 41 unit tests + 7 benchmark tests passed
+  - `guardian-proxy`: 4 unit tests + 10 integration tests + 7 sse_passthrough tests passed
+  - `guardian-cli`: 22 unit tests passed
+- Lints: `cargo clippy --workspace -- -D warnings` passed with 0 warnings
+- Formatting: `cargo fmt --check` passed with 100% adherence
 
 ### Completion Notes List
-- Comprehensive Story 5.1 specification created following BMAD standard.
-- Formulated path canonicalization and sandbox boundary specification resolving Epic 4 Retro Action Item 1.
-- Designed pre-flight plan data structures, workspace scanner, and bulk approval workflow resolving Epic 4 Retro Action Item 3.
-- Specified thread-safe immutable `Arc<PreflightPlan>` injection into Axum `AppState`.
+- Implemented `guardian_core::plan` module with `PreflightPlan`, `SensitiveZone`, `ZoneStrategy`, `SandboxPolicy`, `SandboxViolation`, and `generate_preflight_plan`.
+- Implemented path canonicalization (`validate_sandbox_path`, `normalize_virtual_path`, `canonicalize_path`, `is_path_within_sandbox`) with symlink breakout detection and non-existent path normalization.
+- Extended `AppState` in `guardian-proxy` with `Option<Arc<PreflightPlan>>` for thread-safe immutable pre-flight plan sharing without locking across `.await`.
+- Implemented sandbox boundary jailing in `chat_completions_handler` rejecting directory traversal and out-of-boundary payloads with `403 Forbidden` (`ProxyError::Forbidden`).
+- Implemented `llm-firewall preflight` CLI subcommand with `--path`, `--yes`, `--dry-run`, `--show`, `--clear`, `--output`, and interactive approval prompt.
+- Auto-discovery of approved `.guardian-plan.json` on server startup (`run_server_internal` / `run_server_with_trust`).
 
 ### File List
-- `docs/implementation-artifacts/story-5.1-pre-flight-security-plan-generation.md` (New Story Specification)
+- `crates/guardian-core/Cargo.toml` (Added `ignore = "0.4.30"`)
+- `crates/guardian-core/src/plan.rs` (New plan data models, workspace scanner, path canonicalization engine)
+- `crates/guardian-core/src/lib.rs` (Exported `plan` module and types)
+- `crates/guardian-proxy/Cargo.toml` (Added `tempfile` to dev-dependencies)
- `crates/guardian-core/Cargo.toml` (Added `ignore = "0.4.30"`)
- `crates/guardian-core/src/plan.rs` (New plan data models, scanner, path canonicalization engine)
- `crates/guardian-core/src/lib.rs` (Exported `plan` module and types)
- `crates/guardian-proxy/Cargo.toml` (Added `tempfile` to dev-dependencies)
- `crates/guardian-proxy/src/lib.rs` (Added `preflight_plan` to `AppState`)
- `crates/guardian-proxy/src/proxy.rs` (Added `ProxyError::Forbidden` and sandbox validation)
- `crates/guardian-proxy/tests/integration_tests.rs` (Updated `AppState` and added preflight integration tests)
- `crates/guardian-proxy/tests/sse_passthrough.rs` (Updated `AppState`)
- `crates/guardian-cli/src/preflight.rs` (New CLI preflight subcommand and ANSI table formatter)
- `crates/guardian-cli/src/main.rs` (Dispatched `preflight` subcommand)
- `crates/guardian-cli/src/lib.rs` (Exported `preflight` module and loaded `.guardian-plan.json` in server startup)
- `docs/implementation-artifacts/story-5.1-pre-flight-security-plan-generation.md` (Updated story spec)
- `docs/implementation-artifacts/sprint-status.yaml` (Updated sprint tracking status)

### Adversarial Code Review (bmad-code-review)
 - Conducted thorough adversarial review covering security posture, async lock safety, and invariants.
 - **Findings and Fixes:**
   - **Path Canonicalization Bypass:** Fixed a critical bug in `normalize_virtual_path` where an absolute path missing all ancestor directories (e.g. `/etc/nonexistent`) incorrectly normalized into the workspace root (e.g. `/workspace/etc/nonexistent`), allowing absolute path traversals for nonexistent files to bypass the sandbox. Fixed by strictly rejecting absolute paths with no existing ancestors in the workspace.
   - **Shell Injection Path Evasion:** Fixed `inspect_json_for_sandbox_violations` which only validated strings strictly starting with `/`. A JSON payload like `{"command": "cat /etc/passwd"}` would previously bypass validation. Fixed by tokenizing JSON string fields and scanning all words for traversal patterns (`/`, `~/`, `../`, `..`).
   - **Fail-closed Invariant Breach:** Fixed `guardian-cli/src/lib.rs` where a corrupt `.guardian-plan.json` file on startup would emit a warning and silently operate without a plan (permissive mode) instead of failing safely. Fixed by exiting with code `1`.
 - All tests and clippy passed.
 - Status updated to done.
