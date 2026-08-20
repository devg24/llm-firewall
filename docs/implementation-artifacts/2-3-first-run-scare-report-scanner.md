---
baseline_commit: 0fa5e52e64d9b7250f258dc0eec7511ad873a646
---
# Story 2.3: First-Run Scare Report Scanner
Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want the `llm-firewall scan` command to quickly scan my local repository and print a formatted summary of detected secrets,
So that I can see the immediate value and risk exposure before I even activate the proxy.

## Acceptance Criteria

1. **Given** the user runs `llm-firewall scan` in a repository
   **When** the command executes
   **Then** it traverses all non-gitignored files (under 5 seconds for a 10K file repo)
2. **And** the scanner enforces explicit file-size limits and timeouts per file to prevent DoS from malicious repositories
3. **And** applies the detection engine to find secrets
4. **And** prints a human-readable terminal report detailing the findings and estimated breach cost
5. **And** unit tests verify the scanner correctly respects `.gitignore` rules and accurately formats the terminal report.

## Tasks / Subtasks

- [x] Task 1 (AC: 1, 2) Implement File Discovery and Bounds
  - [x] Use `ignore` or `walkdir` crate to implement fast traversal of non-gitignored files.
  - [x] Implement explicit file-size limits and timeouts per file to skip overly large files.
- [x] Task 2 (AC: 3) Integrate Detection Engine
  - [x] Initialize the detection pipeline from `guardian-core`.
  - [x] Scan discovered files asynchronously using `guardian-core` tier detection.
- [x] Task 3 (AC: 4) Implement Scare Report Output Formatting
  - [x] Format terminal report with findings.
  - [x] Calculate and display estimated breach cost based on findings.
- [x] Task 4 (AC: 5) Testing
  - [x] Write unit tests to verify `.gitignore` is respected.
  - [x] Write unit tests for the terminal report format and breach cost calculation.
  - [x] Write unit tests for file-size limit enforcement and timeouts.

## Dev Notes

- **Architecture Constraints:**
  - CAP-4 (Scare report) lives in `guardian-cli` and is governed by AD-12 (Workspace structure).
  - Depends on `guardian-core` for the detection pipeline logic.
- **Previous Learnings (Story 2.2 / 2.1):**
  - Ensure zero `unsafe` Rust.
  - Adhere to the `guardian-cli` error handling and CLI patterns established by `patcher.rs`.
- **Performance considerations:** The scan must finish in under 5 seconds for a 10K file repo. Using the `ignore` crate in parallel mode (`WalkBuilder` with multiple threads) might be required. Be mindful of locking when aggregating results.

### Project Structure Notes

- New code belongs in the `guardian-cli` crate (e.g. `crates/guardian-cli/src/scanner.rs` or similar subcommand module).
- The `scan` subcommand must be registered in the `clap` parser in `crates/guardian-cli/src/main.rs`.

### References

- Epic breakdown: [Source: docs/planning-artifacts/epics.md#Story 2.3: First-Run Scare Report Scanner]
- Architecture Spine: [Source: docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md]
- Previous Story Intelligence: [Source: docs/implementation-artifacts/2-2-ai-harness-config-auto-patcher.md]

## Dev Agent Record

### Agent Model Used
- Antigravity Model

### Debug Log References

### Completion Notes List
+- Implemented `scanner.rs` with `WalkBuilder` that skips large files and respects `.gitignore`.
+- Spawns asynchronous tasks to read file contents and uses `guardian-core::collect_regex_matches` for detection.
+- Includes estimated breach cost calculation mapped to `PiiType` enum variants.
+- Updated `guardian-cli` main to handle `scan` subcommand.
+- Added unit tests for ignore parsing, file size bounds, and cost calculation.

### File List
+- `crates/guardian-cli/Cargo.toml`
+- `crates/guardian-cli/src/main.rs`
+- `crates/guardian-cli/src/lib.rs`
+- `crates/guardian-cli/src/scanner.rs`
