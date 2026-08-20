---
baseline_commit: HEAD
---
# Story 2.2: AI Harness Config Auto-Patcher

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want the CLI to auto-detect installed AI tools (Cursor, Copilot, Claude Code) and inject proxy settings,
so that I don't have to manually edit config files or environment variables.

## Acceptance Criteria

1. **Given** the proxy is starting up
   **When** it detects Cursor `settings.json` or Copilot configs
   **Then** it patches `http.proxy` and `http.proxyStrictSSL` properties (or exports `HTTP_PROXY` for Claude Code)
2. **And** it restores the original configurations perfectly upon shutdown
3. **And** the CLI detects running IDE processes and prompts the user to restart them to ensure proxy settings take effect
4. **And** integration tests explicitly verify that JSON configuration files are correctly parsed, modified, and restored without data loss or formatting corruption.

## Tasks / Subtasks

- [x] Task 1 (AC: 1) Implement Config Auto-Patcher Logic
  - [x] Implement detection for Cursor `settings.json` and Copilot configs in `guardian-cli`.
  - [x] Implement JSON parsing and modification that preserves original formatting and comments.
  - [x] Inject `http.proxy` and `http.proxyStrictSSL` properties for Cursor/Copilot.
  - [x] Handle `HTTP_PROXY` environment requirements for Claude Code.
- [x] Task 2 (AC: 2) Implement Configuration Restoration
  - [x] Extend the existing graceful shutdown hook (from Story 2.1) in `guardian-cli` to revert config modifications back to their exact original state.
- [x] Task 3 (AC: 3) Detect IDE Processes
  - [x] Implement process detection to find running instances of Cursor or VSCode.
  - [x] Emit a console prompt suggesting the user restart their IDE to pick up the new proxy settings.
- [x] Task 4 (AC: 4) Testing
  - [x] Write integration tests verifying JSON files are modified and restored without formatting loss or data corruption.
  - [x] Write tests verifying process detection and graceful restoration on shutdown signal.

## Dev Notes

- **Architecture:** 
  - (AD-17) Foreground Orchestrator: `llm-firewall on` sets OS configurations and blocks to run the proxy server in the foreground. Graceful shutdown (Ctrl+C) restores settings.
  - (AD-12) Workspace: All CLI orchestration and OS/tool patching logic lives in the `guardian-cli` crate.
- Source tree components to touch:
  - `crates/guardian-cli/src/main.rs` (to hook into the `on` command and shutdown).
  - `crates/guardian-cli/src/` (new module for config patching and process detection).
- Testing standards summary:
  - Mock file system interactions for configuration patching tests.
  - Ensure zero `unsafe` Rust.
  - Fail-closed security posture (if patching fails, exit cleanly without running the proxy or inform the user).

### Project Structure Notes

- New code belongs in the `guardian-cli` crate.
- Coordinate with the graceful shutdown logic introduced in Story 2.1 (which untrusts the CA cert).

### References

- Epic breakdown: [Source: docs/planning-artifacts/epics.md#Story 2.2: AI Harness Config Auto-Patcher]
- Architecture Spine: [Source: docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md]
- Previous Story Intelligence: [Source: docs/implementation-artifacts/2-1-implement-local-ca-trust-generator.md] (Ensure graceful shutdown sequences compose correctly).

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List

### Review Findings

- [x] [Review][Patch] Missing VSCode (Copilot) settings detection and patching [crates/guardian-cli/src/patcher.rs]
- [x] [Review][Patch] Missing Default trait for ConfigPatcher [crates/guardian-cli/src/patcher.rs:12]
- [x] [Review][Patch] Manual string stripping [crates/guardian-cli/src/patcher.rs:122]
