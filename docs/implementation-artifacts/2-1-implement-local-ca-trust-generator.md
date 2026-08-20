---
baseline_commit: 301e0631317126de8dd29c7a614332245c705e7a
---
# Story 2.1: Implement Local CA Trust Generator

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a developer,
I want the CLI to generate a local CA certificate and trust it in the OS trust store on activation,
so that TLS interception works seamlessly without forcing me to disable strict SSL in my tools.

## Acceptance Criteria

1. **Given** a developer starting `llm-firewall on`
   **When** the proxy initializes
   **Then** it generates a local CA certificate and runs the appropriate OS commands (e.g., macOS `security add-trusted-cert`)
2. **And** upon graceful shutdown (Ctrl+C), the certificate is cleanly removed from the OS trust store
3. **And** automated tests verify the certificate generation logic and that the OS commands are correctly formulated.

## Tasks / Subtasks

- [x] Task 1 (AC: 1, 2) Implement CA Certificate Generation and Trust Management
  - [x] Implement local CA certificate generation using a suitable Rust cryptography library (e.g. `rcgen`).
  - [x] Implement macOS OS trust integration (using `security add-trusted-cert`).
  - [x] Ensure graceful shutdown hook (Ctrl+C) un-trusts the CA cert using OS commands (e.g. `security remove-trusted-cert`).
- [x] Task 2 (AC: 1, 2) Integrate with the CLI Orchestrator
  - [x] In `guardian-cli`, handle `llm-firewall on` to trigger the CA generation and trust logic.
  - [x] Block the process running the proxy, and use `tokio::signal::ctrl_c` for graceful shutdown handling to untrust the cert.
- [x] Task 3 (AC: 3) Testing
  - [x] Write unit and integration tests to verify the CA generation logic.
  - [x] Verify that OS commands are correctly formulated and handled (using mocks/fakes where necessary to avoid modifying the host system during tests).

### Review Findings
- [x] [Review][Patch] Insecure Key Permissions
- [x] [Review][Patch] Reckless CA Constraints
- [x] [Review][Patch] Silent Failures on Unsupported Platforms
- [x] [Review][Patch] Panics on Non-UTF8 Paths
- [x] [Review][Patch] Destructive Shutdown Sequence
- [x] [Review][Patch] Fragile Signal Registration
- [x] [Review][Patch] Blind Command Execution
- [x] [Review][Patch] Extraneous Garbage Committed
- [x] [Review][Patch] Redundant init_logging
- [x] [Review][Patch] Concurrent process race condition
- [x] [Review][Patch] SIGTERM instead of SIGINT
- [x] [Review][Patch] Redundant interior mutability in MockRunner
- [x] [Review][Defer] Unpredictable Artifact Placement — deferred, MVP context
- [x] [Review][Defer] Sloppy Argument Parsing — deferred, MVP context

## Dev Notes

- **Architecture:** 
  - (AD-17) Foreground Orchestrator: `llm-firewall on` sets OS configurations and blocks to run the proxy server in the foreground. Graceful shutdown (Ctrl+C) restores settings and untrusts the CA cert.
  - All this logic must live in `guardian-cli` (AD-12).
- Source tree components to touch:
  - `crates/guardian-cli/src/main.rs` and related modules to handle CLI `on` and OS trust.
- Testing standards summary:
  - Mock OS interactions to avoid the test suite modifying global state.
  - Ensure zero `unsafe` Rust.
  - Fail-closed security posture.

### Project Structure Notes

- New code belongs in the `guardian-cli` crate since it concerns CLI orchestrator behavior and tool patching/OS integration (AD-12).
- Ensure no circular dependencies between crates.

### References

- Epic breakdown: [Source: docs/planning-artifacts/epics.md#Story 2.1: Implement Local CA Trust Generator]
- Architecture Spine: [Source: docs/planning-artifacts/architecture/architecture-llm-firewall-rs-elevation-2026-08-19/ARCHITECTURE-SPINE.md]

## Dev Agent Record

### Agent Model Used
Gemini Pro

### Debug Log References
- Generated CA with `rcgen` and wrapped OS shell command execution to use `security add-trusted-cert`.
- Added mock-based testing for MacOS security commands.

### Completion Notes List
- ✅ Implemented local CA cert generation using `rcgen` and `tempfile` for tests.
- ✅ Added `run_server_with_trust` orchestrator which trusts certs using macOS keychain commands before starting `axum` and cleanly untrusts them upon receiving `ctrl_c`.
- ✅ All acceptance criteria met, 11/11 tests pass successfully.

### File List
- crates/guardian-cli/Cargo.toml
- crates/guardian-cli/src/main.rs
- crates/guardian-cli/src/lib.rs
- crates/guardian-cli/src/ca.rs
