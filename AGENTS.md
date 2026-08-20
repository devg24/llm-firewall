# Agent Guidelines & Context Hygiene Rules

These rules are always active for all AI agents working in this repository (`llm-firewall-rs`). Adhere strictly to these conventions to maintain high code quality, preserve session context, and prevent context bloat.

---

## 1. Context Bloat Prevention & Tool Hygiene

### File Editing Rules
- **Use `replace_file_content` for Modifications**: ALWAYS use `replace_file_content` for surgical updates, function modifications, and localized fixes.
- **NO Shell Redirection / `cat` for Code Edits**: Do NOT use bash `cat << 'EOF' > ...` or shell redirection to overwrite code files.
- **Use `write_to_file` Only for New Files or Full Rewrites**: Only use `write_to_file` when creating new files from scratch or performing an approved total rewrite of a small module.
- **Maintain Code Integrity**: When using `replace_file_content`, preserve all surrounding context, existing comments, and docstrings.

### File Reading & Inspection Rules
- **Bounded File Views**: Avoid reading whole files larger than 100 lines at once. Use `StartLine` and `EndLine` parameters with `view_file` to read only the relevant chunks.
- **Targeted Search**: Always supply `SearchDirectory` or `Includes` globs to `grep_search` and `find_by_name`. Never run open-ended searches across the entire workspace without excluding `target/`, `.venv/`, `.git/`, and build artifacts.
- **Never Echo Entire Files in Conversation**: Output concise diffs or summarize findings; do not repeat file contents back in markdown chat responses.

### Terminal & Command Execution Rules
- **Targeted Cargo Commands**: Run specific, targeted commands (e.g., `cargo test -p guardian-core test_name -- --nocapture` or `cargo clippy -p <crate>`) rather than workspace-wide verbose logs.
- **Silence / Filter Noisy Commands**: When running scripts or commands that output thousands of lines, pipe or limit the output (`head`, `tail`, `grep`, or flags like `--quiet` / `--summary`).
- **Never Run Interactive Commands**: Ensure all commands run in non-interactive mode with reasonable timeouts.

---

## 2. Delegation & Subagent Discipline

- **Delegate Deep Research**: For broad codebase sweeps, multi-file forensic traces, or cross-referencing external documentation, spawn a `research` or `self` subagent via `invoke_subagent`.
- **Keep Main Thread Clean**: Subagents perform high-token search and analysis in their own isolated context and report back only the final conclusion, keeping the primary session lean.

---

## 3. Artifact & BMAD Workflow Discipline

- **Persist Large State to Artifacts**: Store architecture plans, PRDs, sprint backlogs, and detailed checklists in `docs/` following the BMAD structure (`docs/planning-artifacts/`, `docs/implementation-artifacts/`, `docs/specs/`).
- **Reference via Links, Don't Re-summarize**: When an artifact is updated or created, link to it using `[Filename](file:///path/to/artifact.md)` and highlight only key questions or action items in the chat. Do not copy-paste the entire artifact into the response.
- **Check Project Context First**: Always consult [docs/project-context.md](file:///Users/devgoyal/desktop/llm-firewall-rs/docs/project-context.md) for Rust, Axum, ML, and async safety conventions.

---

## 4. Rust & Architecture Conventions (Summary)

- **Async Lock Safety**: Never hold `std::sync::Mutex` locks across `.await` points. Drop locks before awaiting.
- **Non-Blocking Runtime**: Offload heavy CPU-bound tasks (e.g., Candle / ORT inference, heavy regex sweeps) to `tokio::task::spawn_blocking`.
- **Axum State**: Request-scoped token maps and streaming MITM handlers must not be stored in global `AppState`.
- **Zero-Warning Policy**: All code must compile cleanly with `cargo clippy` and `cargo fmt`.
