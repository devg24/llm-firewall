---
id: SPEC-guardian-ai-v2
companions:
  - detection-pipeline.md
  - harness-integration.md
sources:
  - ../../brainstorming/brainstorm-elevate-llm-firewall-2026-08-18/brainstorm-intent.md
  - ../../brainstorming/brainstorm-elevate-llm-firewall-2026-08-18/roadmap.md
---

> **Canonical contract.** This SPEC and the files in `companions:` are the complete, preservation-validated contract for what to build, test, and validate. Source documents listed in frontmatter are for traceability only — consult them only if you need narrative rationale or prose color this contract intentionally omits.

# Guardian-AI v2: Fearless AI Pairing Middleware

## Why

Individual developers are locked out of the AI-assisted coding revolution on the work that matters most. Proprietary codebases, NDA repos, startup pre-launch code, and client projects are too sensitive to expose to external LLM APIs — so developers either hand-code everything while watching others 10x with AI, or they silently leak secrets and hope nobody notices. No existing tool sits in the live AI conversation stream as a transparent, zero-config proxy. Guardian-AI v2 captures this opportunity by becoming the invisible safety net that lets any developer use Claude Code, Cursor, or Copilot on any repo without risking data exfiltration — "the tool that gets AI unbanned at your company." The project simultaneously serves as a top 1% open-source portfolio piece demonstrating elite Rust systems engineering, novel detection algorithms, and professional-grade ML pipeline design.

## Capabilities

- **CAP-1: Bidirectional stateful proxy**
  - **intent:** Intercept all LLM API traffic transparently via HTTP_PROXY, replacing detected secrets with indexed placeholder tokens outbound and re-injecting real values into LLM-generated output inbound, so the AI harness operates identically to an unproxied session.
  - **success:** A full Claude Code coding session on a repo containing known secrets produces identical functional output (diffs, commands, files) as an unproxied session, with zero secrets appearing in outbound API request logs.

- **CAP-2: 4-tier cascading detection pipeline**
  - **intent:** Detect sensitive data across four complementary tiers — pattern matching, entropy analysis, named entity recognition, and contextual classification — so that known, unknown, and context-dependent secrets are all caught.
  - **success:** Published F1 score ≥ 0.95 across a golden test dataset containing mixed secret types, with each tier's individual precision/recall and latency benchmarked and documented. See `detection-pipeline.md`.

- **CAP-3: Contextual entropy analysis**
  - **intent:** Identify high-entropy strings (API keys, tokens, passwords with no known pattern) using Shannon entropy scoring combined with surrounding-token context analysis, assigning a confidence score (0.0–1.0) to each detection with a per-tier tunable redaction threshold.
  - **success:** Catches ≥ 90% of unknown-format API keys in the golden dataset while suppressing ≥ 95% of safe high-entropy strings (UUIDs, base64 images, hashed passwords in migrations).

- **CAP-4: First-run scare report**
  - **intent:** On first execution in a repo, silently scan all files and display a summary of secrets that would have been leaked to an LLM provider, converting security-unaware developers into active users.
  - **success:** Running `llm-firewall scan` on a repo containing planted secrets produces a human-readable terminal report listing each finding by type, location, and estimated breach cost, completing in under 5 seconds for a 10K-file repo.

- **CAP-5: Zero-config CLI with auto-detection**
  - **intent:** Enable a two-command install-and-activate workflow (`brew install llm-firewall && llm-firewall on`) that automatically discovers installed AI tools, generates a local CA certificate trusted by the OS, and patches each tool's proxy configuration without requiring any manual config files. See `harness-integration.md`.
  - **success:** A developer with Claude Code installed can go from zero to protected in under 60 seconds with no config files created or edited manually.

- **CAP-6: Pre-flight security plan**
  - **intent:** Before long-haul unattended AI tasks, predict which files and sensitive zones will be accessed and request a single bulk approval for redaction/mock strategies, enabling fully silent operation for the remainder of the task.
  - **success:** A 2-hour unattended Claude Code session runs to completion with zero user interruptions after the initial pre-flight approval, with all sensitive encounters handled per the approved plan.

- **CAP-7: Session audit and stats**
  - **intent:** Track lifetime and per-session detection statistics and generate compliance-ready reports showing secrets caught, types detected, and estimated exposure cost avoided.
  - **success:** `llm-firewall stats` outputs a terminal summary of cumulative detections. `llm-firewall report` generates a shareable report suitable for compliance review or social sharing.

- **CAP-8: Context-aware output scanning**
  - **intent:** Before re-injecting real values into LLM output (inbound direction), analyze the destination context to prevent re-injection into dangerous sinks (network commands, file writes outside the repo, log statements).
  - **success:** A prompt-injected LLM that attempts to exfiltrate secrets via crafted `curl` commands or out-of-repo file writes is blocked, with the dangerous output quarantined and the user alerted.

- **CAP-9: Domain profile auto-detection**
  - **intent:** Scan project dependency manifests (Cargo.toml, package.json, go.mod, requirements.txt) to auto-detect the project's domain (e.g., crypto, healthcare, fintech) and adjust per-tier confidence thresholds accordingly, reducing false positives in specialized codebases.
  - **success:** A blockchain project with `ethers` or `solana` dependencies automatically receives a higher Tier 2 entropy threshold (0.85 vs default 0.6), preventing false positives on hardcoded public keys and test hashes without manual configuration.

- **CAP-10: Power-user configuration via `.guardian.toml`**
  - **intent:** Allow developers to define optional repository-level configuration in `.guardian.toml` to customize per-tier confidence thresholds, add custom regex patterns/entropy rules, specify allowlisted filepaths or variable names, and manually override auto-detected domain profiles.
  - **success:** Placing a valid `.guardian.toml` at the project root overrides default thresholds and auto-detected settings without breaking the fallback zero-config experience when the file is absent.

## Constraints

- Sub-millisecond p99 latency per interception on the proxy hot path. Tier 4 classifier is permitted 10–25ms but only executes on borderline-confidence spans (0.5–0.7), not on every interception.
- Zero `unsafe` Rust. The entire codebase must compile without any `unsafe` blocks, guaranteeing memory safety.
- Fail-closed security posture. Any failure in parsing, detection, or proxy logic halts the request with an error rather than passing potentially sensitive data through.
- Fully local execution. All detection (regex, entropy, NER, classification) runs on-device with no external API dependencies. Air-gap deployable.
- Published, reproducible benchmarks. Every detection tier must have CI-verified F1 scores and latency measurements against a versioned golden dataset.
- Local CA certificate generation. On activation, Guardian-AI generates a local CA cert and trusts it in the OS trust store (macOS `security add-trusted-cert`, Linux `update-ca-certificates`) rather than disabling TLS verification on proxied tools. Maintains full TLS security posture.
- Streaming re-injection operates at the SSE event level, not raw TCP bytes. SSE framing (`data: ...\n\n`) must never be corrupted by the re-injection process.
- Per-tier confidence thresholds, not a single global threshold. Tier 1 (deterministic patterns) bypasses thresholds entirely. Each tier evaluates against its own configured threshold. Merge step acts as tie-breaker for overlapping spans only.
- Graceful configuration fallback. If `.guardian.toml` is absent, the system defaults 100% to zero-config auto-detection. If `.guardian.toml` contains syntax or schema errors, Guardian-AI warns the user and falls back safely to default rules without failing open.

## Non-goals

- Enterprise sales, SSO, or multi-tenant administration. This is an individual developer tool; enterprise adoption is a bonus of bottom-up usage, not a design target.
- Training data collection. The firewall never phones home, logs prompts remotely, or feeds any analytics service.
- Full DLP (Data Loss Prevention) platform. The scope is LLM API traffic interception only, not email, Slack, or general network monitoring.
- Modifying or improving the LLM's output quality. The proxy is transparent to the AI's reasoning; it only redacts/re-injects data.

## Success signal

A solo developer installs Guardian-AI in under 60 seconds, runs the scare report on their work repo, sees concrete secrets that would have leaked, activates protection, and completes a full AI-assisted coding session with zero secrets in outbound traffic and zero degradation in task completion quality — then screenshots their stats and shares it with their team.

## Assumptions

- Individual developers will adopt via `brew install` or `cargo install`. No enterprise procurement channel is needed for initial traction.
- Claude Code respects `HTTP_PROXY`/`HTTPS_PROXY` environment variables for traffic routing (preferred over `ANTHROPIC_BASE_URL` override).
- Cursor and Copilot can be configured via programmatic `settings.json` patching (`http.proxy`, `http.proxySupport`, `http.proxyStrictSSL`).
- Tier 4 training data can be sourced from CodeSearchNet / Stack v2 by mining commits followed by key-rotation commits (positive) and test/doc directories (negative).
- `ort` (ONNX Runtime for Rust) is the primary inference path for Tier 4 — train in Python, export ONNX, run in Rust. `candle` remains for Tier 3 BERT NER (already integrated).
- Power-user settings in `.guardian.toml` follow standard TOML syntax and reside in the project root or user home directory (`~/.guardian.toml`).

## Open Questions

<!-- All core open questions resolved. -->
