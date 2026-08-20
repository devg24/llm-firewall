# Roadmap: Elevating llm-firewall-rs to a Top 1% Open-Source Project

This document outlines a phased approach to evolving `llm-firewall-rs` from its current foundational state (~2K lines, basic regex + NER) into a state-of-the-art, professionally engineered, and highly adoptable developer tool.

---

## Phase 1: Engineering Foundation (This Weekend)
**Goal:** Transform the codebase from a "weekend hack" to an elite engineering showcase. Prove stability, speed, and maintainability.

- **Refactor Monolithic Structure**
  - *What:* Break down the 4 massive files (`main.rs`, `proxy.rs`, `redact.rs`, `ml.rs`) into a modular crate workspace (e.g., `llm-firewall-core`, `llm-firewall-proxy`, `llm-firewall-cli`).
  - *Why:* Demonstrates clean architecture, makes the repo easier for open-source contributors to navigate, and isolates the proxy logic from the ML logic.
- **Implement Test Suite & CI/CD**
  - *What:* Add unit tests for core parsing/redaction logic, set up GitHub Actions for automated testing, linting (clippy), and formatting.
  - *Why:* No serious project lacks CI. This is the bare minimum for top 1% status and accepting external PRs.
- **Establish Benchmark Harness**
  - *What:* Integrate `criterion` for Rust benchmarking on the redaction pipeline. Publish sub-millisecond latency guarantees in CI.
  - *Why:* AI harness developers' biggest fear is latency. Concrete, verifiable benchmarks eliminate this objection instantly.
- **Draft Initial Architecture Docs**
  - *What:* Write a high-level `ARCHITECTURE.md` explaining the bidirectional proxy and stateful token mapping.
  - *Why:* Shows systems thinking and an ability to communicate complex tradeoffs.

---

## Phase 2: Detection Engine Upgrade (Week 1-2)
**Goal:** Build a state-of-the-art, 4-tier detection pipeline that outperforms basic regex scanners, becoming a core differentiator.

- **Implement Tier 2: Contextual Entropy Analysis**
  - *What:* Build a sliding-window Shannon entropy scanner that evaluates high-entropy strings, coupled with local context checking (e.g., looking for "api_key=" vs. base64 image data).
  - *Why:* Novel approach not found in typical scanners. It catches unknown secrets that regex misses without generating false positives on UUIDs/hashes.
- **Upgrade Tier 1: Aho-Corasick Integration**
  - *What:* Replace basic regex matching with Aho-Corasick for O(n) simultaneous multi-pattern matching.
  - *Why:* Drastically improves performance when scanning against hundreds of known secret patterns simultaneously.
- **Introduce Confidence Scoring System**
  - *What:* Assign a 0.0 to 1.0 confidence score to every detection. Allow users to tune the redaction threshold (default: 0.7).
  - *Why:* Provides flexibility for different environments and shows maturity in ML/heuristics design.
- **Precision/Recall Benchmarking**
  - *What:* Create a golden dataset of dummy secrets and safe code. Measure and publish F1 scores.
  - *Why:* Proves the engine's effectiveness empirically. "We catch 99% of secrets with 0.1% false positives."

---

## Phase 3: Product Polish (Week 3-4)
**Goal:** Create a "zero-config" viral developer experience that converts users immediately.

- **CLI First-Run "Scare Report"**
  - *What:* On first execution, silently scan the local repo and output a summary of exposed secrets that *would* have been leaked to an LLM provider.
  - *Why:* This is the conversion engine. It makes the abstract threat real and immediate for non-security-conscious developers.
- **Zero-Config Installation & Auto-Detection**
  - *What:* Enable a `brew install llm-firewall && llm-firewall on` workflow that automatically discovers installed AI tools (Claude Code, Cursor) and patches their proxy settings.
  - *Why:* The path of least resistance wins. If it requires 10 minutes of YAML config, developers will skip it.
- **Pre-Flight Security Plan for Long-Haul Tasks**
  - *What:* Before long unattended AI runs, provide a summary of likely accessed files and request bulk approval for redaction/mocks.
  - *Why:* Solves "prompt fatigue" where the firewall interrupts the user every 5 minutes during an overnight coding task.
- **Session Audit & Stats Command**
  - *What:* Add a `llm-firewall stats` command showing lifetime secrets caught. Generate post-session compliance reports showing "exposure cost avoided."
  - *Why:* Creates a shareable flex for Twitter/Slack and acts as the "Permission Slip" for enterprise compliance.

---

## Phase 4: Community & Traction (Month 2-3)
**Goal:** Launch the project, acquire users, and cement the resume narrative.

- **README Overhaul**
  - *What:* Redesign the README to focus on the "You never have to ___ again" value prop. Include pipeline diagrams, sub-millisecond benchmarks, and F1 scores.
  - *Why:* The README is the landing page. It needs to sell the tool in 5 seconds.
- **Publish Architecture Decision Records (ADRs)**
  - *What:* Document complex decisions, like solving the bidirectional re-injection risk (preventing prompt-injected LLMs from extracting secrets via the proxy).
  - *Why:* The ultimate interview talking point. Shows deep, second-order systems thinking to potential employers.
- **Write Harness Integration Guides**
  - *What:* Provide copy-paste guides for using the firewall with popular tools like Claude Code, Cursor, and Copilot CLI.
  - *Why:* Reduces friction for adoption within existing workflows.
- **Execute Launch Strategy**
  - *What:* Coordinate launches on Hacker News, r/rust, r/programming, and Twitter using the "Scare Report" and "Contextual Entropy" as the main hooks.
  - *Why:* Drives the initial wave of GitHub stars, user feedback, and potential contributors needed for top 1% validation.
