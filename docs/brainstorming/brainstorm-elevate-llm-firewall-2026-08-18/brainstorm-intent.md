# Brainstorm Intent: Elevating llm-firewall-rs

## 1. Vision Statement
`llm-firewall-rs` is evolving from a basic redaction utility into an elite, invisible AIML middleware that enables "fearless AI pairing." It acts as an automatic safety net that allows developers to run powerful AI coding assistants (like Claude Code or Cursor) against proprietary, NDA, or highly sensitive codebases without ever risking data exfiltration or context pollution.

## 2. Core Value Proposition
- **The Angle:** "The Permission Slip" — the definitive tool that gets AI coding tools unbanned at your company, erasing the gap between how you code on personal projects and how you code at work.
- **Target User:** The individual developer (including the "vibe coder" who doesn't realize they are leaking secrets), not the enterprise security buyer.
- **Adoption Model:** Bottom-up. Build for the solo developer to drive organic adoption, treating enterprise compliance as a secondary bonus that follows developer love.

## 3. Key Product Decisions
- **UX Philosophy:** Zero-configuration and frictionless. Installation should be two commands (`brew install llm-firewall && llm-firewall on`) that automatically patch AI proxy settings without requiring YAML configs or environment variables.
- **Workflow:** Eliminate prompt fatigue. The firewall operates silently, using upfront "pre-flight security plans" for bulk approvals during long-haul unattended agentic tasks, rather than constantly interrupting the developer.
- **Positioning:** Sell peace of mind. "You never have to audit what your AI assistant saw again."

## 4. Technical Direction
- **Bidirectional Proxy:** A stateful proxy that swaps secrets for placeholders (e.g., `[REDACTED_1]`) outbound and perfectly re-injects real values inbound. The AI harness remains completely unaware, guaranteeing zero context pollution and unaltered benchmark performance.
- **4-Tier Detection Pipeline:**
  1. Aho-Corasick + regex for known patterns (near-zero cost).
  2. **Contextual Entropy Analysis** (The differentiator).
  3. Quantized BERT NER for named entities.
  4. Lightweight context-aware classifier.
- **Contextual Entropy:** Goes beyond blind Shannon entropy by analyzing surrounding tokens (e.g., strings near `api_key=` vs. inside base64 image URIs). It assigns a 0-1 confidence score to dynamically suppress false positives.

## 5. Engineering Quality Bar
To serve as a "top 1% resume project," the codebase must demonstrate elite systems craft:
- **Zero Unsafe Rust:** Absolute memory safety guarantees.
- **Sub-millisecond Latency:** Benchmarks published directly in CI.
- **Protocol-level Engineering:** Deep systems knowledge demonstrated through the bidirectional proxy implementation.
- **Algorithmic Originality:** Implementing Contextual Entropy rather than relying purely on off-the-shelf regex/ML libraries.
- **Tradeoff-driven Architecture Docs:** Professional-grade documentation detailing system design decisions and F1 scores/latency benchmarks for each detection tier.

## 6. Growth Strategy
- **The Scare Report:** The critical first-run onboarding experience. The tool silently scans the repo and displays exactly what *would* have leaked to an LLM provider (e.g., "I found 4 AWS keys..."). This converts non-technical devs instantly.
- **Viral Shareable Moments:** Generate CLI badges and stats lines (e.g., "llm-firewall: 142 secrets caught this month") optimized for developers to screenshot and share in Slack, Twitter, or Bluesky, driving dev-to-dev word of mouth.

## 7. Key Risks & Mitigations
- **Bidirectional Re-injection Exfiltration:** 
  - *Risk:* A prompt-injected LLM could craft output that tricks the firewall into re-injecting secrets into a `curl` command or malicious file write.
  - *Mitigation:* Implement context-aware output scanning to analyze where the re-injected secret is being placed before finalizing the inbound swap.
- **Entropy False Positives:**
  - *Risk:* Blind entropy scans blocking valid UUIDs, hashes, or base64 data, breaking the AI's workflow.
  - *Mitigation:* Use Contextual Entropy to suppress redaction on known safe structures and require a tunable confidence threshold (default 0.7) before blocking.
