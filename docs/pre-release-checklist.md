# Pre-Release Checklist & Release Workflow

This document outlines the step-by-step release process for `llm-firewall` (`v0.5.0` / pre-release `v0.5.0-rc.1`).

---

## 1. Pre-Flight Verification Matrix

Before tagging or publishing any release, all verification gates must pass cleanly:

| Check | Command | Status Requirement |
| :--- | :--- | :--- |
| **Workspace Unit & Integration Tests** | `cargo test --workspace` | All 112 tests pass (0 failures) |
| **Clippy Linter** | `cargo clippy --workspace --all-targets -- -D warnings` | 0 warnings |
| **Code Formatting** | `cargo fmt --check` | 0 format discrepancies |
| **Release Build** | `cargo build --release --workspace` | Exit 0 with binaries generated |
| **Crate Packaging Dry-Run** | `cargo package --workspace` | Packages build without missing assets |

---

## 2. Release Steps

### Step 1: Version Consistency
Verify all crate versions in `Cargo.toml` files match the target release version (`0.5.0` or `0.5.0-rc.1`):
- [Cargo.toml](file:///Users/devgoyal/desktop/llm-firewall-rs/Cargo.toml)
- [crates/guardian-core/Cargo.toml](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-core/Cargo.toml)
- [crates/guardian-proxy/Cargo.toml](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-proxy/Cargo.toml)
- [crates/guardian-cli/Cargo.toml](file:///Users/devgoyal/desktop/llm-firewall-rs/crates/guardian-cli/Cargo.toml)

### Step 2: Changelog Verification
Ensure [CHANGELOG.md](file:///Users/devgoyal/desktop/llm-firewall-rs/CHANGELOG.md) contains all features, fixes, and architectural improvements under the target version section with the correct release date.

### Step 3: Run Full Validation Suite
```bash
# 1. Format check
cargo fmt --check

# 2. Strict clippy checks across all targets
cargo clippy --workspace --all-targets -- -D warnings

# 3. Complete test suite across all crates
cargo test --workspace

# 4. Build release artifacts
cargo build --release --workspace
```

### Step 4: Commit & Tag Pre-Release
```bash
# Stage version and manifest changes
git add Cargo.toml Cargo.lock crates/*/Cargo.toml CHANGELOG.md docs/

# Commit release bump
git commit -m "chore(release): prepare v0.5.0-rc.1 pre-release"

# Create annotated git tag
git tag -a v0.5.0-rc.1 -m "Release v0.5.0-rc.1 (pre-release candidate)"

# Push commit and tags to remote
git push origin main
git push origin v0.5.0-rc.1
```

### Step 5: Crates.io Publishing Order (If Publishing to Crates Registry)
Because of workspace inter-dependencies, publish in reverse dependency order:
```bash
# 1. Core library first (dry-run)
cargo publish -p guardian-core --dry-run
cargo publish -p guardian-core

# 2. Proxy layer second (dry-run)
cargo publish -p guardian-proxy --dry-run
cargo publish -p guardian-proxy

# 3. CLI entrypoint third (dry-run)
cargo publish -p guardian-cli --dry-run
cargo publish -p guardian-cli

# 4. Top-level wrapper binary
cargo publish -p llm-firewall-rs --dry-run
cargo publish -p llm-firewall-rs
```

### Step 6: GitHub Pre-Release Drafting
1. Navigate to **Releases > Draft a new release** on GitHub.
2. Select tag `v0.5.0-rc.1`.
3. Title: `v0.5.0-rc.1 — Single-Port Multiplexing & Cursor IDE Integration`.
4. Check **"Set as a pre-release"**.
5. Paste the release notes from [CHANGELOG.md](file:///Users/devgoyal/desktop/llm-firewall-rs/CHANGELOG.md).
6. Attach pre-compiled release binaries for:
   - `x86_64-unknown-linux-gnu`
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `x86_64-pc-windows-msvc`
