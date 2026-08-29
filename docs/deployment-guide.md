# Deployment Guide

## Infrastructure Requirements
- A server capable of running Rust compiled binaries.
- Network configuration allowing incoming connections to the proxy port.

## Deployment Process
- Binaries are built using Cargo (`cargo build --release`).
- The `guardian-proxy` binary acts as the primary service and must be kept running (e.g., via systemd or a container).

## CI/CD Pipeline
- Handled via GitHub Actions.
- `.github/workflows/ci.yml`: Runs tests, clippy, and formatting checks on PRs and commits.
- `.github/workflows/release.yml`: Automates release builds and artifacts publishing.
