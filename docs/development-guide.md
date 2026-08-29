# Development Guide

## Prerequisites
- Rust 1.85.0 (as specified in `Cargo.toml`)
- Cargo

## Environment Setup
Clone the repository and ensure you have the correct Rust toolchain installed:
```bash
rustup install 1.85.0
rustup default 1.85.0
```

## Build Process
This is a Cargo workspace containing multiple crates. To build the entire workspace:
```bash
cargo build
```

To build for release with optimizations:
```bash
cargo build --release
```

## Running Locally
To run the proxy:
```bash
cargo run -p guardian-proxy
```

To run the CLI:
```bash
cargo run -p guardian-cli
```

## Testing Approach
Run all workspace tests using Cargo:
```bash
cargo test
```

## Common Tasks
- Updating ML models: Ensure `candle` compatible model files are present.
- Linting and Formatting: `cargo clippy` and `cargo fmt`.
