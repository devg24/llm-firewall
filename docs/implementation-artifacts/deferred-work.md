# Deferred Work

## Deferred from: code review of 1-1-crate-scaffold-axum-http-listener-with-environment-configuration.md (2026-06-27)

- **Test background server task runs indefinitely [src/main.rs:93-95]:** Spawned tokio task runs forever in the background of the test runner, causing resource leakage.
- **Missing graceful shutdown signal handling [src/main.rs:55-57]:** axum server runs without listener shutdown hooks, abruptly closing client connections on shutdown.
- **std::process::exit bypasses drops in main [src/main.rs:39,49]:** Direct exit prevents drop handlers from executing on main variables.

## Deferred from: code review of 1-2-wildcard-transparent-fallback-proxy-routing.md (2026-06-27)

- **Blocking/Synchronous Logging Subscriber Writer [src/main.rs:9-12]:** Synchronous stdout writer could block in high throughput.
- **Missing Standard Forwarding Headers (X-Forwarded-*) [src/proxy.rs:49-67]:** Standard forwarding headers are not appended.
