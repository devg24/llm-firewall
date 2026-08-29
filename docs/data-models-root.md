# Data Models (root)

## Core Structures
- `GuardianConfig` : Core configuration for Guardian
- `RegexConfig`, `AllowlistConfig`, `ThresholdOverrides` : Detection tunables
- `SensitiveZone`, `SandboxPolicy`, `PreflightPlan` : Pre-flight and sandbox modeling
- `SharedModel`, `TokenClassification` : Machine learning and candle-core ML structures
- `TelemetryEvent`, `CostModel`, `CategoryStats`, `AuditStats` : Telemetry and reporting structures
- `Span`, `PiiMatch`, `RedactionState` : Core detection and redaction entities
- `AppState` (Proxy) : Global application state for the proxy
- `SyncStream<S>` : Stream proxy data structure

## Database Schema / Migrations
- This project does not seem to contain an active SQL ORM or standard migrations folder, as it operates primarily as a streaming proxy and relies on in-memory ML inference and configuration files.
