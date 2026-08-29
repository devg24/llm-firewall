# API Contracts Catalog (root)

## HTTP Endpoints
- `GET /health` : Liveness check, returns `"OK"`
- `POST /v1/chat/completions` : PII-intercepting completions handler
- `ANY /{*path}` : Generic passthrough for all other paths (catch-all)

## Request/Response Schemas
- Uses Axum request/response streams natively via `hyper` and `tower`.
- Streaming responses (SSE) are intercepted, decrypted, and modified on the fly for PII redaction.

## Authentication
- Typically operates as a local MITM proxy, handling standard OpenAI-compatible bearer tokens as passthrough to the upstream target.
