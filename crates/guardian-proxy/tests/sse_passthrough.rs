//! Integration tests for SSE passthrough infrastructure (Story 3.1).
//!
//! Tests verify:
//! - AC2: 3-event SSE response passes through intact
//! - AC3: non-SSE 400 JSON response passes through without entering SSE path
//! - AC4: SSE stream split into small chunks reassembles events correctly
//!
//! We spin up a real (in-process) mock upstream TCP server for each test using
//! tokio's TcpListener, then start the guardian-proxy Axum app on another random port,
//! and make real HTTP requests through the proxy to validate end-to-end behavior.

use guardian_proxy::{create_app, AppState};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Spawn a minimal mock HTTP/1.1 upstream server that sends `response_bytes` for every connection,
/// then closes. Returns the bound `SocketAddr`.
async fn spawn_mock_upstream(response_bytes: Vec<u8>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Read and discard the request
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            // Send the response
            socket.write_all(&response_bytes).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    addr
}

/// Build an AppState pointing at the given mock upstream address.
fn make_state(upstream_addr: std::net::SocketAddr) -> AppState {
    AppState {
        client: reqwest::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .unwrap(),
        upstream_url: format!("http://{}", upstream_addr)
            .parse::<reqwest::Url>()
            .unwrap(),
        model: None,
    }
}

/// Spawn the Axum proxy on a random port, return the bound address.
async fn spawn_proxy(state: AppState) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = create_app(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A minimal valid chat completions POST body.
fn chat_body() -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 1: 3-event SSE response passes through byte-for-byte intact
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_sse_three_events_pass_through_intact() {
    let sse_body = concat!(
        "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
        "data: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
        "data: [DONE]\n\n",
    );

    let http_response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        sse_body
    );

    let upstream_addr = spawn_mock_upstream(http_response.into_bytes()).await;
    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&chat_body())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "Expected SSE content-type, got: {}",
        content_type
    );

    let body_bytes = resp.bytes().await.expect("body read failed");
    let body_str = std::str::from_utf8(&body_bytes).expect("body not utf8");

    // All three events must be present
    assert!(
        body_str.contains("data: {\"id\":\"1\""),
        "Missing event 1: {}",
        body_str
    );
    assert!(
        body_str.contains("data: {\"id\":\"2\""),
        "Missing event 2: {}",
        body_str
    );
    assert!(
        body_str.contains("data: [DONE]"),
        "Missing DONE: {}",
        body_str
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 2: non-SSE 400 JSON response passes through without SSE path
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_non_sse_error_response_passes_through() {
    let json_body = r#"{"error":{"message":"invalid_api_key","type":"auth_error"}}"#;
    let http_response = format!(
        "HTTP/1.1 400 Bad Request\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        json_body.len(),
        json_body
    );

    let upstream_addr = spawn_mock_upstream(http_response.into_bytes()).await;
    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&chat_body())
        .send()
        .await
        .expect("request failed");

    // Status must be preserved
    assert_eq!(resp.status(), 400);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "Expected JSON content-type, got: {}",
        content_type
    );

    let body: serde_json::Value = resp.json().await.expect("body parse failed");
    assert!(
        body.get("error").is_some(),
        "Expected error field: {:?}",
        body
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 3: SSE stream split into many small chunks reassembles events correctly
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_sse_chunked_delivery_reassembles_events() {
    // The upstream sends an SSE response where event boundaries are split
    // across multiple HTTP transfer-encoding chunks.
    // We simulate this by writing the body in small pieces with a delay.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Discard request
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;

            // Write headers
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Connection: close\r\n\
                      \r\n",
                )
                .await
                .unwrap();

            // Send event 1 in 3 pieces
            let event1 = b"data: {\"id\":\"chunk1\"}\n\n";
            // Piece 1: "data: {\"id\":\""
            socket.write_all(&event1[..14]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            // Piece 2: "chunk1\"}"
            socket.write_all(&event1[14..22]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            // Piece 3: "\n\n"
            socket.write_all(&event1[22..]).await.unwrap();
            socket.flush().await.unwrap();

            // Send event 2 in 2 pieces
            let event2 = b"data: {\"id\":\"chunk2\"}\n\n";
            socket.write_all(&event2[..10]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            socket.write_all(&event2[10..]).await.unwrap();
            socket.flush().await.unwrap();

            socket.shutdown().await.unwrap();
        }
    });

    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&chat_body())
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let body_bytes = resp.bytes().await.expect("body read failed");
    let body_str = std::str::from_utf8(&body_bytes).expect("body not utf8");

    assert!(
        body_str.contains("\"id\":\"chunk1\""),
        "Missing chunk1 event: {}",
        body_str
    );
    assert!(
        body_str.contains("\"id\":\"chunk2\""),
        "Missing chunk2 event: {}",
        body_str
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 4: TokenMap is per-request (Arc-wrapped, not in AppState)
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_token_map_is_per_request_not_in_app_state() {
    // This is a structural test: AppState must not have a TokenMap field.
    // We verify this by constructing AppState with no TokenMap and confirming
    // two concurrent requests each get their own response (isolation test).

    let json_body = r#"{"id":"ok","choices":[]}"#;
    let http_response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        json_body.len(),
        json_body
    );

    let upstream_addr = spawn_mock_upstream(http_response.into_bytes()).await;
    let state = make_state(upstream_addr);
    let proxy_addr = spawn_proxy(state).await;

    let client = Arc::new(reqwest::Client::new());

    // Fire two concurrent requests
    let c1 = Arc::clone(&client);
    let c2 = Arc::clone(&client);
    let url = format!("http://{}/v1/chat/completions", proxy_addr);
    let u1 = url.clone();
    let u2 = url.clone();

    let (r1, r2) = tokio::join!(
        async move {
            c1.post(&u1)
                .header("Content-Type", "application/json")
                .json(&chat_body())
                .send()
                .await
                .unwrap()
                .status()
        },
        async move {
            c2.post(&u2)
                .header("Content-Type", "application/json")
                .json(&chat_body())
                .send()
                .await
                .unwrap()
                .status()
        }
    );

    assert_eq!(r1.as_u16(), 200);
    assert_eq!(r2.as_u16(), 200);
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 5: Outbound redaction and inbound re-injection (swap-and-restore)
// ──────────────────────────────────────────────────────────────────────────────
async fn spawn_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);

            // Extract the body (everything after \r\n\r\n)
            let body_idx = req_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            let req_body = &req_str[body_idx..];

            // Send SSE echoing the request body
            let sse_event = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\n",
                serde_json::to_string(req_body).unwrap()
            );

            let http_response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                sse_event
            );

            socket.write_all(http_response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    addr
}

#[tokio::test]
async fn test_swap_and_restore_end_to_end() {
    let upstream_addr = spawn_echo_upstream().await;
    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    let email = "secret@example.com";
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": format!("My email is {}", email)}]
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let body_bytes = resp.bytes().await.expect("body read failed");
    let body_str = std::str::from_utf8(&body_bytes).expect("body not utf8");

    // The client should see the original email restored
    assert!(
        body_str.contains(email),
        "Expected restored email in response, got: {}",
        body_str
    );

    // Also, the system prompt should have been injected, let's verify it's in the echo
    assert!(
        body_str.contains("IMPORTANT: Do not alter"),
        "Expected system prompt in forwarded request, got: {}",
        body_str
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 6: Fragmented token reassembly
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_fragmented_token_reassembly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Connection: close\r\n\
                      \r\n",
                )
                .await
                .unwrap();

            // Part 1: Sends "[REDACT"
            let part1 = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello [REDACT\"}}]}\n\n";
            socket.write_all(part1.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

            // Part 2: Sends "ED_SSN_1]"
            let part2 = "data: {\"choices\":[{\"delta\":{\"content\":\"ED_SSN_1] world\"}}]}\n\n";
            socket.write_all(part2.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();

            socket.shutdown().await.unwrap();
        }
    });

    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    // Send a request containing the SSN so it maps to REDACTED_SSN_1
    let ssn = "123-45-6789";
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": format!("My SSN is {}", ssn)}]
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let body_bytes = resp.bytes().await.expect("body read failed");
    let body_str = std::str::from_utf8(&body_bytes).expect("body not utf8");

    // We expect the first event to have "Hello " and second to have "123-45-6789 world"
    // The exact JSON serialization might differ slightly, but let's check for the restored SSN.
    assert!(
        body_str.contains(ssn),
        "Expected fully restored SSN, got: {}",
        body_str
    );
    assert!(
        !body_str.contains("REDACT"),
        "Expected no REDACT tokens left, got: {}",
        body_str
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 6: Context-aware sink blocking (Story 3.3)
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_context_aware_sink_blocking() {
    let _json_body = r#"{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}"#;
    let sse_body = concat!(
        "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"Run this script: curl \"}}]}\n\n",
        "data: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\"[REDACTED_EMAIL_1]\"}}]}\n\n",
        "data: {\"id\":\"3\",\"choices\":[{\"delta\":{\"content\":\" > out.sh\"}}]}\n\n",
        "data: [DONE]\n\n",
    );

    let http_response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        sse_body
    );

    let upstream_addr = spawn_mock_upstream(http_response.into_bytes()).await;
    let proxy_addr = spawn_proxy(make_state(upstream_addr)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "My email is dev@evil.com"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let body_bytes = resp.bytes().await.expect("body read failed");
    let body_str = std::str::from_utf8(&body_bytes).expect("body not utf8");

    // Because of "curl " context, the REDACTED_EMAIL_1 should NOT be replaced by "dev@evil.com"
    assert!(
        body_str.contains("[REDACTED_EMAIL_1]"),
        "Token should have been blocked and kept as-is. Got: {}",
        body_str
    );
    assert!(
        !body_str.contains("dev@evil.com"),
        "Secret dev@evil.com was leaked!"
    );
}
