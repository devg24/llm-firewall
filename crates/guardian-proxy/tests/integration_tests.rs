//! Integration tests for guardian-proxy.
//!
//! These tests verify the full proxy stack by spawning real Axum HTTP servers
//! and making HTTP requests through the proxy to a mock upstream.
//! All servers use graceful shutdown via `tokio::sync::oneshot` channels.

use axum::{
    body::Bytes,
    response::Response,
    routing::{any, post},
    Router,
};
use guardian_proxy::{create_app, AppState};

fn make_test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(300))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_health_endpoint() {
    let client = make_test_client();
    let upstream_url = reqwest::Url::parse("https://api.openai.com").unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };

    let app = create_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let client = make_test_client();
    let response = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let text = response.text().await.unwrap();
    assert_eq!(text, "OK");

    let _ = tx.send(());
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_proxy_transparent_fallback() {
    // 1. Spawn mock upstream server
    let upstream_app = Router::new().route(
        "/{*path}",
        any(|method: axum::http::Method, uri: axum::http::Uri, headers: axum::http::HeaderMap, body: Bytes| async move {
            let builder = Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("x-received-method", method.as_str())
                .header("x-received-uri", uri.to_string())
                .header("x-upstream-response-header", "custom-val")
                .header("connection", "close, x-res-hop")
                .header("x-res-hop", "should-be-dropped-by-proxy");

            let body_str = std::str::from_utf8(&body).unwrap_or("").to_string();
            let multi_vals: Vec<String> = headers
                .get_all("x-multi")
                .iter()
                .map(|v| v.to_str().unwrap_or("").to_string())
                .collect();

            let response_data = serde_json::json!({
                "path": uri.path(),
                "query": uri.query(),
                "host_header": headers.get("host").map(|v| v.to_str().unwrap_or("")),
                "auth_header": headers.get("authorization").map(|v| v.to_str().unwrap_or("")),
                "connection_header": headers.get("connection").map(|v| v.to_str().unwrap_or("")),
                "custom_header": headers.get("x-custom").map(|v| v.to_str().unwrap_or("")),
                "another_hop": headers.get("x-another-hop").map(|v| v.to_str().unwrap_or("")),
                "multi_header": multi_vals,
                "body": body_str,
            });

            builder.body(axum::body::Body::from(serde_json::to_vec(&response_data).unwrap())).unwrap()
        }),
    );

    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let (tx_upstream, rx_upstream) = tokio::sync::oneshot::channel::<()>();
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async move {
                let _ = rx_upstream.await;
            })
            .await
            .unwrap();
    });

    // 2. Spawn proxy server
    let client = make_test_client();
    // Set a path prefix and upstream query parameter in the upstream URL
    let upstream_url =
        reqwest::Url::parse(&format!("http://{}/api/v2?up=yes", upstream_addr)).unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };

    let proxy_app = create_app(state);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (tx_proxy, rx_proxy) = tokio::sync::oneshot::channel::<()>();
    let proxy_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx_proxy.await;
            })
            .await
            .unwrap();
    });

    // 3. Send test request to proxy with query parameter
    let client = make_test_client();
    let response = client
        .post(format!("http://{}/v1/models?foo=bar", proxy_addr))
        .header("Authorization", "Bearer test-key")
        .header("Connection", "keep-alive, x-another-hop") // custom client hop header
        .header("X-Another-Hop", "should-be-dropped")
        .header("X-Custom", "my-custom-header")
        .header("X-Multi", "val1")
        .header("X-Multi", "val2")
        .body("hello world request body")
        .send()
        .await
        .unwrap();

    // 4. Assertions on response
    // Verify response status
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Verify response headers
    assert_eq!(
        response
            .headers()
            .get("x-upstream-response-header")
            .unwrap(),
        "custom-val"
    );
    assert!(
        response.headers().get("connection").is_none()
            || response.headers().get("connection").unwrap() != "close"
    );
    assert!(response.headers().get("x-res-hop").is_none());

    // Verify body and forwarded headers
    let json_body: serde_json::Value = response.json().await.unwrap();

    assert_eq!(json_body["auth_header"], "Bearer test-key");
    assert_eq!(json_body["custom_header"], "my-custom-header");
    assert_eq!(json_body["body"], "hello world request body");

    // Verify connection-specified hop header was dropped
    assert!(json_body["another_hop"].is_null());
    assert_ne!(json_body["connection_header"], "keep-alive");

    // Verify host header was rewritten to match upstream
    assert_eq!(json_body["host_header"], upstream_addr.to_string());

    // Verify multi-value headers are preserved
    let multi_vals = json_body["multi_header"].as_array().unwrap();
    assert_eq!(multi_vals.len(), 2);
    assert_eq!(multi_vals[0], "val1");
    assert_eq!(multi_vals[1], "val2");

    // Verify path prefix preservation
    assert_eq!(json_body["path"], "/api/v2/v1/models");

    // Verify query parameters are merged correctly (upstream's "up=yes" + client's "foo=bar")
    assert_eq!(json_body["query"], "up=yes&foo=bar");

    // 5. Verify GET /v1/chat/completions is proxied correctly (only POST is stubbed)
    let get_completions_response = client
        .get(format!("http://{}/v1/chat/completions", proxy_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(get_completions_response.status(), reqwest::StatusCode::OK);
    let completions_body: serde_json::Value = get_completions_response.json().await.unwrap();
    assert_eq!(completions_body["path"], "/api/v2/v1/chat/completions");

    let _ = tx_proxy.send(());
    let _ = tx_upstream.send(());
    proxy_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn test_proxy_chat_completions_success() {
    guardian_core::init_regexes();

    // 1. Spawn mock upstream server
    let upstream_app = Router::new().route(
        "/v1/chat/completions",
        post(|headers: axum::http::HeaderMap, body: Bytes| async move {
            let builder = Response::builder().status(axum::http::StatusCode::OK);
            let body_str = std::str::from_utf8(&body).unwrap_or("").to_string();
            let response_data = serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("Echo: {}", body_str)
                    },
                    "finish_reason": "stop"
                }]
            });
            assert_eq!(headers.get("authorization").unwrap(), "Bearer test-api-key");
            assert!(headers
                .get("host")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("127.0.0.1"));
            builder
                .body(axum::body::Body::from(
                    serde_json::to_vec(&response_data).unwrap(),
                ))
                .unwrap()
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let (tx_upstream, rx_upstream) = tokio::sync::oneshot::channel::<()>();
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async move {
                let _ = rx_upstream.await;
            })
            .await
            .unwrap();
    });

    // 2. Spawn proxy server
    let client = make_test_client();
    let upstream_url = reqwest::Url::parse(&format!("http://{}", upstream_addr)).unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };
    let proxy_app = create_app(state);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (tx_proxy, rx_proxy) = tokio::sync::oneshot::channel::<()>();
    let proxy_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx_proxy.await;
            })
            .await
            .unwrap();
    });

    // 3. Send valid POST request with simple string content
    let client = make_test_client();
    let response = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .header("Authorization", "Bearer test-api-key")
        .body("{\"messages\": [{\"role\": \"user\", \"content\": \"hello, my SSN is 123-45-6789 and my email is test@example.com\"}]}")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    let content = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(content.contains("Echo:"));
    assert!(content.contains(
        "\"content\":\"hello, my SSN is [REDACTED_SSN_1] and my email is [REDACTED_EMAIL_1]\""
    ));

    let _ = tx_proxy.send(());
    let _ = tx_upstream.send(());
    proxy_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn test_proxy_chat_completions_complex() {
    guardian_core::init_regexes();

    // 1. Spawn mock upstream server
    let upstream_app = Router::new().route(
        "/v1/chat/completions",
        post(|_headers: axum::http::HeaderMap, body: Bytes| async move {
            let builder = Response::builder().status(axum::http::StatusCode::OK);
            let body_str = std::str::from_utf8(&body).unwrap_or("").to_string();
            let response_data = serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("Echo: {}", body_str)
                    },
                    "finish_reason": "stop"
                }]
            });
            builder
                .body(axum::body::Body::from(
                    serde_json::to_vec(&response_data).unwrap(),
                ))
                .unwrap()
        }),
    );
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let (tx_upstream, rx_upstream) = tokio::sync::oneshot::channel::<()>();
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream_app)
            .with_graceful_shutdown(async move {
                let _ = rx_upstream.await;
            })
            .await
            .unwrap();
    });

    // 2. Spawn proxy server
    let client = make_test_client();
    let upstream_url = reqwest::Url::parse(&format!("http://{}", upstream_addr)).unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };
    let proxy_app = create_app(state);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (tx_proxy, rx_proxy) = tokio::sync::oneshot::channel::<()>();
    let proxy_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx_proxy.await;
            })
            .await
            .unwrap();
    });

    // 3. Send complex completions payload (array content with text/image objects)
    let client = make_test_client();
    let payload = serde_json::json!({
        "model": "gpt-4-vision",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Identify what is in this image. Contact info: 123-456-7890"
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "https://example.com/image.png"
                        }
                    }
                ]
            }
        ],
        "temperature": 0.7
    });

    let response = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response_json: serde_json::Value = response.json().await.unwrap();
    let echoed_content = response_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap();

    // Verify echoed_content contains the modified body with "[REDACTED_PHONE_1]" and preserves other values
    let sent_to_upstream: serde_json::Value =
        serde_json::from_str(echoed_content.strip_prefix("Echo: ").unwrap()).unwrap();

    assert_eq!(sent_to_upstream["model"], "gpt-4-vision");
    assert_eq!(sent_to_upstream["temperature"], 0.7);

    let msg_content = &sent_to_upstream["messages"][0]["content"];
    assert_eq!(msg_content[0]["type"], "text");
    assert_eq!(
        msg_content[0]["text"],
        "Identify what is in this image. Contact info: [REDACTED_PHONE_1]"
    );
    assert_eq!(msg_content[1]["type"], "image_url");
    assert_eq!(
        msg_content[1]["image_url"]["url"],
        "https://example.com/image.png"
    );

    let _ = tx_proxy.send(());
    let _ = tx_upstream.send(());
    proxy_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn test_proxy_chat_completions_too_large() {
    let client = make_test_client();
    let upstream_url = reqwest::Url::parse("https://api.openai.com").unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };
    let proxy_app = create_app(state);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    // Create a payload larger than 2MB
    let large_payload = vec![b'a'; 2 * 1024 * 1024 + 10];
    let client = make_test_client();
    let response = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .body(large_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let _ = tx.send(());
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_proxy_chat_completions_fail_closed() {
    let client = make_test_client();
    let upstream_url = reqwest::Url::parse("http://127.0.0.1:1").unwrap();
    let state = AppState {
        client,
        upstream_url,
        model: None,
    };
    let proxy_app = create_app(state);
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    let client = make_test_client();

    // 1. Send malformed/invalid JSON syntax
    let response_malformed = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .body("{invalid-json}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response_malformed.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let body_malformed: serde_json::Value = response_malformed.json().await.unwrap();
    assert!(body_malformed["error"]
        .as_str()
        .unwrap()
        .contains("Invalid JSON payload"));

    // 2. Send JSON missing "messages" field
    let response_missing_msg = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .body("{\"prompt\": \"hello\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response_missing_msg.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let body_missing: serde_json::Value = response_missing_msg.json().await.unwrap();
    assert!(body_missing["error"]
        .as_str()
        .unwrap()
        .contains("Missing or invalid 'messages' array"));

    let _ = tx.send(());
    server_handle.await.unwrap();
}
