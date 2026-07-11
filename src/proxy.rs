use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Uri, StatusCode},
    response::{IntoResponse, Response},
};
use crate::AppState;
use std::time::Instant;

pub struct SyncStream<S>(std::sync::Mutex<S>);

unsafe impl<S> Sync for SyncStream<S> {}

impl<S, T, E> futures_core::Stream for SyncStream<S>
where
    S: futures_core::Stream<Item = Result<T, E>> + Unpin,
{
    type Item = Result<T, E>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut lock = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *lock).poll_next(cx)
    }
}

fn merge_queries(upstream_url: &reqwest::Url, client_query: Option<&str>) -> Option<String> {
    let mut keys = std::collections::HashSet::new();
    let mut pairs = Vec::new();

    // 1. First add upstream queries, record keys to avoid overrides
    for (k, v) in upstream_url.query_pairs() {
        let key_str = k.into_owned();
        pairs.push((key_str.clone(), v.into_owned()));
        keys.insert(key_str);
    }

    // 2. Add client queries if the key wasn't defined by upstream
    if let Some(cq) = client_query {
        for (k, v) in url::form_urlencoded::parse(cq.as_bytes()) {
            let key_str = k.into_owned();
            if !keys.contains(&key_str) {
                pairs.push((key_str, v.into_owned()));
            }
        }
    }

    if pairs.is_empty() {
        None
    } else {
        // Build query string
        let mut target_url = upstream_url.clone();
        target_url.query_pairs_mut().clear().extend_pairs(pairs);
        target_url.query().map(|q| q.to_string())
    }
}

pub async fn proxy_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let start_time = Instant::now();

    // 1. Reconstruct the target URL
    let path = uri.path();
    let query = uri.query();

    let mut target_url = state.upstream_url.clone();
    
    // Joint path logic to preserve configured base path prefix
    let base_path = target_url.path().trim_end_matches('/');
    let incoming_path = path.trim_start_matches('/');
    let joined_path = if base_path.is_empty() {
        format!("/{}", incoming_path)
    } else {
        format!("{}/{}", base_path, incoming_path)
    };
    target_url.set_path(&joined_path);
    
    let merged_query = merge_queries(&state.upstream_url, query);
    target_url.set_query(merged_query.as_deref());

    // 2. Wrap the request body stream to be thread-safe (Sync) for reqwest
    let stream = body.into_data_stream();
    let sync_stream = SyncStream(std::sync::Mutex::new(stream));
    let reqwest_body = reqwest::Body::wrap_stream(sync_stream);

    // 3. Create the reqwest request
    let mut req_builder = state.client.request(method.clone(), target_url.clone());

    // Copy request headers, excluding hop-by-hop headers, and rewrite Host
    let req_headers = match copy_request_headers(&headers, &state.upstream_url) {
        Ok(h) => h,
        Err(err) => return err.into_response(),
    };

    req_builder = req_builder.headers(req_headers).body(reqwest_body);

    // 4. Send the request
    let response = match req_builder.send().await {
        Ok(res) => res,
        Err(e) => {
            let duration = start_time.elapsed().as_millis();
            tracing::error!(
                method = method.as_str(),
                path = path,
                duration_ms = duration,
                error = %e,
                "Upstream request failed"
            );
            let proxy_err = if e.is_timeout() {
                ProxyError::Timeout(e.to_string())
            } else {
                ProxyError::Upstream(e.to_string())
            };
            return proxy_err.into_response();
        }
    };

    let status = response.status();
    let status_code = status.as_u16();

    // Copy response headers, excluding hop-by-hop headers
    let res_headers = match copy_response_headers(response.headers()) {
        Ok(h) => h,
        Err(err) => return err.into_response(),
    };

    let duration = start_time.elapsed().as_millis();

    // 6. Log response
    tracing::info!(
        method = method.as_str(),
        path = path,
        duration_ms = duration,
        status_code = status_code,
        "Request proxied successfully"
    );

    // 7. Reconstruct Axum Response by streaming response bytes directly
    let res_stream = response.bytes_stream();
    let axum_body = Body::from_stream(res_stream);

    let mut axum_res_builder = Response::builder().status(status.as_u16());
    
    if let Some(headers_mut) = axum_res_builder.headers_mut() {
        *headers_mut = res_headers;
    }

    axum_res_builder.body(axum_body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "error": "Security pipeline failure" }))
        ).into_response()
    })
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &axum::http::HeaderName) -> bool {
    let name_str = name.as_str();
    HOP_BY_HOP_HEADERS.iter().any(|h| name_str.eq_ignore_ascii_case(h))
}

fn extract_hop_headers(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut custom_hop_headers = Vec::new();
    for conn_val in headers.get_all(axum::http::header::CONNECTION) {
        let conn_str = conn_val.to_str()
            .map_err(|_| ProxyError::BadRequest("Invalid Connection header".to_string()))?;
        for part in conn_str.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                custom_hop_headers.push(trimmed.to_lowercase());
            }
        }
    }
    Ok(custom_hop_headers)
}

fn extract_res_hop_headers(headers: &reqwest::header::HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut custom_res_hop_headers = Vec::new();
    for conn_val in headers.get_all(reqwest::header::CONNECTION) {
        let conn_str = conn_val.to_str()
            .map_err(|_| ProxyError::Upstream("Invalid response Connection header".to_string()))?;
        for part in conn_str.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                custom_res_hop_headers.push(trimmed.to_lowercase());
            }
        }
    }
    Ok(custom_res_hop_headers)
}

fn copy_request_headers(
    headers: &HeaderMap,
    upstream_url: &reqwest::Url,
) -> Result<reqwest::header::HeaderMap, ProxyError> {
    let custom_hop_headers = extract_hop_headers(headers)?;
    let mut req_headers = reqwest::header::HeaderMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !is_hop_by_hop(name)
            && !custom_hop_headers.iter().any(|h| name_str.eq_ignore_ascii_case(h))
            && !name_str.eq_ignore_ascii_case("transfer-encoding")
        {
            req_headers.append(name.clone(), value.clone());
        }
    }

    // Rewrite Host header (using host_str to handle IPv6 bracket formatting properly, and include port if non-default)
    let host_val = match upstream_url.port() {
        Some(port) => format!("{}:{}", upstream_url.host_str().unwrap_or(""), port),
        None => upstream_url.host_str().unwrap_or("").to_string(),
    };
    let host_header_val = reqwest::header::HeaderValue::from_str(&host_val)
        .map_err(|e| ProxyError::Internal(format!("Invalid Host header value: {}", e)))?;
    req_headers.insert(reqwest::header::HOST, host_header_val);

    Ok(req_headers)
}

fn copy_response_headers(headers: &reqwest::header::HeaderMap) -> Result<HeaderMap, ProxyError> {
    let custom_res_hop_headers = extract_res_hop_headers(headers)?;
    let mut res_headers = HeaderMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !is_hop_by_hop(name)
            && !custom_res_hop_headers.iter().any(|h| name_str.eq_ignore_ascii_case(h))
            && !name_str.eq_ignore_ascii_case("transfer-encoding")
        {
            res_headers.append(name.clone(), value.clone());
        }
    }
    Ok(res_headers)
}

#[derive(Debug)]
pub enum ProxyError {
    Upstream(String),
    Timeout(String),
    PayloadTooLarge,
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(serde_json::json!({
                    "error": "Payload too large"
                })),
            )
                .into_response(),
            ProxyError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": msg
                })),
            )
                .into_response(),
            ProxyError::Upstream(msg) => {
                tracing::error!(error = %msg, "Upstream request failure");
                (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({
                        "error": "Bad Gateway"
                    })),
                )
                    .into_response()
            }
            ProxyError::Timeout(msg) => {
                tracing::error!(error = %msg, "Upstream timeout");
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::Json(serde_json::json!({
                        "error": "Gateway Timeout"
                    })),
                )
                    .into_response()
            }
            ProxyError::Internal(msg) => {
                let is_disconnect = msg.contains("connection closed")
                    || msg.contains("broken pipe")
                    || msg.contains("connection reset")
                    || msg.contains("channel closed");
                if is_disconnect {
                    tracing::debug!(error = %msg, "Client disconnected during request body read");
                } else {
                    tracing::error!(error = %msg, "Internal pipeline failure");
                }
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": "Security pipeline failure"
                    })),
                )
                    .into_response()
            }
        }
    }
}

pub async fn chat_completions_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ProxyError> {
    let start_time = Instant::now();

    // 1. Enforce 2MB limit check
    let limit = 2 * 1024 * 1024;
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|e| {
            use std::error::Error;
            let is_limit = e.source()
                .map(|src| src.to_string().to_lowercase().contains("limit"))
                .unwrap_or(false)
                || e.to_string().to_lowercase().contains("limit");
            if is_limit {
                ProxyError::PayloadTooLarge
            } else {
                ProxyError::Internal(e.to_string())
            }
        })?;

    // Parse payload into untyped JSON Value
    let mut payload: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| ProxyError::BadRequest(format!("Invalid JSON payload: {}", e)))?;

    // Process/Redact payload recursively
    crate::redact::process_completions_payload(&mut payload)
        .map_err(|e| ProxyError::BadRequest(format!("Payload validation failure: {}", e)))?;

    // Rebuild the request body bytes
    let new_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ProxyError::Internal(format!("Failed to serialize payload: {}", e)))?;

    // 2. Reconstruct target URL
    let query = uri.query();
    let mut target_url = state.upstream_url.clone();
    
    let base_path = target_url.path().trim_end_matches('/');
    let joined_path = if base_path.is_empty() {
        "/v1/chat/completions".to_string()
    } else {
        format!("{}/v1/chat/completions", base_path)
    };
    target_url.set_path(&joined_path);
    
    let merged_query = merge_queries(&state.upstream_url, query);
    target_url.set_query(merged_query.as_deref());

    // 3. Prepare reqwest request headers
    let mut req_headers = copy_request_headers(&headers, &state.upstream_url)?;
    
    // Set recalculated Content-Length
    let length = new_bytes.len();
    req_headers.insert(reqwest::header::CONTENT_LENGTH, reqwest::header::HeaderValue::from(length));

    // 4. Send request
    let reqwest_body = reqwest::Body::from(new_bytes);
    let mut req_builder = state.client.request(method.clone(), target_url.clone());
    req_builder = req_builder.headers(req_headers).body(reqwest_body);

    let response = req_builder.send().await.map_err(|e| {
        if e.is_timeout() {
            ProxyError::Timeout(e.to_string())
        } else {
            ProxyError::Upstream(e.to_string())
        }
    })?;

    let status = response.status();

    // 5. Copy response headers, excluding hop-by-hop
    let res_headers = copy_response_headers(response.headers())?;

    let duration = start_time.elapsed().as_millis();
    
    // Log success
    tracing::info!(
        method = method.as_str(),
        path = "/v1/chat/completions",
        duration_ms = duration,
        status_code = status.as_u16(),
        "Intercepted completions request proxied successfully"
    );

    // Reconstruct Response
    let res_stream = response.bytes_stream();
    let axum_body = Body::from_stream(res_stream);

    let mut axum_res_builder = Response::builder().status(status.as_u16());
    if let Some(headers_mut) = axum_res_builder.headers_mut() {
        *headers_mut = res_headers;
    }

    Ok(axum_res_builder.body(axum_body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "error": "Security pipeline failure" }))
        ).into_response()
    }))
}
