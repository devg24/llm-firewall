use crate::AppState;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use guardian_core::TokenMap;
use std::sync::Arc;
use std::time::Instant;

pub struct SyncStream<S>(std::sync::Mutex<S>);

unsafe impl<S: Send> Sync for SyncStream<S> {}

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
            } else if e.is_connect() || e.is_builder() || e.is_request() {
                ProxyError::Upstream(e.to_string())
            } else {
                ProxyError::Internal(e.to_string())
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
            axum::Json(serde_json::json!({ "error": "Security pipeline failure" })),
        )
            .into_response()
    })
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &axum::http::HeaderName) -> bool {
    let name_str = name.as_str();
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| name_str.eq_ignore_ascii_case(h))
}

fn extract_hop_headers(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut custom_hop_headers = Vec::new();
    for conn_val in headers.get_all(axum::http::header::CONNECTION) {
        let conn_str = conn_val
            .to_str()
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

fn extract_res_hop_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<String>, ProxyError> {
    let mut custom_res_hop_headers = Vec::new();
    for conn_val in headers.get_all(reqwest::header::CONNECTION) {
        let conn_str = conn_val
            .to_str()
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
            && !custom_hop_headers
                .iter()
                .any(|h| name_str.eq_ignore_ascii_case(h))
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
            && !custom_res_hop_headers
                .iter()
                .any(|h| name_str.eq_ignore_ascii_case(h))
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
    TooManyRequests,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": "Too Many Requests"
                })),
            )
                .into_response(),
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

impl From<guardian_core::CoreError> for ProxyError {
    fn from(err: guardian_core::CoreError) -> Self {
        match err {
            guardian_core::CoreError::TooManyRequests => ProxyError::TooManyRequests,
            guardian_core::CoreError::InferenceTimeout => {
                ProxyError::Timeout("Inference timeout".to_string())
            }
            guardian_core::CoreError::PayloadValidation(msg) => ProxyError::BadRequest(msg),
            guardian_core::CoreError::ModelLoad(msg)
            | guardian_core::CoreError::Tokenization(msg)
            | guardian_core::CoreError::TaskPanicked(msg)
            | guardian_core::CoreError::Serialization(msg)
            | guardian_core::CoreError::Internal(msg) => ProxyError::Internal(msg),
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
    let bytes = axum::body::to_bytes(body, limit).await.map_err(|e| {
        use std::error::Error;
        let is_limit = e
            .source()
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

    // Instantiate per-request TokenMap
    let token_map_arc = Arc::new(std::sync::Mutex::new(TokenMap::new()));

    // Run Orchestrator Pipeline
    let orchestrator = guardian_core::orchestrator::DetectionOrchestrator::with_config(
        state.model.clone(),
        state.domain,
        state.guardian_config.as_ref(),
    );
    guardian_core::redact::process_completions_payload_with_orchestrator(
        &mut payload,
        &token_map_arc,
        &orchestrator,
    )
    .await
    .map_err(|e| ProxyError::BadRequest(format!("Pipeline failure: {}", e)))?;

    // Inject system prompt guard instruction (AD-11)
    if let Some(messages) = payload.get_mut("messages").and_then(|m| m.as_array_mut()) {
        if !messages.is_empty() {
            let guard_instruction = "IMPORTANT: Do not alter, mutate, lowercase, or reformulate any token matching the pattern [REDACTED_*]. These tokens are placeholders and must be preserved exactly as-is.";

            let has_system_first =
                messages[0].get("role").and_then(|r| r.as_str()) == Some("system");

            if has_system_first {
                if let Some(content) = messages[0].get_mut("content") {
                    if let Some(s) = content.as_str() {
                        let new_content = format!("{}\n\n{}", guard_instruction, s);
                        *content = serde_json::Value::String(new_content);
                    }
                }
            } else {
                let sys_msg = serde_json::json!({
                    "role": "system",
                    "content": guard_instruction
                });
                messages.insert(0, sys_msg);
            }
        }
    }

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
    req_headers.insert(
        reqwest::header::CONTENT_LENGTH,
        reqwest::header::HeaderValue::from(length),
    );

    // 4. Send request
    let reqwest_body = reqwest::Body::from(new_bytes);
    let mut req_builder = state.client.request(method.clone(), target_url.clone());
    req_builder = req_builder.headers(req_headers).body(reqwest_body);

    let response = req_builder.send().await.map_err(|e| {
        if e.is_timeout() {
            ProxyError::Timeout(e.to_string())
        } else if e.is_connect() || e.is_builder() || e.is_request() {
            ProxyError::Upstream(e.to_string())
        } else {
            ProxyError::Internal(e.to_string())
        }
    })?;

    let status = response.status();

    // 5. Copy response headers, excluding hop-by-hop
    let mut res_headers = copy_response_headers(response.headers())?;

    let duration = start_time.elapsed().as_millis();

    // Log success
    tracing::info!(
        method = method.as_str(),
        path = "/v1/chat/completions",
        duration_ms = duration,
        status_code = status.as_u16(),
        "Intercepted completions request proxied successfully"
    );

    // 6. Detect SSE via Content-Type: text/event-stream (AC-2, AC-3)
    let is_sse = res_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let axum_body = if is_sse {
        // Strip Content-Length — SSE is always streamed/chunked, never fixed-length.
        res_headers.remove(axum::http::header::CONTENT_LENGTH);

        // Clone Arc for capture in the stream closure (unused in Story 3.1 — stub for 3.2).
        let _token_map = Arc::clone(&token_map_arc);

        // Build SSE passthrough stream using StreamExt combinators (AD-15: no manual poll_next).
        // State: (upstream_stream, pending_events_buf, raw_byte_buf, done)
        // We use unfold to drive the upstream bytes_stream and emit one complete SSE event
        // per iteration, buffering partial data between polls.
        let upstream_stream = response.bytes_stream();

        type UpstreamStream =
            dyn futures_core::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + Unpin;
        struct SseState {
            upstream: Box<UpstreamStream>,
            buf: Vec<u8>,
            pending: Vec<bytes::Bytes>,
            done: bool,
            token_map: Arc<std::sync::Mutex<TokenMap>>,
            fragment_buf: String,
            lookbehind: String,
            sink_detector: guardian_core::DangerousSinkDetector,
        }

        let state = SseState {
            upstream: Box::new(upstream_stream),
            buf: Vec::new(),
            pending: Vec::new(),
            done: false,
            token_map: token_map_arc,
            fragment_buf: String::new(),
            lookbehind: String::new(),
            sink_detector: guardian_core::DangerousSinkDetector::new(),
        };

        let output_stream = futures_util::stream::unfold(state, |mut s| async move {
            // If we have a queued event from a previous iteration, emit it first.
            if let Some(event) = s.pending.pop() {
                return Some((Ok::<bytes::Bytes, axum::Error>(event), s));
            }

            if s.done {
                // Flush remaining bytes as a final item if any.
                if !s.buf.is_empty() {
                    let remaining = bytes::Bytes::from(std::mem::take(&mut s.buf));
                    return Some((Ok(remaining), s));
                }
                return None;
            }

            // Pull chunks from upstream until we can emit at least one complete event.
            loop {
                // Check if we have a complete event in the buffer.
                if let Some(pos) = find_double_newline(&s.buf) {
                    let event: Vec<u8> = s.buf.drain(..pos).collect();
                    let processed_event = process_sse_event(
                        event,
                        &mut s.fragment_buf,
                        &s.token_map,
                        &mut s.lookbehind,
                        &s.sink_detector,
                    );

                    // Collect any additional complete events into pending (LIFO pop, so reverse).
                    let mut extra = Vec::new();
                    while let Some(p2) = find_double_newline(&s.buf) {
                        let ev2: Vec<u8> = s.buf.drain(..p2).collect();
                        let processed_ev2 = process_sse_event(
                            ev2,
                            &mut s.fragment_buf,
                            &s.token_map,
                            &mut s.lookbehind,
                            &s.sink_detector,
                        );
                        extra.push(bytes::Bytes::from(processed_ev2));
                    }
                    extra.reverse();
                    s.pending = extra;
                    return Some((Ok(bytes::Bytes::from(processed_event)), s));
                }

                // Need more bytes — poll upstream.
                match s.upstream.next().await {
                    Some(Ok(chunk)) => {
                        s.buf.extend_from_slice(&chunk);
                    }
                    Some(Err(e)) => {
                        s.done = true;
                        return Some((Err(axum::Error::new(e)), s));
                    }
                    None => {
                        // Upstream ended; flush remainder if any, then stop.
                        s.done = true;
                        if !s.buf.is_empty() {
                            let remaining = bytes::Bytes::from(std::mem::take(&mut s.buf));
                            return Some((Ok(remaining), s));
                        }
                        return None;
                    }
                }
            }
        });

        Body::from_stream(output_stream)
    } else {
        // Non-SSE: passthrough unchanged (AC-3)
        Body::from_stream(response.bytes_stream())
    };

    let mut axum_res_builder = Response::builder().status(status.as_u16());
    if let Some(headers_mut) = axum_res_builder.headers_mut() {
        *headers_mut = res_headers;
    }

    Ok(axum_res_builder.body(axum_body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "error": "Security pipeline failure" })),
        )
            .into_response()
    }))
}

fn process_sse_event(
    event: Vec<u8>,
    fragment_buf: &mut String,
    token_map: &Arc<std::sync::Mutex<TokenMap>>,
    lookbehind: &mut String,
    sink_detector: &guardian_core::DangerousSinkDetector,
) -> Vec<u8> {
    let event_str = match std::str::from_utf8(&event) {
        Ok(s) => s,
        Err(_) => return event,
    };

    if !event_str.starts_with("data: ") {
        return event;
    }

    let data_str = event_str.trim_start_matches("data: ").trim_end();
    if data_str == "[DONE]" {
        return event;
    }

    let mut parsed: serde_json::Value = match serde_json::from_str(data_str) {
        Ok(v) => v,
        Err(_) => return event,
    };

    let mut modified = false;
    if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices {
            let content_target = if let Some(delta) = choice.get_mut("delta") {
                delta.get_mut("content")
            } else if let Some(message) = choice.get_mut("message") {
                message.get_mut("content")
            } else {
                None
            };

            if let Some(serde_json::Value::String(content)) = content_target {
                lookbehind.push_str(content.as_str());
                if lookbehind.len() > 512 {
                    let trim_pos = lookbehind.len() - 512;
                    let mut char_pos = trim_pos;
                    while char_pos < lookbehind.len() && !lookbehind.is_char_boundary(char_pos) {
                        char_pos += 1;
                    }
                    *lookbehind = lookbehind[char_pos..].to_string();
                }

                let to_scan = fragment_buf.clone() + content.as_str();

                let mut partial = String::new();
                let mut full_content_to_replace = to_scan.clone();

                if let Some(incomplete_start) = to_scan.rfind("[REDACT") {
                    if !to_scan[incomplete_start..].contains(']') {
                        partial = to_scan[incomplete_start..].to_string();
                        full_content_to_replace = to_scan[..incomplete_start].to_string();
                    }
                }

                *fragment_buf = partial;

                let (tokens, original_values) = {
                    let lock = token_map.lock().unwrap();
                    let mut tokens = Vec::new();
                    let mut original_values = Vec::new();
                    for k in lock.keys() {
                        if let Some((secret, _)) = lock.get(k) {
                            tokens.push(k.clone());
                            original_values.push(secret.clone());
                        }
                    }
                    (tokens, original_values)
                };

                let final_content = if !tokens.is_empty() {
                    let is_dangerous = sink_detector.is_dangerous_context(lookbehind);
                    if is_dangerous {
                        tracing::warn!(
                            lookbehind = %lookbehind,
                            "Dangerous sink context detected, blocking token re-injection"
                        );
                        full_content_to_replace
                    } else {
                        match aho_corasick::AhoCorasick::new(&tokens) {
                            Ok(ac) => ac.replace_all(&full_content_to_replace, &original_values),
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to build AhoCorasick automaton for token re-injection");
                                full_content_to_replace
                            }
                        }
                    }
                } else {
                    full_content_to_replace
                };

                if final_content != content.as_str() {
                    *content = final_content;
                    modified = true;
                }
            }
        }
    }

    if modified {
        let mut new_event = String::from("data: ");
        new_event.push_str(&serde_json::to_string(&parsed).unwrap());
        new_event.push_str("\n\n");
        return new_event.into_bytes();
    }

    event
}

/// Find the end boundary of the first complete SSE event in `buf`.
///
/// Returns `Some(pos)` where `pos` is the index *after* the `\n\n` delimiter,
/// i.e. `buf[..pos]` is the complete event including both newlines.
/// Returns `None` if no `\n\n` boundary is found.
fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_double_newline_found() {
        let data = b"data: hello\n\ndata: world\n\n";
        assert_eq!(find_double_newline(data), Some(13));
    }

    #[test]
    fn find_double_newline_not_found() {
        let data = b"data: hello\n";
        assert_eq!(find_double_newline(data), None);
    }

    #[test]
    fn find_double_newline_at_start() {
        let data = b"\n\ndata: hello\n\n";
        assert_eq!(find_double_newline(data), Some(2));
    }

    #[test]
    fn find_double_newline_empty() {
        assert_eq!(find_double_newline(b""), None);
    }
}
