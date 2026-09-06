use crate::AppState;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use guardian_core::TokenMap;
use std::sync::Arc;
use std::time::Instant;

use crate::sse::create_sse_response_stream;
pub use guardian_core::telemetry::{spawn_telemetry_writer, TelemetryWriter};

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

    // Extract dynamic upstream URL if this is a MITM request
    let mut target_url = if headers.contains_key("x-firewall-mitm") {
        if let Some(host_header) = headers.get(axum::http::header::HOST) {
            if let Ok(host_str) = host_header.to_str() {
                reqwest::Url::parse(&format!("https://{}", host_str))
                    .unwrap_or_else(|_| state.upstream_url.clone())
            } else {
                state.upstream_url.clone()
            }
        } else {
            state.upstream_url.clone()
        }
    } else {
        state.upstream_url.clone()
    };

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
    let reqwest_body = if crate::ide_adapters::requires_buffering(path) {
        let bytes = axum::body::to_bytes(body, 5 * 1024 * 1024)
            .await
            .unwrap_or_default();

        if let Ok(Some(blocked_response)) =
            crate::ide_adapters::run_interceptors(path, &bytes, &state, start_time).await
        {
            return blocked_response;
        }

        reqwest::Body::from(bytes)
    } else {
        let stream = body.into_data_stream();
        let sync_stream = SyncStream(std::sync::Mutex::new(stream));
        reqwest::Body::wrap_stream(sync_stream)
    };

    // 3. Create the reqwest request
    let mut req_builder = state.client.request(method.clone(), target_url.clone());

    // Copy request headers, excluding hop-by-hop headers, and rewrite Host
    let req_headers = match copy_request_headers(&headers, &target_url) {
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
    tracing::debug!(
        method = %method,
        path = %path,
        duration_ms = duration,
        status_code = status_code,
        "Request proxied successfully"
    );

    if let Some(ref tx) = state.telemetry_tx {
        let req_id = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "req-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )
            });
        let event = guardian_core::telemetry::TelemetryEvent {
            timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
            request_id: req_id,
            event_type: guardian_core::telemetry::TelemetryEventType::Passthrough,
            tier_triggered: None,
            secret_types: Vec::new(),
            redacted_count: 0,
            sandbox_violation: None,
            model: None,
            latency_ms: duration as u64,
            estimated_cost_saved_usd: 0.0,
        };
        let _ = tx.send(event);
    }

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
    Forbidden(String),
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
            ProxyError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "Forbidden",
                    "message": msg
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

fn inspect_json_for_sandbox_violations(
    val: &serde_json::Value,
    sandbox: &guardian_core::plan::SandboxPolicy,
) -> Result<(), ProxyError> {
    match val {
        serde_json::Value::Object(map) => {
            for (_key, v) in map {
                inspect_json_for_sandbox_violations(v, sandbox)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                inspect_json_for_sandbox_violations(v, sandbox)?;
            }
        }
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                if let Ok(nested) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    inspect_json_for_sandbox_violations(&nested, sandbox)?;
                }
            }

            // Extract potential paths from string (e.g. if embedded in shell command)
            let potential_paths: Vec<&str> = trimmed.split_whitespace().collect();
            let mut paths_to_check = vec![trimmed];
            if potential_paths.len() > 1 {
                paths_to_check.extend(potential_paths);
            }

            for path_str in paths_to_check {
                let p = path_str.trim_matches(|c| c == '"' || c == '\'' || c == '.' || c == ',');
                if p.starts_with('/')
                    || p.starts_with("~/")
                    || p.contains("../")
                    || p.contains("..\\")
                    || p == ".."
                    || p.contains(":\\")
                    || p.starts_with("\\\\")
                {
                    let target = if p.starts_with("~/") {
                        if let Ok(home) = std::env::var("HOME") {
                            std::path::PathBuf::from(home).join(p.trim_start_matches("~/"))
                        } else {
                            std::path::PathBuf::from(p)
                        }
                    } else {
                        std::path::PathBuf::from(p)
                    };

                    if let Err(violation) = sandbox.validate_path(&target) {
                        tracing::warn!(violation = %violation, "Sandbox boundary violation detected in payload");
                        return Err(ProxyError::Forbidden(format!(
                            "Sandbox boundary violation: {}",
                            violation
                        )));
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
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

    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "req-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        });

    // Parse payload into untyped JSON Value
    let mut payload: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| ProxyError::BadRequest(format!("Invalid JSON payload: {}", e)))?;

    let model_name = payload
        .get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());

    // If preflight plan is active, check sandbox violations
    if let Some(ref plan) = state.preflight_plan {
        tracing::debug!(
            version = plan.version,
            approved = plan.approved,
            zones = plan.sensitive_zones.len(),
            "Executing request with active preflight security plan"
        );
        if plan.sandbox.enforce_jailing {
            if let Err(err) = inspect_json_for_sandbox_violations(&payload, &plan.sandbox) {
                if let Some(ref tx) = state.telemetry_tx {
                    let cost_model = guardian_core::telemetry::CostModel::default();
                    let event = guardian_core::telemetry::TelemetryEvent {
                        timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
                        request_id: request_id.clone(),
                        event_type: guardian_core::telemetry::TelemetryEventType::SandboxBlocked,
                        tier_triggered: Some(guardian_core::telemetry::DetectionTier::SandboxJail),
                        secret_types: Vec::new(),
                        redacted_count: 0,
                        sandbox_violation: Some(format!("{:?}", err)),
                        model: model_name.clone(),
                        latency_ms: start_time.elapsed().as_millis() as u64,
                        estimated_cost_saved_usd: cost_model.sandbox_violation_usd,
                    };
                    let _ = tx.send(event);
                }
                if headers.contains_key("x-firewall-mitm") {
                    let host = headers.get("host").and_then(|h| h.to_str().ok());
                    let reason = format!("{:?}", err);
                    return Ok(make_dynamic_block_response(&payload, host, &reason));
                }
                return Err(err);
            }
        }
    }

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

    // Record Telemetry for PII redaction / Passthrough
    let (redacted_count, secret_types) = {
        let lock = token_map_arc.lock().unwrap();
        (lock.len(), lock.secret_types())
    };

    let cost_model = guardian_core::telemetry::CostModel::default();
    let (event_type, tier_triggered, estimated_cost_saved_usd) = if redacted_count > 0 {
        let tier = if secret_types.contains(&guardian_core::redact::PiiType::Person) {
            guardian_core::telemetry::DetectionTier::Tier3Ner
        } else if secret_types.contains(&guardian_core::redact::PiiType::HighEntropy) {
            guardian_core::telemetry::DetectionTier::Tier2Entropy
        } else if secret_types.contains(&guardian_core::redact::PiiType::Custom) {
            guardian_core::telemetry::DetectionTier::CustomRule
        } else {
            guardian_core::telemetry::DetectionTier::Tier1Regex
        };
        let savings = cost_model.calculate_event_savings(
            guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
            &secret_types,
            redacted_count,
        );
        (
            guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
            Some(tier),
            savings,
        )
    } else {
        (
            guardian_core::telemetry::TelemetryEventType::Passthrough,
            None,
            0.0,
        )
    };

    if let Some(ref tx) = state.telemetry_tx {
        let event = guardian_core::telemetry::TelemetryEvent {
            timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
            request_id: request_id.clone(),
            event_type,
            tier_triggered,
            secret_types,
            redacted_count,
            sandbox_violation: None,
            model: model_name.clone(),
            latency_ms: start_time.elapsed().as_millis() as u64,
            estimated_cost_saved_usd,
        };
        let _ = tx.send(event);
    }

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
    let mut target_url = if headers.contains_key("x-firewall-mitm") {
        if let Some(host_header) = headers.get(axum::http::header::HOST) {
            if let Ok(host_str) = host_header.to_str() {
                reqwest::Url::parse(&format!("https://{}", host_str))
                    .unwrap_or_else(|_| state.upstream_url.clone())
            } else {
                state.upstream_url.clone()
            }
        } else {
            state.upstream_url.clone()
        }
    } else {
        state.upstream_url.clone()
    };

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
    let mut req_headers = copy_request_headers(&headers, &target_url)?;

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

        create_sse_response_stream(
            response,
            token_map_arc,
            state.telemetry_tx.clone(),
            request_id,
            model_name,
        )
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

/// Handles Anthropic Messages API requests (`/v1/messages`).
///
/// Features:
/// - Intercepts inbound Anthropic JSON payloads (`system`, `messages[].content`).
/// - Swaps detected secrets and PII with reversible tokens (`[REDACTED_*]`).
/// - Injects guard instructions into the `system` prompt to ensure Claude preserves tokens.
/// - Multiplexes upstream target URL: points to `https://api.anthropic.com` (or `ANTHROPIC_UPSTREAM_URL` / custom).
/// - Transparently mutates return SSE streams (`event: content_block_delta`), restoring tokens in safe context.
/// - Employs lookbehind sink detection to prevent exfiltration into `curl`, `eval`, or shell commands.
pub async fn anthropic_messages_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ProxyError> {
    let start_time = Instant::now();

    // 1. Enforce payload limit
    let limit = 5 * 1024 * 1024;
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

    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "req-anthropic-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        });

    let mut payload: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| ProxyError::BadRequest(format!("Invalid JSON payload: {}", e)))?;

    let model_name = payload
        .get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());

    // Check preflight plan sandbox violations
    if let Some(ref plan) = state.preflight_plan {
        if plan.sandbox.enforce_jailing {
            if let Err(err) = inspect_json_for_sandbox_violations(&payload, &plan.sandbox) {
                if let Some(ref tx) = state.telemetry_tx {
                    let cost_model = guardian_core::telemetry::CostModel::default();
                    let event = guardian_core::telemetry::TelemetryEvent {
                        timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
                        request_id: request_id.clone(),
                        event_type: guardian_core::telemetry::TelemetryEventType::SandboxBlocked,
                        tier_triggered: Some(guardian_core::telemetry::DetectionTier::SandboxJail),
                        secret_types: Vec::new(),
                        redacted_count: 0,
                        sandbox_violation: Some(format!("{:?}", err)),
                        model: model_name.clone(),
                        latency_ms: start_time.elapsed().as_millis() as u64,
                        estimated_cost_saved_usd: cost_model.sandbox_violation_usd,
                    };
                    let _ = tx.send(event);
                }
                if headers.contains_key("x-firewall-mitm") {
                    let host = headers.get("host").and_then(|h| h.to_str().ok());
                    let reason = format!("{:?}", err);
                    return Ok(make_dynamic_block_response(&payload, host, &reason));
                }
                return Err(err);
            }
        }
    }

    // Instantiate per-request TokenMap
    let token_map_arc = Arc::new(std::sync::Mutex::new(TokenMap::new()));

    // Run Orchestrator Pipeline
    let orchestrator = guardian_core::orchestrator::DetectionOrchestrator::with_config(
        state.model.clone(),
        state.domain,
        state.guardian_config.as_ref(),
    );
    guardian_core::redact::process_anthropic_payload_with_orchestrator(
        &mut payload,
        &token_map_arc,
        &orchestrator,
    )
    .await
    .map_err(|e| ProxyError::BadRequest(format!("Pipeline failure: {}", e)))?;

    // Record Telemetry
    let (redacted_count, secret_types) = {
        let lock = token_map_arc.lock().unwrap();
        (lock.len(), lock.secret_types())
    };

    let cost_model = guardian_core::telemetry::CostModel::default();
    let (event_type, tier_triggered, estimated_cost_saved_usd) = if redacted_count > 0 {
        let tier = if secret_types.contains(&guardian_core::redact::PiiType::Person) {
            guardian_core::telemetry::DetectionTier::Tier3Ner
        } else if secret_types.contains(&guardian_core::redact::PiiType::HighEntropy) {
            guardian_core::telemetry::DetectionTier::Tier2Entropy
        } else if secret_types.contains(&guardian_core::redact::PiiType::Custom) {
            guardian_core::telemetry::DetectionTier::CustomRule
        } else {
            guardian_core::telemetry::DetectionTier::Tier1Regex
        };
        let savings = cost_model.calculate_event_savings(
            guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
            &secret_types,
            redacted_count,
        );
        (
            guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
            Some(tier),
            savings,
        )
    } else {
        (
            guardian_core::telemetry::TelemetryEventType::Passthrough,
            None,
            0.0,
        )
    };

    if let Some(ref tx) = state.telemetry_tx {
        let event = guardian_core::telemetry::TelemetryEvent {
            timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
            request_id: request_id.clone(),
            event_type,
            tier_triggered,
            secret_types,
            redacted_count,
            sandbox_violation: None,
            model: model_name.clone(),
            latency_ms: start_time.elapsed().as_millis() as u64,
            estimated_cost_saved_usd,
        };
        let _ = tx.send(event);
    }

    // Inject system prompt guard instruction for Anthropic (AD-11)
    let guard_instruction = "IMPORTANT: Do not alter, mutate, lowercase, or reformulate any token matching the pattern [REDACTED_*]. These tokens are placeholders and must be preserved exactly as-is.";
    if let Some(sys) = payload.get_mut("system") {
        if let Some(s) = sys.as_str() {
            *sys = serde_json::Value::String(format!("{}\n\n{}", guard_instruction, s));
        } else if let Some(arr) = sys.as_array_mut() {
            arr.insert(
                0,
                serde_json::json!({
                    "type": "text",
                    "text": guard_instruction
                }),
            );
        }
    } else {
        payload["system"] = serde_json::Value::String(guard_instruction.to_string());
    }

    // Serialize modified payload
    let new_bytes = serde_json::to_vec(&payload)
        .map_err(|e| ProxyError::Internal(format!("Failed to serialize payload: {}", e)))?;

    // Reconstruct target URL for Anthropic
    let query = uri.query();
    let mut target_url = if headers.contains_key("x-firewall-mitm") {
        if let Some(host_header) = headers.get(axum::http::header::HOST) {
            if let Ok(host_str) = host_header.to_str() {
                reqwest::Url::parse(&format!("https://{}", host_str))
                    .unwrap_or_else(|_| state.upstream_url.clone())
            } else {
                state.upstream_url.clone()
            }
        } else {
            state.upstream_url.clone()
        }
    } else if let Ok(anthropic_url) = std::env::var("ANTHROPIC_UPSTREAM_URL") {
        reqwest::Url::parse(&anthropic_url).unwrap_or_else(|_| state.upstream_url.clone())
    } else if state.upstream_url.host_str() == Some("api.openai.com") {
        reqwest::Url::parse("https://api.anthropic.com")
            .unwrap_or_else(|_| state.upstream_url.clone())
    } else {
        state.upstream_url.clone()
    };

    let base_path = target_url.path().trim_end_matches('/');
    let joined_path = if base_path.is_empty() {
        "/v1/messages".to_string()
    } else {
        format!("{}/v1/messages", base_path)
    };
    target_url.set_path(&joined_path);

    let merged_query = merge_queries(&state.upstream_url, query);
    target_url.set_query(merged_query.as_deref());

    // Prepare headers
    let mut req_headers = copy_request_headers(&headers, &target_url)?;
    let length = new_bytes.len();
    req_headers.insert(
        reqwest::header::CONTENT_LENGTH,
        reqwest::header::HeaderValue::from(length),
    );

    // Send request
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
    let mut res_headers = copy_response_headers(response.headers())?;

    let duration = start_time.elapsed().as_millis();
    tracing::info!(
        method = method.as_str(),
        path = "/v1/messages",
        duration_ms = duration,
        status_code = status.as_u16(),
        "Intercepted Anthropic messages request proxied successfully"
    );

    // Detect SSE
    let is_sse = res_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let axum_body = if is_sse {
        res_headers.remove(axum::http::header::CONTENT_LENGTH);
        create_sse_response_stream(
            response,
            token_map_arc,
            state.telemetry_tx.clone(),
            request_id,
            model_name,
        )
    } else {
        // For non-streaming responses, restore tokens if JSON
        let content_type = res_headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if status.is_success() && content_type.contains("application/json") {
            let res_bytes = response
                .bytes()
                .await
                .map_err(|e| ProxyError::Upstream(e.to_string()))?;

            if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&res_bytes) {
                let (tokens, original_values) = {
                    let lock = token_map_arc.lock().unwrap();
                    let mut t = Vec::new();
                    let mut v = Vec::new();
                    for k in lock.keys() {
                        if let Some((secret, _)) = lock.get(k) {
                            t.push(k.clone());
                            v.push(secret.clone());
                        }
                    }
                    (t, v)
                };

                if !tokens.is_empty() {
                    if let Ok(ac) = aho_corasick::AhoCorasick::new(&tokens) {
                        if let Some(content_arr) =
                            json.get_mut("content").and_then(|c| c.as_array_mut())
                        {
                            for block in content_arr {
                                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(text) =
                                        block.get_mut("text").and_then(|t| t.as_str())
                                    {
                                        let replaced = ac.replace_all(text, &original_values);
                                        block["text"] = serde_json::Value::String(replaced);
                                    }
                                }
                            }
                        }
                    }
                }

                let out_bytes = serde_json::to_vec(&json)
                    .map_err(|e| ProxyError::Internal(format!("Serialization error: {}", e)))?;
                res_headers.insert(
                    axum::http::header::CONTENT_LENGTH,
                    axum::http::HeaderValue::from(out_bytes.len()),
                );
                Body::from(out_bytes)
            } else {
                Body::from(res_bytes)
            }
        } else {
            Body::from_stream(response.bytes_stream())
        }
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

/// Builds a dynamic HTTP response mimicking an LLM provider block.
/// Detects stream vs REST and OpenAI vs Anthropic from payload/headers.
pub fn make_dynamic_block_response(
    payload: &serde_json::Value,
    host: Option<&str>,
    reason: &str,
) -> Response {
    let is_stream = payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_anthropic = host.unwrap_or("").contains("anthropic");

    let msg = format!("⚠️ **LLM Firewall blocked this request.** {}", reason);

    if is_stream {
        if is_anthropic {
            let chunk = serde_json::json!({
                "type": "message_delta",
                "delta": {
                    "text": msg
                }
            });
            let body = format!(
                "event: message_delta\ndata: {}\n\nevent: message_stop\ndata: {{}}\n\n",
                serde_json::to_string(&chunk).unwrap()
            );
            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Firewall-Block", "true")
                .body(Body::from(body))
                .unwrap()
        } else {
            let chunk1 = serde_json::json!({
                "id": "fw-block",
                "object": "chat.completion.chunk",
                "choices": [{
                    "delta": { "content": msg },
                    "index": 0,
                    "finish_reason": null
                }]
            });
            let chunk2 = serde_json::json!({
                "id": "fw-block",
                "object": "chat.completion.chunk",
                "choices": [{"delta": {}, "index": 0, "finish_reason": "stop"}]
            });
            let body = format!(
                "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                serde_json::to_string(&chunk1).unwrap(),
                serde_json::to_string(&chunk2).unwrap()
            );
            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Firewall-Block", "true")
                .body(Body::from(body))
                .unwrap()
        }
    } else {
        if is_anthropic {
            let body = serde_json::json!({
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": msg}]
            });
            Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .header("X-Firewall-Block", "true")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        } else {
            let body = serde_json::json!({
                "id": "fw-block",
                "object": "chat.completion",
                "choices": [{
                    "message": { "role": "assistant", "content": msg },
                    "index": 0,
                    "finish_reason": "stop"
                }]
            });
            Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .header("X-Firewall-Block", "true")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }
    }
}
