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
    let reqwest_body = if path.contains("RunSSE") || path.contains("BidiAppend") {
        let bytes = axum::body::to_bytes(body, 5 * 1024 * 1024)
            .await
            .unwrap_or_default();

        let mut data = bytes.to_vec();
        if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(data.as_slice());
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                data = decompressed;
            }
        }

        let mut combined_text = String::from_utf8_lossy(&data).into_owned();
        let mut current_hex = String::new();
        for c in combined_text.clone().chars() {
            if c.is_ascii_hexdigit() {
                current_hex.push(c);
            } else {
                if current_hex.len() >= 32 && current_hex.len() % 2 == 0 {
                    if let Ok(decoded) = hex::decode(&current_hex) {
                        combined_text.push('\n');
                        combined_text.push_str(&String::from_utf8_lossy(&decoded));
                    }
                }
                current_hex.clear();
            }
        }
        if current_hex.len() >= 32 && current_hex.len() % 2 == 0 {
            if let Ok(decoded) = hex::decode(&current_hex) {
                combined_text.push('\n');
                combined_text.push_str(&String::from_utf8_lossy(&decoded));
            }
        }

        let orchestrator = guardian_core::orchestrator::DetectionOrchestrator::with_config(
            state.model.clone(),
            state.domain,
            state.guardian_config.as_ref(),
        );

        if let Ok(spans) = orchestrator.orchestrate(&combined_text).await {
            if !spans.is_empty() {
                tracing::warn!("PII DETECTED IN CURSOR ENDPOINT [{}] -> BLOCKING!", path);

                // Telemetry tracking for blocked request
                if let Some(ref tx) = state.telemetry_tx {
                    let cost_model = guardian_core::telemetry::CostModel::default();
                    let request_id = format!(
                        "req-cursor-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );
                    let mut secret_types = vec![];
                    for span in &spans {
                        if !secret_types.contains(&span.label) {
                            secret_types.push(span.label);
                        }
                    }
                    let event = guardian_core::telemetry::TelemetryEvent {
                        timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
                        request_id,
                        event_type: guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
                        tier_triggered: Some(guardian_core::telemetry::DetectionTier::Tier3Ner),
                        secret_types,
                        redacted_count: spans.len(),
                        sandbox_violation: None,
                        model: Some("cursor-custom".to_string()),
                        latency_ms: start_time.elapsed().as_millis() as u64,
                        estimated_cost_saved_usd: cost_model.calculate_event_savings(
                            guardian_core::telemetry::TelemetryEventType::PiiIntercepted,
                            &[],
                            spans.len(),
                        ),
                    };
                    let _ = tx.send(event);
                }

                return axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        "{\"error\": \"LLM Firewall: PII detected in Cursor request!\"}",
                    ))
                    .unwrap();
            }
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
            telemetry_tx: Option<
                tokio::sync::mpsc::UnboundedSender<guardian_core::telemetry::TelemetryEvent>,
            >,
            request_id: String,
            model: Option<String>,
        }

        impl SseState {
            fn process_event(&mut self, event: Vec<u8>) -> Vec<u8> {
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
                            self.lookbehind.push_str(content.as_str());
                            if self.lookbehind.len() > 512 {
                                let trim_pos = self.lookbehind.len() - 512;
                                let mut char_pos = trim_pos;
                                while char_pos < self.lookbehind.len()
                                    && !self.lookbehind.is_char_boundary(char_pos)
                                {
                                    char_pos += 1;
                                }
                                self.lookbehind = self.lookbehind[char_pos..].to_string();
                            }

                            let to_scan = self.fragment_buf.clone() + content.as_str();

                            let mut partial = String::new();
                            let mut full_content_to_replace = to_scan.clone();

                            if let Some(incomplete_start) = to_scan.rfind("[REDACT") {
                                if !to_scan[incomplete_start..].contains(']') {
                                    partial = to_scan[incomplete_start..].to_string();
                                    full_content_to_replace =
                                        to_scan[..incomplete_start].to_string();
                                }
                            }

                            self.fragment_buf = partial;

                            let (tokens, original_values) = {
                                let lock = self.token_map.lock().unwrap();
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
                                let is_dangerous =
                                    self.sink_detector.is_dangerous_context(&self.lookbehind);
                                if is_dangerous {
                                    tracing::warn!(
                                        lookbehind = %self.lookbehind,
                                        "Dangerous sink context detected, blocking token re-injection"
                                    );
                                    if let Some(ref tx) = self.telemetry_tx {
                                        let ev = guardian_core::telemetry::TelemetryEvent {
                                            timestamp: guardian_core::telemetry::TelemetryEvent::current_timestamp(),
                                            request_id: self.request_id.clone(),
                                            event_type: guardian_core::telemetry::TelemetryEventType::SinkBlocked,
                                            tier_triggered: Some(guardian_core::telemetry::DetectionTier::DangerousSink),
                                            secret_types: Vec::new(),
                                            redacted_count: 0,
                                            sandbox_violation: None,
                                            model: self.model.clone(),
                                            latency_ms: 0,
                                            estimated_cost_saved_usd: 2500.0,
                                        };
                                        let _ = tx.send(ev);
                                    }
                                    full_content_to_replace
                                } else {
                                    match aho_corasick::AhoCorasick::new(&tokens) {
                                        Ok(ac) => ac.replace_all(
                                            &full_content_to_replace,
                                            &original_values,
                                        ),
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
            telemetry_tx: state.telemetry_tx.clone(),
            request_id: request_id.clone(),
            model: model_name.clone(),
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
                    let processed_event = s.process_event(event);

                    // Collect any additional complete events into pending (LIFO pop, so reverse).
                    let mut extra = Vec::new();
                    while let Some(p2) = find_double_newline(&s.buf) {
                        let ev2: Vec<u8> = s.buf.drain(..p2).collect();
                        let processed_ev2 = s.process_event(ev2);
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

/// Find the end boundary of the first complete SSE event in `buf`.
///
/// Returns `Some(pos)` where `pos` is the index *after* the `\n\n` delimiter,
/// i.e. `buf[..pos]` is the complete event including both newlines.
/// Returns `None` if no `\n\n` boundary is found.
fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
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
