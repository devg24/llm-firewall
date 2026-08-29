use crate::AppState;
use std::time::Instant;

pub fn is_target_endpoint(path: &str) -> bool {
    path.contains("RunSSE") || path.contains("BidiAppend")
}

pub async fn intercept(
    path: &str,
    bytes: &[u8],
    state: &AppState,
    start_time: Instant,
) -> Result<Option<axum::response::Response>, crate::proxy::ProxyError> {
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

            let connect_err_json = "{\n  \"code\": \"permission_denied\",\n  \"message\": \"LLM Firewall: PII detected in Cursor request!\"\n}";

            return Ok(Some(
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    // gRPC headers so gRPC clients don't treat it as a generic HTTP failure and retry
                    .header("grpc-status", "7")
                    .header(
                        "grpc-message",
                        "LLM Firewall: PII detected in Cursor request!",
                    )
                    .body(axum::body::Body::from(connect_err_json))
                    .unwrap(),
            ));
        }
    }

    Ok(None)
}
