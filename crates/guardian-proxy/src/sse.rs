//! Server-Sent Events (SSE) streaming mutation and token restoration engine.
//!
//! This module handles bidirectional streaming SSE transformation:
//! - Unfolds upstream chunks from OpenAI and Anthropic SSE streams.
//! - Detects `choices[].delta.content` (OpenAI) and `delta.text` (Anthropic).
//! - Maintains a 512-byte sliding lookbehind window to detect dangerous execution sinks
//!   (e.g., `curl`, `eval`, `subprocess`, `os.system`).
//! - Re-injects original secret values in safe contexts via Aho-Corasick matching.
//! - Quarantines secrets if dangerous sinks are detected, recording security telemetry.

use axum::body::Body;
use futures_util::StreamExt;
use guardian_core::TokenMap;
use std::sync::Arc;

pub type UpstreamStream =
    dyn futures_core::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + Unpin;

pub struct SseState {
    pub upstream: Box<UpstreamStream>,
    pub buf: Vec<u8>,
    pub pending: Vec<bytes::Bytes>,
    pub done: bool,
    pub token_map: Arc<std::sync::Mutex<TokenMap>>,
    pub fragment_buf: String,
    pub lookbehind: String,
    pub sink_detector: guardian_core::DangerousSinkDetector,
    pub telemetry_tx:
        Option<tokio::sync::mpsc::UnboundedSender<guardian_core::telemetry::TelemetryEvent>>,
    pub request_id: String,
    pub model: Option<String>,
}

impl SseState {
    pub fn mutate_text(&mut self, content: &mut String) -> bool {
        self.lookbehind.push_str(content.as_str());
        if self.lookbehind.len() > 512 {
            let trim_pos = self.lookbehind.len() - 512;
            let mut char_pos = trim_pos;
            while char_pos < self.lookbehind.len() && !self.lookbehind.is_char_boundary(char_pos) {
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
                full_content_to_replace = to_scan[..incomplete_start].to_string();
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
            let is_dangerous = self.sink_detector.is_dangerous_context(&self.lookbehind);
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
                        tier_triggered: Some(
                            guardian_core::telemetry::DetectionTier::DangerousSink,
                        ),
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

        if final_content != *content {
            *content = final_content;
            true
        } else {
            false
        }
    }

    pub fn process_event(&mut self, event: Vec<u8>) -> Vec<u8> {
        let event_str = match std::str::from_utf8(&event) {
            Ok(s) => s,
            Err(_) => return event,
        };

        let data_pos = match event_str.find("data: ") {
            Some(pos) => pos,
            None => return event,
        };

        let prefix = &event_str[..data_pos];
        let after_data = &event_str[data_pos + 6..];
        let data_line_end = after_data.find('\n').unwrap_or(after_data.len());
        let data_str = after_data[..data_line_end].trim();

        if data_str == "[DONE]" || data_str.is_empty() {
            return event;
        }

        let mut parsed: serde_json::Value = match serde_json::from_str(data_str) {
            Ok(v) => v,
            Err(_) => return event,
        };

        let mut modified = false;

        // 1. OpenAI format: choices[].delta.content or choices[].message.content
        if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                let content_target = if let Some(delta) = choice.get_mut("delta") {
                    delta.get_mut("content")
                } else if let Some(message) = choice.get_mut("message") {
                    message.get_mut("content")
                } else {
                    None
                };

                if let Some(serde_json::Value::String(ref mut content)) = content_target {
                    if self.mutate_text(content) {
                        modified = true;
                    }
                }
            }
        }

        // 2. Anthropic format: delta.text
        if let Some(delta) = parsed.get_mut("delta") {
            if let Some(text_val) = delta.get_mut("text") {
                if let Some(serde_json::Value::String(ref mut content)) = Some(text_val) {
                    if self.mutate_text(content) {
                        modified = true;
                    }
                }
            }
        }

        if modified {
            let mut new_event = String::from(prefix);
            new_event.push_str("data: ");
            new_event
                .push_str(&serde_json::to_string(&parsed).unwrap_or_else(|_| data_str.to_string()));
            new_event.push_str("\n\n");
            return new_event.into_bytes();
        }

        event
    }
}

/// Constructs an Axum streaming `Body` that transparently mutates incoming SSE events.
pub fn create_sse_response_stream(
    response: reqwest::Response,
    token_map_arc: Arc<std::sync::Mutex<TokenMap>>,
    telemetry_tx: Option<
        tokio::sync::mpsc::UnboundedSender<guardian_core::telemetry::TelemetryEvent>,
    >,
    request_id: String,
    model_name: Option<String>,
) -> Body {
    let upstream_stream = response.bytes_stream();
    let state = SseState {
        upstream: Box::new(upstream_stream),
        buf: Vec::new(),
        pending: Vec::new(),
        done: false,
        token_map: token_map_arc,
        fragment_buf: String::new(),
        lookbehind: String::new(),
        sink_detector: guardian_core::DangerousSinkDetector::new(),
        telemetry_tx,
        request_id,
        model: model_name,
    };

    let output_stream = futures_util::stream::unfold(state, |mut s| async move {
        if let Some(event) = s.pending.pop() {
            return Some((Ok::<bytes::Bytes, axum::Error>(event), s));
        }

        if s.done {
            if !s.buf.is_empty() {
                let remaining = bytes::Bytes::from(std::mem::take(&mut s.buf));
                return Some((Ok(remaining), s));
            }
            return None;
        }

        loop {
            if let Some(pos) = find_double_newline(&s.buf) {
                let event: Vec<u8> = s.buf.drain(..pos).collect();
                let processed_event = s.process_event(event);

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

            match s.upstream.next().await {
                Some(Ok(chunk)) => {
                    s.buf.extend_from_slice(&chunk);
                }
                Some(Err(e)) => {
                    s.done = true;
                    return Some((Err(axum::Error::new(e)), s));
                }
                None => {
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
}

/// Find the end boundary of the first complete SSE event in `buf`.
///
/// Returns `Some(pos)` where `pos` is the index *after* the `\n\n` delimiter,
/// i.e. `buf[..pos]` is the complete event including both newlines.
/// Returns `None` if no `\n\n` boundary is found.
pub fn find_double_newline(buf: &[u8]) -> Option<usize> {
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
