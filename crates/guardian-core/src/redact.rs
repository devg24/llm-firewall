use crate::error::CoreError;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

use crate::token_map::TokenMap;

pub fn process_completions_payload(payload: &mut serde_json::Value) -> Result<(), CoreError> {
    let mut token_map = TokenMap::new();
    process_completions_payload_with_map(payload, &mut token_map)
}

pub fn process_completions_payload_with_map(
    payload: &mut serde_json::Value,
    token_map: &mut TokenMap,
) -> Result<(), CoreError> {
    let messages = payload
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| {
            CoreError::PayloadValidation("Missing or invalid 'messages' array".to_string())
        })?;

    let mut state = RedactionState::new();

    for message in messages {
        if let Some(content) = message.get_mut("content") {
            mutate_content_field(content, &mut state, token_map, 0);
        }
        if let Some(name) = message.get_mut("name") {
            mutate_content_field(name, &mut state, token_map, 0);
        }
        if let Some(tool_calls) = message.get_mut("tool_calls") {
            mutate_content_field(tool_calls, &mut state, token_map, 0);
        }
        if let Some(function_call) = message.get_mut("function_call") {
            mutate_content_field(function_call, &mut state, token_map, 0);
        }
    }
    Ok(())
}

pub fn mutate_content_field(
    content: &mut serde_json::Value,
    state: &mut RedactionState,
    token_map: &mut TokenMap,
    depth: usize,
) {
    if depth > 100 {
        return;
    }
    match content {
        serde_json::Value::String(s) => {
            let normalized = normalize_text(s);
            let mut matches = collect_regex_matches(&normalized);
            resolve_overlaps(&mut matches);
            *s = redact_text(&normalized, &matches, state, token_map);
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                mutate_content_field(item, state, token_map, depth + 1);
            }
        }
        serde_json::Value::Object(obj) => {
            if let Some(serde_json::Value::String(text_val)) = obj.get_mut("text") {
                let normalized = normalize_text(text_val);
                let mut matches = collect_regex_matches(&normalized);
                resolve_overlaps(&mut matches);
                *text_val = redact_text(&normalized, &matches, state, token_map);
            }
            for (key, val) in obj.iter_mut() {
                if key != "image_url" && key != "type" && key != "role" {
                    if key == "text" && val.is_string() {
                        continue;
                    }
                    mutate_content_field(val, state, token_map, depth + 1);
                }
            }
        }
        _ => {}
    }
}

static SSN_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IP_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV6_REGEX: OnceLock<Regex> = OnceLock::new();
static AWS_REGEX: OnceLock<Regex> = OnceLock::new();
static GCP_REGEX: OnceLock<Regex> = OnceLock::new();
static GITHUB_REGEX: OnceLock<Regex> = OnceLock::new();
static BEARER_REGEX: OnceLock<Regex> = OnceLock::new();

const SSN_PATTERN: &str = r"\b\d{3}-\d{2}-\d{4}\b";
const CC_PATTERN: &str = r"\b(?:\d[ -]*?){13,19}\b";
const EMAIL_PATTERN: &str = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b";
const PHONE_PATTERN: &str = r"\b(?:\+?\d{1,3}[- .]?)?\(?\d{3}\)?[- .]?\d{3}[- .]?\d{4}\b";
const IP_PATTERN: &str = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";
const IPV6_PATTERN: &str = r"(?i)\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b|(?:\b(?:[0-9a-fA-F]{1,4}:){1,6})?::(?:[0-9a-fA-F]{1,4}\b)?|::[0-9a-fA-F]{1,4}\b";
const AWS_PATTERN: &str = r"(?i)\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b";
const GCP_PATTERN: &str = r"(?i)\bAIza[0-9A-Za-z-_]{35}\b";
const GITHUB_PATTERN: &str = r"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b";
const BEARER_PATTERN: &str = r"(?i)\bbearer\s+[A-Za-z0-9\-\._~\+\/]+=*\b";

pub fn init_regexes() {
    let _ = SSN_REGEX.get_or_init(|| Regex::new(SSN_PATTERN).unwrap());
    let _ = CC_REGEX.get_or_init(|| Regex::new(CC_PATTERN).unwrap());
    let _ = EMAIL_REGEX.get_or_init(|| Regex::new(EMAIL_PATTERN).unwrap());
    let _ = PHONE_REGEX.get_or_init(|| Regex::new(PHONE_PATTERN).unwrap());
    let _ = IP_REGEX.get_or_init(|| Regex::new(IP_PATTERN).unwrap());
    let _ = IPV6_REGEX.get_or_init(|| Regex::new(IPV6_PATTERN).unwrap());
    let _ = AWS_REGEX.get_or_init(|| Regex::new(AWS_PATTERN).unwrap());
    let _ = GCP_REGEX.get_or_init(|| Regex::new(GCP_PATTERN).unwrap());
    let _ = GITHUB_REGEX.get_or_init(|| Regex::new(GITHUB_PATTERN).unwrap());
    let _ = BEARER_REGEX.get_or_init(|| Regex::new(BEARER_PATTERN).unwrap());
}

pub fn ssn_regex() -> &'static Regex {
    SSN_REGEX.get_or_init(|| Regex::new(SSN_PATTERN).unwrap())
}

pub fn cc_regex() -> &'static Regex {
    CC_REGEX.get_or_init(|| Regex::new(CC_PATTERN).unwrap())
}

pub fn email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| Regex::new(EMAIL_PATTERN).unwrap())
}

pub fn phone_regex() -> &'static Regex {
    PHONE_REGEX.get_or_init(|| Regex::new(PHONE_PATTERN).unwrap())
}

pub fn ip_regex() -> &'static Regex {
    IP_REGEX.get_or_init(|| Regex::new(IP_PATTERN).unwrap())
}

pub fn ipv6_regex() -> &'static Regex {
    IPV6_REGEX.get_or_init(|| Regex::new(IPV6_PATTERN).unwrap())
}

pub fn aws_regex() -> &'static Regex {
    AWS_REGEX.get_or_init(|| Regex::new(AWS_PATTERN).unwrap())
}

pub fn gcp_regex() -> &'static Regex {
    GCP_REGEX.get_or_init(|| Regex::new(GCP_PATTERN).unwrap())
}

pub fn github_regex() -> &'static Regex {
    GITHUB_REGEX.get_or_init(|| Regex::new(GITHUB_PATTERN).unwrap())
}

pub fn bearer_regex() -> &'static Regex {
    BEARER_REGEX.get_or_init(|| Regex::new(BEARER_PATTERN).unwrap())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiType {
    Ssn,
    Cc,
    Email,
    Phone,
    Ip,
    Aws,
    Gcp,
    Github,
    Bearer,
    HighEntropy,
    Person,
    Custom,
    Unknown,
}

impl PiiType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiType::Ssn => "SSN",
            PiiType::Cc => "CC",
            PiiType::Email => "EMAIL",
            PiiType::Phone => "PHONE",
            PiiType::Ip => "IP",
            PiiType::Aws => "AWS",
            PiiType::Gcp => "GCP",
            PiiType::Github => "GITHUB",
            PiiType::Bearer => "BEARER",
            PiiType::HighEntropy => "HIGH_ENTROPY",
            PiiType::Person => "PERSON",
            PiiType::Custom => "CUSTOM",
            PiiType::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub start: usize,
    pub end: usize,
    pub pii_type: PiiType,
    pub value: String,
}

pub fn normalize_text(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    for c in text.nfc() {
        if c == '\u{200B}' || c == '\u{200C}' || c == '\u{200D}' {
            continue;
        }
        if c.is_control() {
            if c == '\n' || c == '\r' || c == '\t' {
                normalized.push(c);
            }
            continue;
        }
        normalized.push(c);
    }
    normalized
}

pub fn collect_regex_matches(text: &str) -> Vec<PiiMatch> {
    let mut matches = Vec::new();

    // 1. SSN
    for mat in ssn_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Ssn,
            value: mat.as_str().to_string(),
        });
    }
    // 2. CC
    for mat in cc_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Cc,
            value: mat.as_str().to_string(),
        });
    }
    // 3. Email
    for mat in email_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Email,
            value: mat.as_str().to_string(),
        });
    }
    // 4. Phone
    for mat in phone_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Phone,
            value: mat.as_str().to_string(),
        });
    }
    // 5. IP
    for mat in ip_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Ip,
            value: mat.as_str().to_string(),
        });
    }
    // 6. IPv6
    for mat in ipv6_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Ip,
            value: mat.as_str().to_string(),
        });
    }
    // 7. AWS
    for mat in aws_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Aws,
            value: mat.as_str().to_string(),
        });
    }
    // 8. GCP
    for mat in gcp_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Gcp,
            value: mat.as_str().to_string(),
        });
    }
    // 9. GitHub
    for mat in github_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Github,
            value: mat.as_str().to_string(),
        });
    }
    // 10. Bearer
    for mat in bearer_regex().find_iter(text) {
        matches.push(PiiMatch {
            start: mat.start(),
            end: mat.end(),
            pii_type: PiiType::Bearer,
            value: mat.as_str().to_string(),
        });
    }

    matches
}

pub fn resolve_overlaps(matches: &mut Vec<PiiMatch>) {
    matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

    let mut resolved: Vec<PiiMatch> = Vec::with_capacity(matches.len());

    for m in matches.drain(..) {
        if resolved.is_empty() || m.start >= resolved.last().unwrap().end {
            resolved.push(m);
        } else {
            if let Some(last) = resolved.last_mut() {
                if m.end > last.end {
                    last.end = m.end;
                }
            }
        }
    }
    *matches = resolved;
}

pub struct RedactionState {
    pub map: HashMap<(String, PiiType), String>,
    pub counters: HashMap<PiiType, usize>,
}

impl Default for RedactionState {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionState {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    pub fn get_or_create_token(&mut self, value: &str, pii_type: PiiType) -> String {
        let key = (value.to_lowercase(), pii_type);
        if let Some(token) = self.map.get(&key) {
            token.clone()
        } else {
            let count = self.counters.entry(pii_type).or_insert(0);
            *count += 1;
            let token = format!("[REDACTED_{}_{}]", pii_type.as_str(), count);
            self.map.insert(key, token.clone());
            token
        }
    }
}

pub fn redact_text(
    text: &str,
    matches: &[PiiMatch],
    state: &mut RedactionState,
    token_map: &mut TokenMap,
) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut last_idx = 0;

    for m in matches {
        if m.start > last_idx {
            redacted.push_str(&text[last_idx..m.start]);
        }
        let token = state.get_or_create_token(&m.value, m.pii_type);
        token_map.insert(token.clone(), m.value.clone(), m.pii_type);
        redacted.push_str(&token);
        last_idx = m.end;
    }

    if last_idx < text.len() {
        redacted.push_str(&text[last_idx..]);
    }

    redacted
}

pub async fn process_completions_payload_with_orchestrator(
    payload: &mut serde_json::Value,
    token_map: &std::sync::Arc<std::sync::Mutex<crate::token_map::TokenMap>>,
    orchestrator: &crate::orchestrator::DetectionOrchestrator,
) -> Result<(), crate::CoreError> {
    let messages = payload
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| {
            crate::CoreError::PayloadValidation("Missing or invalid 'messages' array".to_string())
        })?;

    for message in messages {
        if let Some(content) = message.get_mut("content") {
            mutate_content_field_with_orchestrator(content, token_map, orchestrator, 0).await;
        }
    }

    Ok(())
}

/// Processes an Anthropic Messages API payload (`/v1/messages`).
///
/// In Anthropic's format:
/// - `system` can be an optional string or an array of content blocks (e.g. `[{"type": "text", "text": "..."}]`).
/// - `messages` is an array of message objects, where each message has a `content` field
///   which can be either a string or an array of content blocks (`[{"type": "text", "text": "..."}]`).
pub async fn process_anthropic_payload_with_orchestrator(
    payload: &mut serde_json::Value,
    token_map: &std::sync::Arc<std::sync::Mutex<crate::token_map::TokenMap>>,
    orchestrator: &crate::orchestrator::DetectionOrchestrator,
) -> Result<(), crate::CoreError> {
    // 1. Redact top-level system prompt if present
    if let Some(system) = payload.get_mut("system") {
        mutate_content_field_with_orchestrator(system, token_map, orchestrator, 0).await;
    }

    // 2. Redact messages array
    let messages = payload
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| {
            crate::CoreError::PayloadValidation(
                "Missing or invalid 'messages' array in Anthropic payload".to_string(),
            )
        })?;

    for message in messages {
        if let Some(content) = message.get_mut("content") {
            mutate_content_field_with_orchestrator(content, token_map, orchestrator, 0).await;
        }
    }

    Ok(())
}

use futures_util::future::BoxFuture;
use futures_util::FutureExt;

pub fn mutate_content_field_with_orchestrator<'a>(
    content: &'a mut serde_json::Value,
    token_map: &'a std::sync::Arc<std::sync::Mutex<crate::token_map::TokenMap>>,
    orchestrator: &'a crate::orchestrator::DetectionOrchestrator,
    depth: usize,
) -> BoxFuture<'a, ()> {
    async move {
        if depth > 100 {
            return;
        }
        match content {
            serde_json::Value::String(s) => {
                let text = s.clone();
                if let Ok(mut spans) = orchestrator.orchestrate(&text).await {
                    if !spans.is_empty() {
                        spans.sort_by_key(|span| span.start);
                        let mut redacted = text.clone();
                        let mut offset: isize = 0;
                        let mut counters = std::collections::HashMap::new();

                        for span in spans {
                            let actual_start = (span.start as isize + offset) as usize;
                            let actual_end = (span.end as isize + offset) as usize;

                            if actual_start > redacted.len() || actual_end > redacted.len() {
                                continue;
                            }

                            let secret = redacted[actual_start..actual_end].to_string();
                            let pii_type = span.label;

                            let count = counters.entry(pii_type).or_insert(1);
                            let token = format!("[REDACTED_{}_{}]", pii_type.as_str(), count);
                            *count += 1;

                            {
                                let mut lock = token_map.lock().unwrap();
                                lock.insert(token.clone(), secret.clone(), pii_type);
                            };

                            redacted.replace_range(actual_start..actual_end, &token);
                            offset += token.len() as isize - (actual_end - actual_start) as isize;
                        }
                        *s = redacted;
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    mutate_content_field_with_orchestrator(v, token_map, orchestrator, depth + 1)
                        .await;
                }
            }
            serde_json::Value::Object(obj) => {
                for v in obj.values_mut() {
                    mutate_content_field_with_orchestrator(v, token_map, orchestrator, depth + 1)
                        .await;
                }
            }
            _ => {}
        }
    }
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_regex() {
        let re = ssn_regex();
        // Valid SSNs
        assert!(
            re.is_match("000-12-3456"),
            "Should match valid SSN 000-12-3456"
        );
        assert!(
            re.is_match("123-45-6789"),
            "Should match valid SSN 123-45-6789"
        );
        // Invalid SSNs
        assert!(
            !re.is_match("123-45-678"),
            "Should reject 9-digit without correct grouping"
        );
        assert!(
            !re.is_match("12-345-6789"),
            "Should reject incorrect grouping"
        );
        assert!(!re.is_match("abc-de-fghj"), "Should reject non-digits");
    }

    #[test]
    fn test_cc_regex() {
        let re = cc_regex();
        // Valid CCs
        assert!(
            re.is_match("1234-5678-9012-3456"),
            "Should match Visa/MC format"
        );
        assert!(re.is_match("1234567890123"), "Should match 13-digit card");
        assert!(
            re.is_match("1234 5678 9012 3456"),
            "Should match with spaces"
        );
        // Invalid CCs
        assert!(
            !re.is_match("123456789012"),
            "Should reject fewer than 13 digits"
        );
        assert!(!re.is_match("abc-def-ghi-jkl"), "Should reject non-digits");
    }

    #[test]
    fn test_email_regex() {
        let re = email_regex();
        // Valid Emails
        assert!(re.is_match("test@example.com"), "Should match simple email");
        assert!(
            re.is_match("user.name+tag@sub.domain.org"),
            "Should match complex email"
        );
        // Invalid Emails
        assert!(!re.is_match("test@"), "Should reject missing domain");
        assert!(
            !re.is_match("@example.com"),
            "Should reject missing local part"
        );
        assert!(!re.is_match("test@example"), "Should reject missing TLD");
    }

    #[test]
    fn test_phone_regex() {
        let re = phone_regex();
        // Valid Phones
        assert!(
            re.is_match("123-456-7890"),
            "Should match format 123-456-7890"
        );
        assert!(
            re.is_match("+1 123 456 7890"),
            "Should match with country code"
        );
        assert!(
            re.is_match("(123) 456-7890"),
            "Should match with parentheses"
        );
        assert!(re.is_match("1234567890"), "Should match continuous digits");
        // Invalid Phones
        assert!(!re.is_match("12345"), "Should reject short numbers");
    }

    #[test]
    fn test_ip_regex() {
        let re = ip_regex();
        // Valid IPs
        assert!(re.is_match("192.168.1.1"), "Should match valid IPv4");
        assert!(re.is_match("10.0.0.1"), "Should match valid IPv4");
        assert!(
            re.is_match("255.255.255.255"),
            "Should match maximum IPv4 address"
        );
        // Invalid IPs
        assert!(
            !re.is_match("999.999.999.999"),
            "Should reject out-of-range octets"
        );
        assert!(
            !re.is_match("256.1.2.3"),
            "Should reject out-of-range first octet"
        );
    }

    #[test]
    fn test_text_normalization() {
        let input = "Hello\u{200B} World!\u{0000}\nPreserved\t\r";
        let output = normalize_text(input);
        assert_eq!(output, "Hello World!\nPreserved\t\r");
    }

    #[test]
    fn test_resolve_overlaps() {
        let mut matches = vec![
            PiiMatch {
                start: 10,
                end: 20,
                pii_type: PiiType::Cc,
                value: "1234567890123456".to_string(),
            },
            PiiMatch {
                start: 12,
                end: 18,
                pii_type: PiiType::Phone,
                value: "123456".to_string(),
            },
            PiiMatch {
                start: 25,
                end: 35,
                pii_type: PiiType::Email,
                value: "a@b.com".to_string(),
            },
        ];
        resolve_overlaps(&mut matches);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pii_type, PiiType::Cc);
        assert_eq!(matches[1].pii_type, PiiType::Email);
    }

    #[test]
    fn test_co_reference_mapping_consistency() {
        let mut state = RedactionState::new();
        let token1 = state.get_or_create_token("123-45-6789", PiiType::Ssn);
        let token2 = state.get_or_create_token("123-45-6789", PiiType::Ssn);
        assert_eq!(token1, "[REDACTED_SSN_1]");
        assert_eq!(token2, "[REDACTED_SSN_1]");

        let token3 = state.get_or_create_token("987-65-4321", PiiType::Ssn);
        assert_eq!(token3, "[REDACTED_SSN_2]");

        let token_email = state.get_or_create_token("test@example.com", PiiType::Email);
        assert_eq!(token_email, "[REDACTED_EMAIL_1]");
    }

    #[test]
    fn test_single_pass_redaction() {
        let text = "My SSN is 123-45-6789 and my friend's SSN is also 123-45-6789. Another friend has 987-65-4321.";
        let normalized = normalize_text(text);
        let mut matches = collect_regex_matches(&normalized);
        resolve_overlaps(&mut matches);

        let mut state = RedactionState::new();
        let mut token_map = TokenMap::new();
        let redacted = redact_text(&normalized, &matches, &mut state, &mut token_map);

        assert_eq!(
            redacted,
            "My SSN is [REDACTED_SSN_1] and my friend's SSN is also [REDACTED_SSN_1]. Another friend has [REDACTED_SSN_2]."
        );
    }

    #[test]
    fn test_ipv6_regex() {
        let re = ipv6_regex();
        assert!(re.is_match("2001:db8:3333:4444:5555:6666:7777:8888"));
        assert!(re.is_match("2001:db8::1234"));
        assert!(re.is_match("::1"));
    }

    #[test]
    fn test_zwnj_normalization() {
        let input = "Hello\u{200C}World\u{200D}!";
        assert_eq!(normalize_text(input), "HelloWorld!");
    }

    #[test]
    fn test_type_partitioned_co_reference() {
        let mut state = RedactionState::new();
        // Same value under different PII types gets different tokens
        let tok1 = state.get_or_create_token("123-456-7890", PiiType::Phone);
        let tok2 = state.get_or_create_token("123-456-7890", PiiType::Cc);
        assert_eq!(tok1, "[REDACTED_PHONE_1]");
        assert_eq!(tok2, "[REDACTED_CC_1]");

        // Case insensitive check
        let tok3 = state.get_or_create_token("TEST@EXAMPLE.COM", PiiType::Email);
        let tok4 = state.get_or_create_token("test@example.com", PiiType::Email);
        assert_eq!(tok3, "[REDACTED_EMAIL_1]");
        assert_eq!(tok4, "[REDACTED_EMAIL_1]");
    }

    #[test]
    fn test_resolve_overlaps_extended() {
        let mut matches = vec![
            PiiMatch {
                start: 10,
                end: 20,
                pii_type: PiiType::Ssn,
                value: "123-45-6789".to_string(),
            },
            PiiMatch {
                start: 15,
                end: 25,
                pii_type: PiiType::Phone,
                value: "6789012".to_string(),
            },
        ];
        resolve_overlaps(&mut matches);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 10);
        assert_eq!(matches[0].end, 25);
    }

    #[test]
    fn test_process_payload_extended_scope_and_sequential() {
        let mut payload = serde_json::json!({
            "messages": [
                {
                    "role": "user",
                    "name": "John Doe 123-45-6789",
                    "content": "My phone is 123-456-7890",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "do_work",
                                "arguments": "{\"secret_cc\":\"1234-5678-9012-3456\"}"
                            }
                        }
                    ]
                },
                {
                    "role": "assistant",
                    "content": "Same phone: 123-456-7890 and name John Doe 123-45-6789"
                }
            ]
        });

        process_completions_payload(&mut payload).unwrap();

        let msg1 = &payload["messages"][0];
        assert_eq!(msg1["name"], "John Doe [REDACTED_SSN_1]");
        assert_eq!(msg1["content"], "My phone is [REDACTED_PHONE_1]");
        assert!(msg1["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap()
            .contains("[REDACTED_CC_1]"));

        let msg2 = &payload["messages"][1];
        // Sequential request-level cache validation: phone and name get same tokens!
        assert_eq!(
            msg2["content"],
            "Same phone: [REDACTED_PHONE_1] and name John Doe [REDACTED_SSN_1]"
        );
    }

    #[tokio::test]
    async fn test_process_anthropic_payload_with_orchestrator() {
        use std::sync::{Arc, Mutex};
        init_regexes();
        let token_map = Arc::new(Mutex::new(crate::token_map::TokenMap::new()));
        let orchestrator = crate::orchestrator::DetectionOrchestrator::new(None);

        let mut payload = serde_json::json!({
            "model": "claude-3-7-sonnet-20250219",
            "system": "System instructions with secret AKIAIOSFODNN7EXAMPLE",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Please reach out to support@acme-corp.com regarding my account"
                        }
                    ]
                }
            ]
        });

        process_anthropic_payload_with_orchestrator(&mut payload, &token_map, &orchestrator)
            .await
            .unwrap();

        assert!(payload["system"]
            .as_str()
            .unwrap()
            .contains("[REDACTED_AWS_1]"));
        assert!(!payload["system"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"));

        let content_text = payload["messages"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(content_text.contains("[REDACTED_EMAIL_1]"));
        assert!(!content_text.contains("support@acme-corp.com"));

        let lock = token_map.lock().unwrap();
        assert_eq!(lock.len(), 2);
    }
}
