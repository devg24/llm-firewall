pub fn process_completions_payload(payload: &mut serde_json::Value) -> Result<(), String> {
    let messages = payload
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| "Missing or invalid 'messages' array".to_string())?;

    for message in messages {
        if let Some(content) = message.get_mut("content") {
            mutate_content_field(content);
        }
    }
    Ok(())
}

fn mutate_content_field(content: &mut serde_json::Value) {
    match content {
        serde_json::Value::String(s) => {
            *s = "[REDACTED_DUMMY]".to_string();
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                mutate_content_field(item);
            }
        }
        serde_json::Value::Object(obj) => {
            if let Some(serde_json::Value::String(text_val)) = obj.get_mut("text") {
                *text_val = "[REDACTED_DUMMY]".to_string();
            }
            for (key, val) in obj.iter_mut() {
                if key != "image_url" && key != "type" && key != "role" && key != "text" {
                    mutate_content_field(val);
                }
            }
        }
        _ => {}
    }
}

use regex::Regex;
use std::sync::OnceLock;

static SSN_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IP_REGEX: OnceLock<Regex> = OnceLock::new();

const SSN_PATTERN: &str = r"\b\d{3}-\d{2}-\d{4}\b";
const CC_PATTERN: &str = r"\b(?:\d[ -]*?){13,16}\b";
const EMAIL_PATTERN: &str = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b";
const PHONE_PATTERN: &str = r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b";
const IP_PATTERN: &str = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";

pub fn init_regexes() {
    let _ = SSN_REGEX.get_or_init(|| Regex::new(SSN_PATTERN).unwrap());
    let _ = CC_REGEX.get_or_init(|| Regex::new(CC_PATTERN).unwrap());
    let _ = EMAIL_REGEX.get_or_init(|| Regex::new(EMAIL_PATTERN).unwrap());
    let _ = PHONE_REGEX.get_or_init(|| Regex::new(PHONE_PATTERN).unwrap());
    let _ = IP_REGEX.get_or_init(|| Regex::new(IP_PATTERN).unwrap());
}

#[allow(dead_code)]
pub fn ssn_regex() -> &'static Regex {
    SSN_REGEX.get_or_init(|| Regex::new(SSN_PATTERN).unwrap())
}

#[allow(dead_code)]
pub fn cc_regex() -> &'static Regex {
    CC_REGEX.get_or_init(|| Regex::new(CC_PATTERN).unwrap())
}

#[allow(dead_code)]
pub fn email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| Regex::new(EMAIL_PATTERN).unwrap())
}

#[allow(dead_code)]
pub fn phone_regex() -> &'static Regex {
    PHONE_REGEX.get_or_init(|| Regex::new(PHONE_PATTERN).unwrap())
}

#[allow(dead_code)]
pub fn ip_regex() -> &'static Regex {
    IP_REGEX.get_or_init(|| Regex::new(IP_PATTERN).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_regex() {
        let re = ssn_regex();
        // Valid SSNs
        assert!(re.is_match("000-12-3456"), "Should match valid SSN 000-12-3456");
        assert!(re.is_match("123-45-6789"), "Should match valid SSN 123-45-6789");
        // Invalid SSNs
        assert!(!re.is_match("123-45-678"), "Should reject 9-digit without correct grouping");
        assert!(!re.is_match("12-345-6789"), "Should reject incorrect grouping");
        assert!(!re.is_match("abc-de-fghj"), "Should reject non-digits");
    }

    #[test]
    fn test_cc_regex() {
        let re = cc_regex();
        // Valid CCs
        assert!(re.is_match("1234-5678-9012-3456"), "Should match Visa/MC format");
        assert!(re.is_match("1234567890123"), "Should match 13-digit card");
        assert!(re.is_match("1234 5678 9012 3456"), "Should match with spaces");
        // Invalid CCs
        assert!(!re.is_match("123456789012"), "Should reject fewer than 13 digits");
        assert!(!re.is_match("abc-def-ghi-jkl"), "Should reject non-digits");
    }

    #[test]
    fn test_email_regex() {
        let re = email_regex();
        // Valid Emails
        assert!(re.is_match("test@example.com"), "Should match simple email");
        assert!(re.is_match("user.name+tag@sub.domain.org"), "Should match complex email");
        // Invalid Emails
        assert!(!re.is_match("test@"), "Should reject missing domain");
        assert!(!re.is_match("@example.com"), "Should reject missing local part");
        assert!(!re.is_match("test@example"), "Should reject missing TLD");
    }

    #[test]
    fn test_phone_regex() {
        let re = phone_regex();
        // Valid Phones
        assert!(re.is_match("123-456-7890"), "Should match format 123-456-7890");
        assert!(re.is_match("+1 123 456 7890"), "Should match with country code");
        assert!(re.is_match("(123) 456-7890"), "Should match with parentheses");
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
        assert!(re.is_match("255.255.255.255"), "Should match maximum IPv4 address");
        // Invalid IPs
        assert!(!re.is_match("999.999.999.999"), "Should reject out-of-range octets");
        assert!(!re.is_match("256.1.2.3"), "Should reject out-of-range first octet");
    }
}

