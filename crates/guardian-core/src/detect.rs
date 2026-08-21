use crate::error::CoreError;
use crate::ml::{run_inference, SharedModel};
use crate::redact::{collect_regex_matches, PiiType};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f32,
    pub label: PiiType,
}

pub trait Detector: Send + Sync {
    fn detect(&self, _text: &str) -> Vec<Span> {
        vec![]
    }

    #[allow(async_fn_in_trait)]
    async fn detect_async(&self, _text: &str) -> Result<Vec<Span>, CoreError> {
        Ok(vec![])
    }
}

pub struct RegexDetector;

impl Detector for RegexDetector {
    fn detect(&self, text: &str) -> Vec<Span> {
        let matches = collect_regex_matches(text);
        matches
            .into_iter()
            .map(|m| Span {
                start: m.start,
                end: m.end,
                text: m.value,
                confidence: 1.0,
                label: m.pii_type,
            })
            .collect()
    }
}

pub struct EntropyDetector {
    window_size: usize,
    threshold: f32,
    min_span_len: usize,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            window_size: 20,
            threshold: 4.1,
            min_span_len: 20,
        }
    }
}

impl EntropyDetector {
    /// Construct with a custom threshold (raw Shannon bits, 0.0–8.0 scale).
    /// Used by `DetectionOrchestrator::with_domain` to apply domain-derived thresholds.
    pub fn with_threshold(threshold: f32) -> Self {
        Self {
            window_size: 20,
            threshold,
            min_span_len: 20,
        }
    }
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

impl Detector for EntropyDetector {
    fn detect(&self, text: &str) -> Vec<Span> {
        let chars: Vec<char> = text.chars().collect();
        let mut spans = Vec::new();
        let mut i = 0;

        while i + self.window_size <= chars.len() {
            let window: String = chars[i..i + self.window_size].iter().collect();
            let space_count = window.chars().filter(|c| c.is_whitespace()).count();

            // High-entropy secrets (API keys, passwords, base64) are contiguous tokens with no spaces
            if space_count == 0 {
                let entropy = shannon_entropy(&window);

                if entropy >= self.threshold {
                    let mut end = i + self.window_size;
                    while end < chars.len() {
                        let next_char = chars[end];
                        if !next_char.is_whitespace() && (next_char.is_alphanumeric() || "+/=_-!@#$%^&*".contains(next_char)) {
                            end += 1;
                        } else {
                            break;
                        }
                    }

                    let span_text: String = chars[i..end].iter().collect();
                    if span_text.len() >= self.min_span_len {
                        let confidence = ((entropy - self.threshold) / 0.2 + 0.6).clamp(0.5, 1.0);

                        let start_idx = text.chars().take(i).map(|c| c.len_utf8()).sum();
                        let end_idx = text.chars().take(end).map(|c| c.len_utf8()).sum();

                        spans.push(Span {
                            start: start_idx,
                            end: end_idx,
                            text: span_text,
                            confidence,
                            label: PiiType::HighEntropy,
                        });
                    }
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        spans
    }
}

pub struct NerDetector {
    pub model: Option<Arc<SharedModel>>,
}

impl NerDetector {
    pub fn new(model: Option<Arc<SharedModel>>) -> Self {
        Self { model }
    }
}

impl Detector for NerDetector {
    #[allow(async_fn_in_trait)]
    async fn detect_async(&self, text: &str) -> Result<Vec<Span>, CoreError> {
        let Some(model) = &self.model else {
            return Ok(vec![]);
        };

        let classifications = run_inference(model.clone(), text.to_string()).await?;
        let spans = classifications
            .into_iter()
            .filter_map(|c| {
                let label = match c.entity_group.as_str() {
                    "B-PERSON" | "I-PERSON" | "B-PER" | "I-PER" | "PER" => PiiType::Person,
                    "B-ORG" | "I-ORG" | "ORG" => PiiType::Bearer,
                    _ => return None,
                };
                Some(Span {
                    start: c.start,
                    end: c.end,
                    text: c.word,
                    confidence: c.score,
                    label,
                })
            })
            .collect();
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_detector() {
        let detector = RegexDetector;
        let spans = detector.detect("my email is test@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text, "test@example.com");
        assert_eq!(spans[0].confidence, 1.0);
        assert_eq!(spans[0].label, PiiType::Email);
    }

    #[test]
    fn test_entropy_detector() {
        let detector = EntropyDetector::default();
        let safe_text = "This is a completely normal sentence with low entropy.";
        assert!(detector.detect(safe_text).is_empty());

        let high_entropy = "The password is: xQ9!pL4$mN2@kR7#vB5^AWS_KEY_1234567890ABCDEF";
        let spans = detector.detect(high_entropy);
        assert!(!spans.is_empty());
        assert_eq!(spans[0].label, PiiType::HighEntropy);
        assert!(spans[0].confidence > 0.0);
    }

    #[tokio::test]
    async fn test_ner_detector_empty() {
        let detector = NerDetector::new(None);
        let spans = detector.detect_async("test").await.unwrap();
        assert!(spans.is_empty());
    }
}
