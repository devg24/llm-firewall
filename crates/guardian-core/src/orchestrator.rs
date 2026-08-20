use crate::detect::{Detector, EntropyDetector, NerDetector, RegexDetector, Span};
use crate::error::CoreError;
use crate::ml::SharedModel;
use std::cmp::Ordering;
use std::sync::Arc;

pub struct DetectionOrchestrator {
    regex: RegexDetector,
    entropy: EntropyDetector,
    ner: NerDetector,
}

impl DetectionOrchestrator {
    pub fn new(model: Option<Arc<SharedModel>>) -> Self {
        Self {
            regex: RegexDetector,
            entropy: EntropyDetector::default(),
            ner: NerDetector::new(model),
        }
    }

    pub async fn orchestrate(&self, text: &str) -> Result<Vec<Span>, CoreError> {
        let mut spans = Vec::new();

        // Tier 1: Regex
        let tier1_spans = self.regex.detect(text);
        spans.extend(tier1_spans.into_iter().filter(|s| s.confidence >= 1.0));

        // Tier 2: Entropy
        let tier2_spans = self.entropy.detect(text);
        spans.extend(tier2_spans.into_iter().filter(|s| s.confidence >= 0.5));

        // Tier 3: NER
        let tier3_spans = self.ner.detect_async(text).await?;
        spans.extend(tier3_spans.into_iter().filter(|s| s.confidence >= 0.6));

        // Tier 4: Contextual (Deferred)
        // TODO: Tier 4 (ONNX contextual classifier) - feature-flagged, see Architecture Spine

        // Overlap resolution:
        // Priority 1: Higher confidence first
        // Priority 2: Deterministic Tier 1 PII types over statistical HighEntropy
        // Priority 3: Longer span
        spans.sort_by(|a, b| {
            let a_is_tier1 = a.label != crate::redact::PiiType::HighEntropy;
            let b_is_tier1 = b.label != crate::redact::PiiType::HighEntropy;

            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
                .then_with(|| b_is_tier1.cmp(&a_is_tier1))
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
                .then_with(|| a.start.cmp(&b.start))
        });

        let mut resolved: Vec<Span> = Vec::new();
        for span in spans {
            let overlaps = resolved
                .iter()
                .any(|r| span.start < r.end && span.end > r.start);
            if !overlaps {
                resolved.push(span);
            }
        }
        resolved.sort_by_key(|s| s.start);

        Ok(resolved)
    }
}
