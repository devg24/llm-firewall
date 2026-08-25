use crate::detect::{Detector, EntropyDetector, NerDetector, RegexDetector, Span};
use crate::domain::DomainProfile;
use crate::error::CoreError;
use crate::manifest::GuardianConfig;
use crate::ml::SharedModel;
use crate::redact::PiiType;
use std::cmp::Ordering;
use std::sync::Arc;

pub struct DetectionOrchestrator {
    regex: RegexDetector,
    custom_rules: Vec<(String, regex::Regex, PiiType)>,
    entropy: EntropyDetector,
    ner: NerDetector,
    allowlist_terms: Vec<String>,
    allowlist_patterns: Vec<regex::Regex>,
    ner_threshold: f32,
}

impl DetectionOrchestrator {
    /// Create an orchestrator with an optional ML model and optional domain profile.
    ///
    /// When `domain` is `None`, the `Standard` profile thresholds are applied.
    pub fn new(model: Option<Arc<SharedModel>>) -> Self {
        Self::with_domain(model, DomainProfile::Standard)
    }

    /// Create an orchestrator with a specific domain profile.
    pub fn with_domain(model: Option<Arc<SharedModel>>, domain: DomainProfile) -> Self {
        Self::with_config(model, domain, None)
    }

    /// Create an orchestrator with a domain profile and optional `.guardian.toml` config.
    pub fn with_config(
        model: Option<Arc<SharedModel>>,
        domain: DomainProfile,
        config: Option<&GuardianConfig>,
    ) -> Self {
        let thresholds = domain.thresholds();
        let mut entropy_threshold = thresholds.entropy_tier;
        let mut ner_threshold = thresholds.ner_tier;

        let mut custom_rules = Vec::new();
        let mut allowlist_terms = Vec::new();
        let mut allowlist_patterns = Vec::new();

        if let Some(cfg) = config {
            // Apply threshold overrides
            if let Some(ref overrides) = cfg.thresholds {
                if let Some(ent) = overrides.entropy {
                    entropy_threshold = ent;
                }
                if let Some(n) = overrides.ner {
                    ner_threshold = n;
                }
            }

            // Compile custom rules
            let mut all_rules = Vec::new();
            if let Some(ref regex_cfg) = cfg.regex {
                all_rules.extend(regex_cfg.rules.clone());
            }
            if let Some(ref direct_rules) = cfg.rules {
                all_rules.extend(direct_rules.clone());
            }

            let compile_regex = |pattern: &str| -> Result<regex::Regex, regex::Error> {
                regex::RegexBuilder::new(pattern)
                    .size_limit(crate::config::MAX_REGEX_AST_SIZE)
                    .dfa_size_limit(crate::config::MAX_REGEX_DFA_SIZE)
                    .build()
            };

            for rule in all_rules {
                if let Ok(re) = compile_regex(&rule.pattern) {
                    let pii_type = match rule
                        .pii_type
                        .as_deref()
                        .map(|s| s.to_uppercase())
                        .as_deref()
                    {
                        Some("SSN") => PiiType::Ssn,
                        Some("CC") => PiiType::Cc,
                        Some("EMAIL") => PiiType::Email,
                        Some("PHONE") => PiiType::Phone,
                        Some("IP") => PiiType::Ip,
                        Some("AWS") => PiiType::Aws,
                        Some("GCP") => PiiType::Gcp,
                        Some("GITHUB") => PiiType::Github,
                        Some("BEARER") => PiiType::Bearer,
                        Some("HIGH_ENTROPY") => PiiType::HighEntropy,
                        Some("PERSON") => PiiType::Person,
                        _ => PiiType::Custom,
                    };
                    custom_rules.push((rule.id, re, pii_type));
                }
            }

            // Compile allowlist
            if let Some(ref allowlist) = cfg.allowlist {
                if let Some(ref terms) = allowlist.terms {
                    allowlist_terms.extend(terms.clone());
                }
                if let Some(ref patterns) = allowlist.patterns {
                    for pat in patterns {
                        if let Ok(re) = compile_regex(pat) {
                            allowlist_patterns.push(re);
                        }
                    }
                }
            }
        }

        Self {
            regex: RegexDetector,
            custom_rules,
            entropy: EntropyDetector::with_threshold(entropy_threshold),
            ner: NerDetector::new(model),
            allowlist_terms,
            allowlist_patterns,
            ner_threshold,
        }
    }

    pub async fn orchestrate(&self, text: &str) -> Result<Vec<Span>, CoreError> {
        let mut spans = Vec::new();

        // Tier 1: Regex — deterministic, exact-match, always confidence 1.0
        let tier1_spans = self.regex.detect(text);
        spans.extend(tier1_spans.into_iter().filter(|s| s.confidence >= 1.0));

        // Tier 1 (Custom): Custom regex rules from .guardian.toml
        for (_id, re, pii_type) in &self.custom_rules {
            for m in re.find_iter(text) {
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    text: m.as_str().to_string(),
                    confidence: 1.0,
                    label: *pii_type,
                });
            }
        }

        // Tier 2: Entropy — threshold set by domain profile / config override
        let tier2_spans = self.entropy.detect(text);
        spans.extend(tier2_spans.into_iter().filter(|s| s.confidence >= 0.5));

        // Tier 3: NER — threshold set by domain profile / config override
        let tier3_spans = self.ner.detect_async(text).await?;
        spans.extend(
            tier3_spans
                .into_iter()
                .filter(|s| s.confidence >= self.ner_threshold),
        );

        // Tier 4: Contextual (Deferred)
        // TODO: Tier 4 (ONNX contextual classifier) - feature-flagged, see Architecture Spine

        // Filter out any spans matching the allowlist
        if !self.allowlist_terms.is_empty() || !self.allowlist_patterns.is_empty() {
            spans.retain(|span| {
                // Check if exact span text matches any allowlist term (case-insensitive)
                let term_match = self
                    .allowlist_terms
                    .iter()
                    .any(|term| span.text == *term || span.text.eq_ignore_ascii_case(term));
                if term_match {
                    return false;
                }

                // Check if span text matches any allowlist regex pattern
                let pattern_match = self.allowlist_patterns.iter().any(|re| {
                    re.is_match(&span.text)
                        || re
                            .find_iter(text)
                            .any(|m| m.start() <= span.start && m.end() >= span.end)
                });
                if pattern_match {
                    return false;
                }

                true
            });
        }

        // Overlap resolution:
        // Priority 1: Higher confidence first
        // Priority 2: Deterministic Tier 1 PII types over statistical HighEntropy
        // Priority 3: Longer span
        spans.sort_by(|a, b| {
            let a_is_tier1 = a.label != PiiType::HighEntropy;
            let b_is_tier1 = b.label != PiiType::HighEntropy;

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
