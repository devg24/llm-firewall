use serde::{Deserialize, Serialize};

/// Identifies the project's security domain, which drives per-tier detection thresholds.
///
/// Auto-detected at startup by scanning dependency manifests (Cargo.toml, package.json)
/// or overridden explicitly via `.guardian.toml`. Defaults to `Standard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DomainProfile {
    /// General-purpose software projects. Balanced thresholds.
    #[default]
    Standard,
    /// Crypto / DeFi / Fintech projects. Raises the entropy tier to avoid flagging
    /// public keys, transaction hashes, and contract addresses as secrets.
    CryptoFintech,
    /// Healthcare / FHIR / HL7 projects. Tightens NER to catch patient identifiers
    /// while keeping entropy tolerant of UUIDs and DICOM UIDs.
    Healthcare,
}

/// Per-tier confidence thresholds for the detection pipeline.
///
/// # Scale note
/// `entropy_tier` is in **raw Shannon bits (0.0 – 8.0)**, matching the
/// `EntropyDetector.threshold` field. All other tiers use a normalised 0.0–1.0
/// confidence score produced by their respective classifiers.
///
/// # Quantitative basis
/// Entropy thresholds were derived by an F1-optimised sweep across 30,000
/// domain-stratified synthetic items (10,000 per domain, 200-step resolution
/// at 0.04-bit granularity). See `tests/fixtures/threshold_sweep_results.json`
/// for the full sweep data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdMatrix {
    /// Tier 1 (Regex): always 1.0 — deterministic exact-match, no threshold needed.
    pub pattern_tier: f32,
    /// Tier 2 (Shannon entropy): raw bits. Span flagged only when entropy ≥ this value.
    pub entropy_tier: f32,
    /// Tier 3 (NER): normalised confidence score from the BERT model.
    pub ner_tier: f32,
    /// Tier 4 (Contextual classifier): normalised confidence score from the ORT model.
    pub contextual_tier: f32,
}

impl DomainProfile {
    /// Returns the quantitatively derived detection thresholds for this domain.
    ///
    /// Entropy values were produced by the dataset generator + F1 sweep:
    ///   `scripts/generate_benchmark_datasets.py`
    pub fn thresholds(&self) -> ThresholdMatrix {
        match self {
            // Standard: optimal=3.84 bits  F1=0.8554  P=0.8627  R=0.8482
            DomainProfile::Standard => ThresholdMatrix {
                pattern_tier: 1.0,
                entropy_tier: 3.84,
                ner_tier: 0.70,
                contextual_tier: 0.50,
            },
            // CryptoFintech: optimal=4.28 bits  F1=0.6953  P=0.7457  R=0.6514
            // Raised threshold avoids flagging Ethereum addresses, Solana pubkeys,
            // transaction hashes, and block hashes as secrets.
            DomainProfile::CryptoFintech => ThresholdMatrix {
                pattern_tier: 1.0,
                entropy_tier: 4.28,
                ner_tier: 0.80,
                contextual_tier: 0.60,
            },
            // Healthcare: optimal=4.16 bits  F1=0.7943  P=0.9910  R=0.6628
            // High precision to avoid clinical workflow disruption. Very tight NER
            // threshold to catch patient identifiers that regex cannot match.
            DomainProfile::Healthcare => ThresholdMatrix {
                pattern_tier: 1.0,
                entropy_tier: 4.16,
                ner_tier: 0.60,
                contextual_tier: 0.40,
            },
        }
    }
}
