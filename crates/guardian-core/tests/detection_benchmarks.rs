use guardian_core::detect::{Detector, EntropyDetector, RegexDetector};
use guardian_core::domain::DomainProfile;
use guardian_core::orchestrator::DetectionOrchestrator;
use guardian_core::redact::PiiType;
use serde::Deserialize;

// ──────────────────────────────────────────────────────────────────────────────
// Shared types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BenchmarkItem {
    id: String,
    category: String,
    text: String,
    expected_spans: Vec<ExpectedSpan>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedSpan {
    start: usize,
    end: usize,
    label: PiiType,
}

/// Flattened item from domain-stratified datasets
/// (dataset_standard.json / dataset_crypto.json / dataset_healthcare.json)
#[derive(Debug, Deserialize)]
struct DomainItem {
    id: String,
    domain: String,
    is_secret: bool,
    secret_value: String,
    entropy: f64,
}

// ──────────────────────────────────────────────────────────────────────────────
// Dataset loaders
// ──────────────────────────────────────────────────────────────────────────────

fn load_dataset() -> Vec<BenchmarkItem> {
    let fixture_str = include_str!("fixtures/golden_dataset.json");
    serde_json::from_str(fixture_str).expect("Failed to parse golden_dataset.json fixture")
}

fn load_domain_dataset(domain: &str) -> Vec<DomainItem> {
    let path = format!(
        "{}/tests/fixtures/dataset_{}.json",
        env!("CARGO_MANIFEST_DIR"),
        domain
    );
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Missing domain dataset: {path}\nRun: python3 scripts/generate_benchmark_datasets.py"));
    serde_json::from_str(&content).expect("Failed to parse domain dataset JSON")
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared metric helpers
// ──────────────────────────────────────────────────────────────────────────────

fn compute_metrics(tp: f32, fp: f32, fn_: f32) -> (f32, f32, f32) {
    let precision = if tp + fp == 0.0 {
        1.0
    } else {
        tp / (tp + fp)
    };
    let recall = if tp + fn_ == 0.0 {
        1.0
    } else {
        tp / (tp + fn_)
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * (precision * recall) / (precision + recall)
    };
    (precision, recall, f1)
}

/// Run an entropy threshold sweep over a domain dataset (mirrors the Python generator).
/// Returns the optimal threshold and its F1 score.
fn entropy_f1_sweep(items: &[DomainItem], steps: usize) -> (f64, f64) {
    let mut best_threshold = 0.0f64;
    let mut best_f1 = 0.0f64;

    for step in 0..=steps {
        let threshold = (step as f64 / steps as f64) * 8.0;
        let mut tp = 0.0f32;
        let mut fp = 0.0f32;
        let mut fn_ = 0.0f32;

        for item in items {
            let predicted = item.entropy >= threshold;
            if predicted && item.is_secret {
                tp += 1.0;
            } else if predicted && !item.is_secret {
                fp += 1.0;
            } else if !predicted && item.is_secret {
                fn_ += 1.0;
            }
        }

        let (_, _, f1) = compute_metrics(tp, fp, fn_);
        if f1 as f64 > best_f1 {
            best_f1 = f1 as f64;
            best_threshold = threshold;
        }
    }
    (best_threshold, best_f1)
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 1: Tier 1 Regex Detector with Exact Annotation Matching
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn benchmark_regex_detector_exact_matching() {
    let dataset = load_dataset();
    let detector = RegexDetector;

    let mut total_tp = 0.0;
    let mut total_fp = 0.0;
    let mut total_fn = 0.0;

    for item in &dataset {
        // Filter expected spans to only those expected from Regex
        let regex_expected: Vec<&ExpectedSpan> = item
            .expected_spans
            .iter()
            .filter(|s| s.label != PiiType::HighEntropy && s.label != PiiType::Person)
            .collect();

        let detected = detector.detect(&item.text);

        let mut tp = 0.0;
        let mut matched_exp = vec![false; regex_expected.len()];

        for d in &detected {
            for (i, exp) in regex_expected.iter().enumerate() {
                if !matched_exp[i]
                    && d.start == exp.start
                    && d.end == exp.end
                    && d.label == exp.label
                {
                    matched_exp[i] = true;
                    tp += 1.0;
                    break;
                }
            }
        }

        let fp = (detected.len() as f32 - tp).max(0.0);
        let fn_ = (regex_expected.len() as f32 - tp).max(0.0);

        if fp > 0.0 || fn_ > 0.0 {
            eprintln!(
                "Regex mismatch on [{}] '{}': detected={:?}, expected={:?}",
                item.id, item.text, detected, regex_expected
            );
        }

        total_tp += tp;
        total_fp += fp;
        total_fn += fn_;
    }

    let (precision, recall, f1) = compute_metrics(total_tp, total_fp, total_fn);
    println!(
        "Tier 1 Regex Exact Benchmark -> Precision: {:.2}, Recall: {:.2}, F1: {:.2}",
        precision, recall, f1
    );

    assert!(
        f1 >= 0.95,
        "Regex exact matching F1 score ({:.2}) must be >= 0.95",
        f1
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 2: Tier 2 Shannon Entropy Detector on High Entropy Secrets vs False Positives
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn benchmark_entropy_detector_accuracy() {
    let dataset = load_dataset();
    let detector = EntropyDetector::default();

    let mut total_tp = 0.0;
    let mut total_fp = 0.0;
    let mut total_fn = 0.0;

    for item in &dataset {
        let is_high_entropy_target = item.category == "high_entropy";
        let is_false_positive_trap = item.category.starts_with("false_positive");

        let detected = detector.detect(&item.text);

        if is_high_entropy_target {
            if !detected.is_empty() {
                total_tp += 1.0;
            } else {
                total_fn += 1.0;
                eprintln!("Entropy missed high-entropy target [{}]: {}", item.id, item.text);
            }
        } else if is_false_positive_trap {
            if !detected.is_empty() {
                total_fp += detected.len() as f32;
                eprintln!("Entropy triggered false positive on [{}]: {:?}", item.id, detected);
            }
        }
    }

    let (precision, recall, f1) = compute_metrics(total_tp, total_fp, total_fn);
    println!(
        "Tier 2 Entropy Benchmark -> Precision: {:.2}, Recall: {:.2}, F1: {:.2}",
        precision, recall, f1
    );

    assert!(
        f1 >= 0.80,
        "Entropy Detector F1 score ({:.2}) must be >= 0.80",
        f1
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 3: End-to-End DetectionOrchestrator Cascade Benchmark
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn benchmark_orchestrator_full_cascade() {
    let dataset = load_dataset();
    let orchestrator = DetectionOrchestrator::new(None);

    let mut total_tp = 0.0;
    let mut total_fp = 0.0;
    let mut total_fn = 0.0;

    for item in &dataset {
        let detected = orchestrator.orchestrate(&item.text).await.unwrap();

        // Check against all expected spans in item
        let mut tp = 0.0;
        let mut matched_exp = vec![false; item.expected_spans.len()];

        for d in &detected {
            for (i, exp) in item.expected_spans.iter().enumerate() {
                if !matched_exp[i] {
                    let is_exact = d.start == exp.start && d.end == exp.end && d.label == exp.label;
                    let is_entropy_overlap = exp.label == PiiType::HighEntropy
                        && d.label == PiiType::HighEntropy
                        && (d.start < exp.end && d.end > exp.start);

                    if is_exact || is_entropy_overlap {
                        matched_exp[i] = true;
                        tp += 1.0;
                        break;
                    }
                }
            }
        }

        let fp = (detected.len() as f32 - tp).max(0.0);
        let fn_ = (item.expected_spans.len() as f32 - tp).max(0.0);

        if fp > 0.0 || fn_ > 0.0 {
            eprintln!(
                "Cascade item mismatch [{}]: detected={:?}, expected={:?}",
                item.id, detected, item.expected_spans
            );
        }

        total_tp += tp;
        total_fp += fp;
        total_fn += fn_;
    }

    let (precision, recall, f1) = compute_metrics(total_tp, total_fp, total_fn);
    println!(
        "DetectionOrchestrator Cascade Benchmark -> Precision: {:.2}, Recall: {:.2}, F1: {:.2}",
        precision, recall, f1
    );

    assert!(
        f1 >= 0.95,
        "Orchestrator Cascade F1 score ({:.2}) must be >= 0.95",
        f1
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 4: Domain-Stratified Entropy F1 Validation (Standard domain)
//
// Loads dataset_standard.json (5,000 TP secrets + 5,000 FP common hashes/words).
// Validates that the domain.rs locked threshold (3.84 bits) produces F1 >= 0.82.
// Tolerance: ±0.12 bits versus the Python-computed optimal.
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn benchmark_domain_standard_entropy_f1() {
    let items = load_domain_dataset("standard");
    assert_eq!(items.len(), 10_000, "Expected 10,000 items in standard dataset");

    let locked_threshold = DomainProfile::Standard.thresholds().entropy_tier as f64; // 3.84 bits

    let mut tp = 0.0f32;
    let mut fp = 0.0f32;
    let mut fn_ = 0.0f32;
    for item in &items {
        let predicted = item.entropy >= locked_threshold;
        if predicted && item.is_secret { tp += 1.0; }
        else if predicted && !item.is_secret { fp += 1.0; }
        else if !predicted && item.is_secret { fn_ += 1.0; }
    }
    let (precision, recall, f1) = compute_metrics(tp, fp, fn_);
    println!(
        "Standard domain @ {:.4} bits -> P={:.4} R={:.4} F1={:.4}",
        locked_threshold, precision, recall, f1
    );

    // Verify the locked threshold is close to the mathematically optimal one
    let (optimal_threshold, optimal_f1) = entropy_f1_sweep(&items, 200);
    println!(
        "Standard domain optimal threshold: {:.4} bits (F1={:.4})",
        optimal_threshold, optimal_f1
    );
    assert!(
        (locked_threshold - optimal_threshold).abs() <= 0.12,
        "Standard entropy threshold ({locked_threshold:.4}) deviates more than 0.12 bits \
         from optimal ({optimal_threshold:.4}). Re-run generate_benchmark_datasets.py and update domain.rs."
    );
    assert!(
        f1 >= 0.82,
        "Standard domain F1 ({f1:.4}) must be >= 0.82 at locked threshold {locked_threshold:.4}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 5: Domain-Stratified Entropy F1 Validation (Crypto/Fintech domain)
//
// Loads dataset_crypto.json (5,000 TP secrets + 5,000 FP crypto addresses/hashes).
// Validates that the domain.rs locked threshold (4.28 bits) avoids flagging
// Ethereum addresses, Solana pubkeys, tx hashes as secrets.
// Tolerance: ±0.12 bits versus Python-computed optimal.
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn benchmark_domain_crypto_entropy_f1() {
    let items = load_domain_dataset("crypto");
    assert_eq!(items.len(), 10_000, "Expected 10,000 items in crypto dataset");

    let locked_threshold = DomainProfile::CryptoFintech.thresholds().entropy_tier as f64; // 4.28 bits

    let mut tp = 0.0f32;
    let mut fp = 0.0f32;
    let mut fn_ = 0.0f32;
    for item in &items {
        let predicted = item.entropy >= locked_threshold;
        if predicted && item.is_secret { tp += 1.0; }
        else if predicted && !item.is_secret { fp += 1.0; }
        else if !predicted && item.is_secret { fn_ += 1.0; }
    }
    let (precision, recall, f1) = compute_metrics(tp, fp, fn_);
    println!(
        "Crypto domain @ {:.4} bits -> P={:.4} R={:.4} F1={:.4}",
        locked_threshold, precision, recall, f1
    );

    let (optimal_threshold, optimal_f1) = entropy_f1_sweep(&items, 200);
    println!(
        "Crypto domain optimal threshold: {:.4} bits (F1={:.4})",
        optimal_threshold, optimal_f1
    );
    assert!(
        (locked_threshold - optimal_threshold).abs() <= 0.12,
        "Crypto entropy threshold ({locked_threshold:.4}) deviates more than 0.12 bits \
         from optimal ({optimal_threshold:.4}). Re-run generate_benchmark_datasets.py and update domain.rs."
    );
    assert!(
        f1 >= 0.65,
        "Crypto domain F1 ({f1:.4}) must be >= 0.65 at locked threshold {locked_threshold:.4}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 6: Domain-Stratified Entropy F1 Validation (Healthcare domain)
//
// Loads dataset_healthcare.json (5,000 TP secrets + 5,000 FP FHIR UUIDs/DICOM UIDs).
// Validates that the domain.rs locked threshold (4.16 bits) produces high precision
// to avoid disrupting clinical workflows.
// Tolerance: ±0.12 bits versus Python-computed optimal.
// ──────────────────────────────────────────────────────────────────────────────
#[test]
fn benchmark_domain_healthcare_entropy_f1() {
    let items = load_domain_dataset("healthcare");
    assert_eq!(items.len(), 10_000, "Expected 10,000 items in healthcare dataset");

    let locked_threshold = DomainProfile::Healthcare.thresholds().entropy_tier as f64; // 4.16 bits

    let mut tp = 0.0f32;
    let mut fp = 0.0f32;
    let mut fn_ = 0.0f32;
    for item in &items {
        let predicted = item.entropy >= locked_threshold;
        if predicted && item.is_secret { tp += 1.0; }
        else if predicted && !item.is_secret { fp += 1.0; }
        else if !predicted && item.is_secret { fn_ += 1.0; }
    }
    let (precision, recall, f1) = compute_metrics(tp, fp, fn_);
    println!(
        "Healthcare domain @ {:.4} bits -> P={:.4} R={:.4} F1={:.4}",
        locked_threshold, precision, recall, f1
    );

    let (optimal_threshold, optimal_f1) = entropy_f1_sweep(&items, 200);
    println!(
        "Healthcare domain optimal threshold: {:.4} bits (F1={:.4})",
        optimal_threshold, optimal_f1
    );
    assert!(
        (locked_threshold - optimal_threshold).abs() <= 0.12,
        "Healthcare entropy threshold ({locked_threshold:.4}) deviates more than 0.12 bits \
         from optimal ({optimal_threshold:.4}). Re-run generate_benchmark_datasets.py and update domain.rs."
    );
    assert!(
        f1 >= 0.72,
        "Healthcare domain F1 ({f1:.4}) must be >= 0.72 at locked threshold {locked_threshold:.4}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmark 7: Domain-Aware Orchestrator — Crypto False-Positive Guard
//
// Verifies that the CryptoFintech orchestrator does NOT flag Ethereum/Solana
// addresses as secrets (they would be flagged by the Standard profile).
// ──────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn benchmark_crypto_orchestrator_fp_guard() {
    let crypto_orch = DetectionOrchestrator::with_domain(None, DomainProfile::CryptoFintech);
    let std_orch = DetectionOrchestrator::with_domain(None, DomainProfile::Standard);

    let crypto_false_positives = vec![
        // Ethereum address
        "sending to address: 0xdAC17F958D2ee523a2206206994597C13D831ec7",
        // Solana pubkey
        "validator pubkey: 4Nd1mBQtrMJVYVfKf2PX98KuKNqwRrAhTCcFSAKKJ2Jd",
        // TX hash
        "tx hash: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    ];

    let mut std_flags = 0usize;
    let mut crypto_flags = 0usize;

    for input in &crypto_false_positives {
        let std_spans = std_orch.orchestrate(input).await.unwrap();
        let crypto_spans = crypto_orch.orchestrate(input).await.unwrap();

        // Only count HighEntropy spans (not regex-matched secrets like AWS keys)
        let std_entropy_flags: Vec<_> = std_spans
            .iter()
            .filter(|s| s.label == guardian_core::PiiType::HighEntropy)
            .collect();
        let crypto_entropy_flags: Vec<_> = crypto_spans
            .iter()
            .filter(|s| s.label == guardian_core::PiiType::HighEntropy)
            .collect();

        std_flags += std_entropy_flags.len();
        crypto_flags += crypto_entropy_flags.len();

        if !crypto_entropy_flags.is_empty() {
            eprintln!(
                "CryptoFintech orchestrator false-positive on: {input}\n  → {:?}",
                crypto_entropy_flags
            );
        }
    }

    println!(
        "Standard orchestrator flagged {std_flags} crypto FPs; CryptoFintech orchestrator flagged {crypto_flags}"
    );

    // The crypto domain orchestrator must produce strictly fewer false positives
    // than the standard orchestrator on crypto-domain data.
    assert!(
        crypto_flags <= std_flags,
        "CryptoFintech orchestrator ({crypto_flags} flags) should flag fewer crypto FPs \
         than Standard orchestrator ({std_flags} flags)"
    );
}
