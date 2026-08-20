use guardian_core::detect::{Detector, EntropyDetector, RegexDetector};
use guardian_core::orchestrator::DetectionOrchestrator;
use guardian_core::redact::PiiType;
use serde::Deserialize;

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

fn load_dataset() -> Vec<BenchmarkItem> {
    let fixture_str = include_str!("fixtures/golden_dataset.json");
    serde_json::from_str(fixture_str).expect("Failed to parse golden_dataset.json fixture")
}

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
