//! CLI statistics handler for LLM Firewall telemetry data.
//!
//! Provides aggregated KPI metrics, detection breakdown, and estimated risk savings.

use guardian_core::telemetry::{
    compute_stats, default_audit_log_path, format_rfc3339, load_telemetry_events, parse_duration,
    AuditStats,
};
use std::path::PathBuf;

/// Command-line arguments for the `stats` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsCliArgs {
    /// Optional time window filter (e.g. "24h", "7d", "30d", "all").
    pub since: Option<String>,
    /// Optional path to audit JSONL file.
    pub file: Option<PathBuf>,
    /// Whether to output machine-readable JSON instead of tabular text.
    pub json: bool,
}

/// Parses CLI arguments for the `stats` subcommand.
///
/// # Errors
/// Returns an error message string if arguments are invalid.
pub fn parse_stats_args(args: &[String]) -> Result<StatsCliArgs, String> {
    let mut since = None;
    let mut file = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--since" | "-s" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "--since requires a duration value (e.g. '24h', '7d', 'all')".to_string(),
                    );
                }
                since = Some(args[i].clone());
            }
            "--file" | "-f" | "--log" => {
                i += 1;
                if i >= args.len() {
                    return Err("--file requires a file path argument".to_string());
                }
                file = Some(PathBuf::from(&args[i]));
            }
            "--json" => {
                json = true;
            }
            "--help" | "-h" => {
                return Err(
                    "Usage: guardian stats [--since <DURATION>] [--file <PATH>] [--json]"
                        .to_string(),
                );
            }
            other => {
                return Err(format!(
                    "Unknown argument '{}'. Run with --help for usage.",
                    other
                ));
            }
        }
        i += 1;
    }

    Ok(StatsCliArgs { since, file, json })
}

/// Executes the `stats` subcommand.
///
/// # Errors
/// Returns an error if reading logs or formatting fails.
pub fn run_stats(args: StatsCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = args.file.unwrap_or_else(default_audit_log_path);
    let duration = match args.since {
        Some(ref s) => parse_duration(s)?,
        None => None,
    };

    let events = load_telemetry_events(&log_path, duration)?;
    let stats = compute_stats(&events, None);

    if args.json {
        let json_str = serde_json::to_string_pretty(&stats)?;
        println!("{}", json_str);
    } else {
        print_stats_table(&stats, &log_path, events.len());
    }

    Ok(())
}

/// Formats and prints the statistics summary table to stdout.
pub fn print_stats_table(stats: &AuditStats, log_path: &std::path::Path, total_events: usize) {
    let period_str = match (stats.time_period_start, stats.time_period_end) {
        (Some(start), Some(end)) => {
            format!("{} to {}", format_rfc3339(start), format_rfc3339(end))
        }
        _ => "All Available Events".to_string(),
    };

    println!("================================================================================");
    println!("                LLM Firewall — Security & Compliance Statistics                ");
    println!("================================================================================");
    println!("Audit Log Source : {}", log_path.display());
    println!(
        "Time Period      : {} ({} events)",
        period_str, total_events
    );
    println!("--------------------------------------------------------------------------------");
    println!("EXECUTIVE METRICS SUMMARY");
    println!("--------------------------------------------------------------------------------");
    println!(
        "  • Requests Monitored            : {}",
        stats.total_requests
    );
    println!(
        "  • Sensitive Secrets Redacted    : {}",
        stats.total_secrets_redacted
    );
    println!(
        "  • Dangerous Sinks Blocked       : {}",
        stats.dangerous_sinks_blocked
    );
    println!(
        "  • Sandbox Traversal Blocked     : {}",
        stats.sandbox_violations_blocked
    );
    println!(
        "  • Clean Passthrough Requests    : {}",
        stats.passthrough_requests
    );
    println!(
        "  • Estimated Risk Avoided        : ${:.2}",
        stats.total_estimated_cost_saved
    );
    println!("--------------------------------------------------------------------------------");
    println!("DETECTION & INTERCEPTION BREAKDOWN");
    println!("--------------------------------------------------------------------------------");

    if stats.category_breakdown.is_empty() {
        println!("  No sensitive items or security incidents recorded for this period.");
    } else {
        println!(
            "  {:<26} {:<12} {:<24} {:<12}",
            "CATEGORY", "DETECTIONS", "DETECTION TIER", "RISK SAVED"
        );
        println!("  {:-<26} {:-<12} {:-<24} {:-<12}", "", "", "", "");
        for cat in &stats.category_breakdown {
            println!(
                "  {:<26} {:<12} {:<24} ${:<11.2}",
                cat.category, cat.count, cat.tier, cat.estimated_risk_saved
            );
        }
    }
    println!("================================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::telemetry::{
        append_telemetry_event, DetectionTier, TelemetryEvent, TelemetryEventType,
    };
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_stats_args() {
        let args = vec![
            "--since".to_string(),
            "24h".to_string(),
            "--json".to_string(),
        ];
        let parsed = parse_stats_args(&args).unwrap();
        assert_eq!(parsed.since, Some("24h".to_string()));
        assert!(parsed.json);
        assert_eq!(parsed.file, None);

        let args2 = vec![
            "-f".to_string(),
            "/tmp/test.jsonl".to_string(),
            "-s".to_string(),
            "7d".to_string(),
        ];
        let parsed2 = parse_stats_args(&args2).unwrap();
        assert_eq!(parsed2.since, Some("7d".to_string()));
        assert_eq!(parsed2.file, Some(PathBuf::from("/tmp/test.jsonl")));
        assert!(!parsed2.json);
    }

    #[test]
    fn test_run_stats_json_output() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let event = TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-cli-1".to_string(),
            event_type: TelemetryEventType::SinkBlocked,
            tier_triggered: Some(DetectionTier::DangerousSink),
            secret_types: vec![],
            redacted_count: 0,
            sandbox_violation: None,
            model: None,
            latency_ms: 1,
            estimated_cost_saved_usd: 2500.0,
        };
        append_telemetry_event(&path, &event).unwrap();

        let args = StatsCliArgs {
            since: None,
            file: Some(path),
            json: true,
        };

        assert!(run_stats(args).is_ok());
    }
}
