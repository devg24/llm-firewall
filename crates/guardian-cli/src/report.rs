//! CLI compliance report generator handler for LLM Firewall.
//!
//! Produces compliance audit documentation in Markdown or JSON format.

use guardian_core::report::{generate_json_report, generate_markdown_report, ReportFormat};
use guardian_core::telemetry::{
    compute_stats, default_audit_log_path, load_telemetry_events, parse_duration,
};
use std::path::PathBuf;

/// Command-line arguments for the `report` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportCliArgs {
    /// Optional output file destination (defaults to stdout).
    pub output: Option<PathBuf>,
    /// Report output format (defaults to Markdown).
    pub format: ReportFormat,
    /// Optional time window filter (e.g. "24h", "7d", "30d", "all").
    pub since: Option<String>,
    /// Whether to include the detailed chronological event log appendix.
    pub detailed: bool,
    /// Optional audit JSONL log file source.
    pub file: Option<PathBuf>,
}

/// Parses CLI arguments for the `report` subcommand.
///
/// # Errors
/// Returns an error message string if arguments are invalid.
pub fn parse_report_args(args: &[String]) -> Result<ReportCliArgs, String> {
    let mut output = None;
    let mut format = ReportFormat::Markdown;
    let mut since = None;
    let mut detailed = false;
    let mut file = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() {
                    return Err("--output requires a file path".to_string());
                }
                output = Some(PathBuf::from(&args[i]));
            }
            "--format" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "--format requires a format value ('markdown' or 'json')".to_string()
                    );
                }
                format = args[i].parse::<ReportFormat>()?;
            }
            "--since" | "-s" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "--since requires a duration value (e.g. '24h', '7d', 'all')".to_string(),
                    );
                }
                since = Some(args[i].clone());
            }
            "--detailed" => {
                detailed = true;
            }
            "--file" | "-f" | "--log" => {
                i += 1;
                if i >= args.len() {
                    return Err("--file requires a file path argument".to_string());
                }
                file = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                return Err("Usage: guardian report [--output <FILE>] [--format markdown|json] [--since <DURATION>] [--detailed] [--file <PATH>]".to_string());
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

    Ok(ReportCliArgs {
        output,
        format,
        since,
        detailed,
        file,
    })
}

/// Executes the `report` subcommand.
///
/// # Errors
/// Returns an error if reading logs, report generation, or writing to disk fails.
pub fn run_report(args: ReportCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = args.file.unwrap_or_else(default_audit_log_path);
    let duration = match args.since {
        Some(ref s) => parse_duration(s)?,
        None => None,
    };

    let events = load_telemetry_events(&log_path, duration)?;
    let stats = compute_stats(&events, None);

    let report_content = match args.format {
        ReportFormat::Markdown => {
            generate_markdown_report(&stats, &events, args.detailed, Some(&log_path))
        }
        ReportFormat::Json => {
            generate_json_report(&stats, &events, args.detailed, Some(&log_path))?
        }
    };

    if let Some(ref out_path) = args.output {
        if let Some(parent) = out_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(out_path, &report_content)?;
        println!(
            "✓ Compliance report successfully generated and saved to: {}",
            out_path.display()
        );
    } else {
        println!("{}", report_content);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::redact::PiiType;
    use guardian_core::telemetry::{
        append_telemetry_event, DetectionTier, TelemetryEvent, TelemetryEventType,
    };
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_report_args() {
        let args = vec![
            "-o".to_string(),
            "/tmp/report.md".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--detailed".to_string(),
        ];
        let parsed = parse_report_args(&args).unwrap();
        assert_eq!(parsed.output, Some(PathBuf::from("/tmp/report.md")));
        assert_eq!(parsed.format, ReportFormat::Json);
        assert!(parsed.detailed);
        assert_eq!(parsed.since, None);
    }

    #[test]
    fn test_run_report_markdown_and_json() {
        let temp_log = NamedTempFile::new().unwrap();
        let log_path = temp_log.path().to_path_buf();

        let event = TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-rep-1".to_string(),
            event_type: TelemetryEventType::PiiIntercepted,
            tier_triggered: Some(DetectionTier::Tier1Regex),
            secret_types: vec![PiiType::Aws],
            redacted_count: 1,
            sandbox_violation: None,
            model: Some("gpt-4o".to_string()),
            latency_ms: 10,
            estimated_cost_saved_usd: 1000.0,
        };
        append_telemetry_event(&log_path, &event).unwrap();

        let out_md = NamedTempFile::new().unwrap();
        let md_args = ReportCliArgs {
            output: Some(out_md.path().to_path_buf()),
            format: ReportFormat::Markdown,
            since: None,
            detailed: true,
            file: Some(log_path.clone()),
        };
        assert!(run_report(md_args).is_ok());
        let md_content = std::fs::read_to_string(out_md.path()).unwrap();
        assert!(md_content.contains("LLM Firewall — Compliance & Security Audit Report"));
        assert!(md_content.contains("req-rep-1"));

        let out_json = NamedTempFile::new().unwrap();
        let json_args = ReportCliArgs {
            output: Some(out_json.path().to_path_buf()),
            format: ReportFormat::Json,
            since: None,
            detailed: false,
            file: Some(log_path),
        };
        assert!(run_report(json_args).is_ok());
        let json_content = std::fs::read_to_string(out_json.path()).unwrap();
        assert!(json_content.contains("\"firewall_version\": \"0.1.0\""));
    }
}
