pub mod config;
pub mod detect;
pub mod discovery;
pub mod domain;
pub mod error;
pub mod manifest;
pub mod ml;
pub mod orchestrator;
pub mod plan;
pub mod redact;
pub mod report;
pub mod sink;
pub mod telemetry;
pub mod token_map;

pub use domain::{DomainProfile, ThresholdMatrix};
pub use error::CoreError;
pub use ml::{run_inference, SharedModel, TokenClassification};
pub use orchestrator::DetectionOrchestrator;
pub use plan::{
    canonicalize_path, generate_preflight_plan, is_path_within_sandbox, normalize_virtual_path,
    validate_sandbox_path, PreflightPlan, SandboxPolicy, SandboxViolation, SensitiveZone,
    ZoneStrategy,
};
pub use redact::{
    aws_regex, bearer_regex, cc_regex, collect_regex_matches, email_regex, gcp_regex, github_regex,
    init_regexes, ip_regex, ipv6_regex, mutate_content_field, normalize_text, phone_regex,
    process_anthropic_payload_with_orchestrator, process_completions_payload,
    process_completions_payload_with_map, redact_text, resolve_overlaps, ssn_regex, PiiMatch,
    PiiType, RedactionState,
};
pub use report::{
    generate_json_report, generate_markdown_report, ComplianceMapping, JsonAuditReport,
    JsonReportMetadata, ReportFormat,
};
pub use sink::DangerousSinkDetector;
pub use telemetry::{
    aggregate, append_telemetry_event, compute_stats, default_audit_log_path, ensure_audit_dir,
    load_telemetry_events, read_events, spawn_telemetry_writer, AggregateStats, AuditStats,
    CategoryStats, CostModel, DetectionTier, TelemetryEvent, TelemetryEventType, TelemetryWriter,
};
pub use token_map::TokenMap;
