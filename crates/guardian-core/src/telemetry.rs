//! Pure-Rust append-only telemetry event persistence and aggregation engine.
//!
//! This module provides:
//! - Strongly typed [`TelemetryEvent`] and classification enums ([`TelemetryEventType`], [`DetectionTier`]).
//! - Configurable cost/risk savings estimation model ([`CostModel`]).
//! - Thread-safe asynchronous background recorder ([`TelemetryWriter`]).
//! - Resilient streaming JSONL reader with fail-safe corrupted line skipping ([`load_telemetry_events`]).
//! - Aggregated compliance and detection statistics ([`compute_stats`], [`AuditStats`]).

use crate::error::CoreError;
use crate::redact::PiiType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Type of intercepted security event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventType {
    /// Sensitive PII or secret tokens were intercepted and redacted.
    PiiIntercepted,
    /// Dangerous sink execution was detected and blocked.
    SinkBlocked,
    /// Out-of-boundary sandbox directory traversal was detected and blocked.
    SandboxBlocked,
    /// Clean request passed through without sensitive match.
    Passthrough,
}

impl TelemetryEventType {
    /// Returns a human-readable display label for the event type.
    pub fn as_str(&self) -> &'static str {
        match self {
            TelemetryEventType::PiiIntercepted => "PII / Secret Intercepted",
            TelemetryEventType::SinkBlocked => "Dangerous Sink Blocked",
            TelemetryEventType::SandboxBlocked => "Sandbox Traversal Blocked",
            TelemetryEventType::Passthrough => "Clean Passthrough",
        }
    }
}

/// The detection tier or subsystem that triggered the security action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    /// Tier 1 deterministic regex patterns (AWS, GitHub, Bearer, etc.).
    Tier1Regex,
    /// Tier 2 Shannon entropy threshold analysis.
    Tier2Entropy,
    /// Tier 3 BERT NER model inference.
    Tier3Ner,
    /// Tier 4 ML / LLM classification model.
    Tier4Model,
    /// Dangerous sink detector (curl, eval, exec, etc.).
    DangerousSink,
    /// Sandbox jail boundary enforcement.
    SandboxJail,
    /// User-defined custom rule or threshold.
    CustomRule,
}

impl DetectionTier {
    /// Returns a human-readable string representation of the detection tier.
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionTier::Tier1Regex => "Tier 1 (Regex)",
            DetectionTier::Tier2Entropy => "Tier 2 (Shannon Entropy)",
            DetectionTier::Tier3Ner => "Tier 3 (BERT NER)",
            DetectionTier::Tier4Model => "Tier 4 (ML Inference)",
            DetectionTier::DangerousSink => "Dangerous Sink",
            DetectionTier::SandboxJail => "Sandbox Jail",
            DetectionTier::CustomRule => "Custom Rule",
        }
    }
}

/// An immutable telemetry audit event recorded during proxy request processing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryEvent {
    /// Unix timestamp in seconds since epoch when the event occurred.
    pub timestamp: u64,
    /// Unique identifier per intercepted HTTP request (UUID string).
    pub request_id: String,
    /// Classification of the telemetry event.
    pub event_type: TelemetryEventType,
    /// Optional detection tier that triggered the intervention.
    pub tier_triggered: Option<DetectionTier>,
    /// Categories of PII / secrets detected (empty for passthrough or non-PII events).
    #[serde(default)]
    pub secret_types: Vec<PiiType>,
    /// Total number of placeholder substitutions in the request.
    pub redacted_count: usize,
    /// Optional violation message if sandbox boundary was violated.
    pub sandbox_violation: Option<String>,
    /// Upstream LLM model name extracted from request payload (e.g. `gpt-4o`).
    pub model: Option<String>,
    /// End-to-end security pipeline processing duration in milliseconds.
    pub latency_ms: u64,
    /// Calculated risk avoidance / cost saved in USD.
    pub estimated_cost_saved_usd: f64,
}

impl TelemetryEvent {
    /// Returns current Unix timestamp in seconds.
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Formats the event's Unix timestamp as an RFC3339 UTC string.
    pub fn timestamp_rfc3339(&self) -> String {
        format_rfc3339(self.timestamp)
    }
}

/// Formats a Unix timestamp in seconds as an RFC3339 UTC string.
pub fn format_rfc3339(timestamp_secs: u64) -> String {
    let seconds_in_day = 86400;
    let days = timestamp_secs / seconds_in_day;
    let rem_secs = timestamp_secs % seconds_in_day;

    let hours = rem_secs / 3600;
    let rem_mins = rem_secs % 3600;
    let minutes = rem_mins / 60;
    let seconds = rem_mins % 60;

    // Gregorian algorithm (Hinnant)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hours, minutes, seconds
    )
}

/// Cost and risk avoidance multipliers based on industry security benchmarks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostModel {
    /// Value per cloud provider key (AWS, GCP, Azure) leak prevented.
    pub cloud_key_usd: f64,
    /// Value per code host / API bearer token leak prevented.
    pub token_usd: f64,
    /// Value per private cryptographic key leak prevented.
    pub private_key_usd: f64,
    /// Value per financial / identity PII record (SSN, Credit Card) leak prevented.
    pub pci_ssn_usd: f64,
    /// Value per general personal data record (Email, Phone, Person, IP) leak prevented.
    pub general_pii_usd: f64,
    /// Value per dangerous sink execution blocked (RCE prevention).
    pub dangerous_sink_usd: f64,
    /// Value per sandbox breakout / traversal prevented.
    pub sandbox_violation_usd: f64,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            cloud_key_usd: 1000.0,
            token_usd: 500.0,
            private_key_usd: 1000.0,
            pci_ssn_usd: 150.0,
            general_pii_usd: 50.0,
            dangerous_sink_usd: 2500.0,
            sandbox_violation_usd: 1500.0,
        }
    }
}

impl CostModel {
    /// Calculates estimated risk avoidance value for a single event.
    pub fn calculate_event_savings(
        &self,
        event_type: TelemetryEventType,
        secret_types: &[PiiType],
        redacted_count: usize,
    ) -> f64 {
        match event_type {
            TelemetryEventType::SinkBlocked => self.dangerous_sink_usd,
            TelemetryEventType::SandboxBlocked => self.sandbox_violation_usd,
            TelemetryEventType::Passthrough => 0.0,
            TelemetryEventType::PiiIntercepted => {
                if secret_types.is_empty() {
                    return self.general_pii_usd * (redacted_count.max(1) as f64);
                }
                let mut total = 0.0;
                for pii in secret_types {
                    total += match pii {
                        PiiType::Aws | PiiType::Gcp => self.cloud_key_usd,
                        PiiType::Github | PiiType::Bearer => self.token_usd,
                        PiiType::HighEntropy => self.token_usd,
                        PiiType::Ssn | PiiType::Cc => self.pci_ssn_usd,
                        PiiType::Email
                        | PiiType::Phone
                        | PiiType::Ip
                        | PiiType::Person
                        | PiiType::Custom
                        | PiiType::Unknown => self.general_pii_usd,
                    };
                }
                total
            }
        }
    }
}

/// Statistics for an individual detected category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategoryStats {
    /// Name of the category (e.g. "AWS Credentials", "GitHub Tokens").
    pub category: String,
    /// Total count of occurrences.
    pub count: usize,
    /// Detection tier typically associated with this category.
    pub tier: String,
    /// Cumulative estimated risk value avoided.
    pub estimated_risk_saved: f64,
}

/// Cumulative aggregate statistics computed across a set of telemetry events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditStats {
    /// Total intercepted requests (including passthrough and violations).
    pub total_requests: usize,
    /// Total secret / PII placeholder substitutions performed.
    pub total_secrets_redacted: usize,
    /// Total dangerous command sink executions prevented.
    pub dangerous_sinks_blocked: usize,
    /// Total out-of-boundary sandbox traversals prevented.
    pub sandbox_violations_blocked: usize,
    /// Total clean requests passing without modifications.
    pub passthrough_requests: usize,
    /// Total cumulative estimated cost/risk saved in USD.
    pub total_estimated_cost_saved: f64,
    /// Category-by-category breakdown table.
    pub category_breakdown: Vec<CategoryStats>,
    /// Detections breakdown by detection tier.
    pub tier_breakdown: HashMap<DetectionTier, usize>,
    /// Detailed count of each specific [`PiiType`].
    pub secret_type_counts: HashMap<PiiType, usize>,
    /// Earliest event timestamp in the analyzed window.
    pub time_period_start: Option<u64>,
    /// Latest event timestamp in the analyzed window.
    pub time_period_end: Option<u64>,
}

/// Type alias for AggregateStats.
pub type AggregateStats = AuditStats;

/// Resolves the default path for the append-only audit JSONL file.
///
/// Order of precedence:
/// 1. `GUARDIAN_AUDIT_LOG` environment variable.
/// 2. `~/.guardian/audit.jsonl` in user's home directory.
/// 3. `.guardian/audit.jsonl` relative to current working directory.
pub fn default_audit_log_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("GUARDIAN_AUDIT_LOG") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            let has_traversal = path.components().any(|c| c == std::path::Component::ParentDir);
            if has_traversal {
                tracing::warn!("GUARDIAN_AUDIT_LOG contains directory traversal (..). Falling back to default.");
            } else {
                return path;
            }
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        return home_path.join(".guardian").join("audit.jsonl");
    }

    PathBuf::from(".guardian").join("audit.jsonl")
}

/// Ensures the parent directory of the audit log exists with secure permissions.
///
/// # Errors
/// Returns an [`std::io::Error`] if directory creation or permission setting fails.
pub fn ensure_audit_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
    Ok(())
}

/// Appends a single [`TelemetryEvent`] synchronously to the specified JSONL file.
///
/// # Errors
/// Returns a [`CoreError`] if serialization or disk writing fails.
pub fn append_telemetry_event(path: &Path, event: &TelemetryEvent) -> Result<(), CoreError> {
    ensure_audit_dir(path)
        .map_err(|e| CoreError::Internal(format!("Failed to create audit log directory: {}", e)))?;

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| CoreError::Internal(format!("Failed to open audit log file: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let json_line = serde_json::to_string(event).map_err(|e| {
        CoreError::Serialization(format!("Failed to serialize telemetry event: {}", e))
    })?;

    writeln!(file, "{}", json_line).map_err(|e| {
        CoreError::Internal(format!("Failed to write telemetry event to disk: {}", e))
    })?;

    Ok(())
}

/// Asynchronous writer wrapper that continuously drains a channel of events and appends to disk.
pub struct TelemetryWriter {
    /// Background task join handle.
    pub handle: tokio::task::JoinHandle<()>,
}

impl TelemetryWriter {
    /// Spawns a background task that reads [`TelemetryEvent`]s from an unbounded receiver
    /// and appends them to `log_path`.
    pub fn new(log_path: PathBuf) -> (tokio::sync::mpsc::UnboundedSender<TelemetryEvent>, Self) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = spawn_telemetry_writer(rx, log_path);
        (tx, Self { handle })
    }

    /// Spawns a background task with bounded channel of specified capacity.
    pub fn new_bounded(
        log_path: PathBuf,
        capacity: usize,
    ) -> (tokio::sync::mpsc::Sender<TelemetryEvent>, Self) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<TelemetryEvent>(capacity);
        let handle = tokio::spawn(async move {
            if let Err(e) = ensure_audit_dir(&log_path) {
                tracing::error!(error = %e, "Failed to create audit log directory");
                return;
            }

            let file_opt = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await;

            let mut file = match file_opt {
                Ok(f) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
                    }
                    f
                }
                Err(e) => {
                    tracing::error!(error = %e, path = ?log_path, "Failed to open audit log file");
                    return;
                }
            };

            use tokio::io::AsyncWriteExt;
            while let Some(event) = rx.recv().await {
                if let Ok(line) = serde_json::to_string(&event) {
                    let mut data = line.into_bytes();
                    data.push(b'\n');
                    if let Err(e) = file.write_all(&data).await {
                        tracing::error!(error = %e, "Failed to append telemetry event to disk");
                    }
                }
            }
            let _ = file.flush().await;
            tracing::debug!("Bounded telemetry writer task completed cleanly");
        });
        (tx, Self { handle })
    }
}

/// Spawns an asynchronous Tokio worker task that flushes received events to the JSONL log file.
pub fn spawn_telemetry_writer(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<TelemetryEvent>,
    log_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = ensure_audit_dir(&log_path) {
            tracing::error!(error = %e, "Failed to create audit log directory");
            return;
        }

        let file_opt = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await;

        let mut file = match file_opt {
            Ok(f) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
                }
                f
            }
            Err(e) => {
                tracing::error!(error = %e, path = ?log_path, "Failed to open audit log file");
                return;
            }
        };

        use tokio::io::AsyncWriteExt;
        while let Some(event) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&event) {
                let mut data = line.into_bytes();
                data.push(b'\n');
                if let Err(e) = file.write_all(&data).await {
                    tracing::error!(error = %e, "Failed to append telemetry event to disk");
                }
            }
        }
        let _ = file.flush().await;
        tracing::debug!("Telemetry writer task completed cleanly");
    })
}

/// Reads all valid [`TelemetryEvent`] records from an audit log file, optionally filtered by time window.
///
/// Corrupted or partial lines are safely skipped with diagnostic warnings.
///
/// # Errors
/// Returns [`CoreError`] if the file cannot be opened (other than `NotFound`).
pub fn load_telemetry_events(
    path: &Path,
    since: Option<std::time::Duration>,
) -> Result<Vec<TelemetryEvent>, CoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    use std::io::BufRead;
    let file = std::fs::File::open(path).map_err(|e| {
        CoreError::Internal(format!("Failed to read audit log at {:?}: {}", path, e))
    })?;
    let reader = std::io::BufReader::new(file);

    let cutoff_timestamp = since.map(|dur| {
        let now = TelemetryEvent::current_timestamp();
        now.saturating_sub(dur.as_secs())
    });

    let mut events = Vec::new();
    for (line_num, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(line = line_num + 1, error = %e, "Failed to read line from audit log, skipping");
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<TelemetryEvent>(trimmed) {
            Ok(event) => {
                if let Some(cutoff) = cutoff_timestamp {
                    if event.timestamp < cutoff {
                        continue;
                    }
                }
                events.push(event);
            }
            Err(e) => {
                tracing::warn!(
                    line = line_num + 1,
                    error = %e,
                    "Malformed JSONL line in audit log, skipping"
                );
            }
        }
    }

    Ok(events)
}

/// Convenience function to read all events from a log file without time filtering.
///
/// # Errors
/// Returns [`CoreError`] if reading fails.
pub fn read_events(log_path: &Path) -> Result<Vec<TelemetryEvent>, CoreError> {
    load_telemetry_events(log_path, None)
}

/// Parses a duration string (e.g. "24h", "7d", "30d", "60m", "all") into an optional [`std::time::Duration`].
///
/// # Errors
/// Returns an error message string if the format is invalid.
pub fn parse_duration(s: &str) -> Result<Option<std::time::Duration>, String> {
    let trimmed = s.trim().to_lowercase();
    if trimmed == "all" || trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(num_str) = trimmed.strip_suffix('s') {
        let n: u64 = num_str
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        return Ok(Some(std::time::Duration::from_secs(n)));
    }
    if let Some(num_str) = trimmed.strip_suffix('m') {
        let n: u64 = num_str
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        return Ok(Some(std::time::Duration::from_secs(n * 60)));
    }
    if let Some(num_str) = trimmed.strip_suffix('h') {
        let n: u64 = num_str
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        return Ok(Some(std::time::Duration::from_secs(n * 3600)));
    }
    if let Some(num_str) = trimmed.strip_suffix('d') {
        let n: u64 = num_str
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        return Ok(Some(std::time::Duration::from_secs(n * 86400)));
    }
    if let Some(num_str) = trimmed.strip_suffix('w') {
        let n: u64 = num_str
            .parse()
            .map_err(|e| format!("Invalid duration '{}': {}", s, e))?;
        return Ok(Some(std::time::Duration::from_secs(n * 7 * 86400)));
    }
    let n: u64 = trimmed.parse().map_err(|_| {
        format!(
            "Invalid duration format '{}'. Expected format e.g. '24h', '7d', '30d', 'all'",
            s
        )
    })?;
    Ok(Some(std::time::Duration::from_secs(n * 3600)))
}

/// Computes cumulative summary statistics from a slice of [`TelemetryEvent`] records.
pub fn compute_stats(events: &[TelemetryEvent], cost_model: Option<&CostModel>) -> AuditStats {
    let default_cm = CostModel::default();
    let cm = cost_model.unwrap_or(&default_cm);

    let mut total_secrets_redacted = 0;
    let mut dangerous_sinks_blocked = 0;
    let mut sandbox_violations_blocked = 0;
    let mut passthrough_requests = 0;
    let mut total_estimated_cost_saved = 0.0;

    let mut tier_breakdown: HashMap<DetectionTier, usize> = HashMap::new();
    let mut secret_type_counts: HashMap<PiiType, usize> = HashMap::new();

    let mut earliest_ts: Option<u64> = None;
    let mut latest_ts: Option<u64> = None;

    let mut pii_cost_by_type: HashMap<PiiType, (usize, f64)> = HashMap::new();

    for ev in events {
        earliest_ts = Some(match earliest_ts {
            Some(curr) => curr.min(ev.timestamp),
            None => ev.timestamp,
        });
        latest_ts = Some(match latest_ts {
            Some(curr) => curr.max(ev.timestamp),
            None => ev.timestamp,
        });

        if let Some(tier) = ev.tier_triggered {
            *tier_breakdown.entry(tier).or_insert(0) += 1;
        }

        match ev.event_type {
            TelemetryEventType::PiiIntercepted => {
                total_secrets_redacted += ev.redacted_count;
                let savings = if ev.estimated_cost_saved_usd > 0.0 {
                    ev.estimated_cost_saved_usd
                } else {
                    cm.calculate_event_savings(ev.event_type, &ev.secret_types, ev.redacted_count)
                };
                total_estimated_cost_saved += savings;

                for pii in &ev.secret_types {
                    *secret_type_counts.entry(*pii).or_insert(0) += 1;
                    let pii_savings =
                        cm.calculate_event_savings(TelemetryEventType::PiiIntercepted, &[*pii], 1);
                    let entry = pii_cost_by_type.entry(*pii).or_insert((0, 0.0));
                    entry.0 += 1;
                    entry.1 += pii_savings;
                }
            }
            TelemetryEventType::SinkBlocked => {
                dangerous_sinks_blocked += 1;
                let savings = if ev.estimated_cost_saved_usd > 0.0 {
                    ev.estimated_cost_saved_usd
                } else {
                    cm.dangerous_sink_usd
                };
                total_estimated_cost_saved += savings;
            }
            TelemetryEventType::SandboxBlocked => {
                sandbox_violations_blocked += 1;
                let savings = if ev.estimated_cost_saved_usd > 0.0 {
                    ev.estimated_cost_saved_usd
                } else {
                    cm.sandbox_violation_usd
                };
                total_estimated_cost_saved += savings;
            }
            TelemetryEventType::Passthrough => {
                passthrough_requests += 1;
            }
        }
    }

    let mut category_breakdown = Vec::new();

    // Map PII Types to categories
    for (pii, (count, saved)) in &pii_cost_by_type {
        let (name, tier) = match pii {
            PiiType::Aws => ("AWS Credentials", "Tier 1 (Regex)"),
            PiiType::Gcp => ("GCP Keys", "Tier 1 (Regex)"),
            PiiType::Github => ("GitHub Tokens", "Tier 1 (Regex)"),
            PiiType::Bearer => ("Bearer Tokens", "Tier 1 (Regex)"),
            PiiType::HighEntropy => ("High-Entropy Keys", "Tier 2 (Shannon Entropy)"),
            PiiType::Ssn => ("Social Security Numbers", "Tier 1 (Regex)"),
            PiiType::Cc => ("Credit Cards (PCI)", "Tier 1 (Regex)"),
            PiiType::Email => ("Email Addresses", "Tier 1 (Regex)"),
            PiiType::Phone => ("Phone Numbers", "Tier 1 (Regex)"),
            PiiType::Ip => ("IP Addresses", "Tier 1 (Regex)"),
            PiiType::Person => ("Person / Name (NER)", "Tier 3 (BERT NER)"),
            PiiType::Custom => ("Custom Pattern Rules", "Custom Rule"),
            PiiType::Unknown => ("Unclassified Sensitive Data", "Tier 1 (Regex)"),
        };
        category_breakdown.push(CategoryStats {
            category: name.to_string(),
            count: *count,
            tier: tier.to_string(),
            estimated_risk_saved: *saved,
        });
    }

    if dangerous_sinks_blocked > 0 {
        category_breakdown.push(CategoryStats {
            category: "Dangerous Sinks".to_string(),
            count: dangerous_sinks_blocked,
            tier: "Dangerous Sink Detector".to_string(),
            estimated_risk_saved: dangerous_sinks_blocked as f64 * cm.dangerous_sink_usd,
        });
    }

    if sandbox_violations_blocked > 0 {
        category_breakdown.push(CategoryStats {
            category: "Sandbox Breakouts".to_string(),
            count: sandbox_violations_blocked,
            tier: "Sandbox Jail Engine".to_string(),
            estimated_risk_saved: sandbox_violations_blocked as f64 * cm.sandbox_violation_usd,
        });
    }

    category_breakdown.sort_by_key(|b| std::cmp::Reverse(b.count));

    AuditStats {
        total_requests: events.len(),
        total_secrets_redacted,
        dangerous_sinks_blocked,
        sandbox_violations_blocked,
        passthrough_requests,
        total_estimated_cost_saved,
        category_breakdown,
        tier_breakdown,
        secret_type_counts,
        time_period_start: earliest_ts,
        time_period_end: latest_ts,
    }
}

/// Convenience alias for `compute_stats` with default cost model.
pub fn aggregate(events: &[TelemetryEvent]) -> AggregateStats {
    compute_stats(events, None)
}

/// Computes a standard SHA-256 hex digest for arbitrary input bytes in 100% safe pure Rust.
pub fn sha256_digest(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_telemetry_event_serde_roundtrip() {
        let event = TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-test-uuid-123".to_string(),
            event_type: TelemetryEventType::PiiIntercepted,
            tier_triggered: Some(DetectionTier::Tier1Regex),
            secret_types: vec![PiiType::Aws, PiiType::Github],
            redacted_count: 2,
            sandbox_violation: None,
            model: Some("gpt-4o".to_string()),
            latency_ms: 12,
            estimated_cost_saved_usd: 1500.0,
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: TelemetryEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_telemetry_roundtrip() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let event1 = TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-1".to_string(),
            event_type: TelemetryEventType::PiiIntercepted,
            tier_triggered: Some(DetectionTier::Tier1Regex),
            secret_types: vec![PiiType::Aws],
            redacted_count: 1,
            sandbox_violation: None,
            model: Some("gpt-4o".to_string()),
            latency_ms: 5,
            estimated_cost_saved_usd: 1000.0,
        };

        let event2 = TelemetryEvent {
            timestamp: 1700000010,
            request_id: "req-2".to_string(),
            event_type: TelemetryEventType::SinkBlocked,
            tier_triggered: Some(DetectionTier::DangerousSink),
            secret_types: vec![],
            redacted_count: 0,
            sandbox_violation: None,
            model: None,
            latency_ms: 2,
            estimated_cost_saved_usd: 2500.0,
        };

        append_telemetry_event(&path, &event1).unwrap();
        append_telemetry_event(&path, &event2).unwrap();

        let events = read_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], event1);
        assert_eq!(events[1], event2);
    }

    #[test]
    fn test_resilient_reader() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();

        let event = TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-valid".to_string(),
            event_type: TelemetryEventType::Passthrough,
            tier_triggered: None,
            secret_types: vec![],
            redacted_count: 0,
            sandbox_violation: None,
            model: Some("claude-3-5-sonnet".to_string()),
            latency_ms: 8,
            estimated_cost_saved_usd: 0.0,
        };

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        // Write: valid line, empty line, malformed json, another valid line
        let valid_json = serde_json::to_string(&event).unwrap();
        writeln!(file, "{}", valid_json).unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{{corrupted json string").unwrap();
        writeln!(file, "{}", valid_json).unwrap();

        let events = load_telemetry_events(&path, None).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].request_id, "req-valid");
        assert_eq!(events[1].request_id, "req-valid");
    }

    #[test]
    fn test_aggregate_stats() {
        let events = vec![
            TelemetryEvent {
                timestamp: 1700000000,
                request_id: "req-1".to_string(),
                event_type: TelemetryEventType::PiiIntercepted,
                tier_triggered: Some(DetectionTier::Tier1Regex),
                secret_types: vec![PiiType::Aws, PiiType::Github],
                redacted_count: 2,
                sandbox_violation: None,
                model: Some("gpt-4o".to_string()),
                latency_ms: 10,
                estimated_cost_saved_usd: 1500.0,
            },
            TelemetryEvent {
                timestamp: 1700000050,
                request_id: "req-2".to_string(),
                event_type: TelemetryEventType::SinkBlocked,
                tier_triggered: Some(DetectionTier::DangerousSink),
                secret_types: vec![],
                redacted_count: 0,
                sandbox_violation: None,
                model: None,
                latency_ms: 3,
                estimated_cost_saved_usd: 2500.0,
            },
            TelemetryEvent {
                timestamp: 1700000100,
                request_id: "req-3".to_string(),
                event_type: TelemetryEventType::SandboxBlocked,
                tier_triggered: Some(DetectionTier::SandboxJail),
                secret_types: vec![],
                redacted_count: 0,
                sandbox_violation: Some("/etc/shadow".to_string()),
                model: None,
                latency_ms: 2,
                estimated_cost_saved_usd: 1500.0,
            },
            TelemetryEvent {
                timestamp: 1700000150,
                request_id: "req-4".to_string(),
                event_type: TelemetryEventType::Passthrough,
                tier_triggered: None,
                secret_types: vec![],
                redacted_count: 0,
                sandbox_violation: None,
                model: Some("gpt-4o".to_string()),
                latency_ms: 15,
                estimated_cost_saved_usd: 0.0,
            },
        ];

        let stats = aggregate(&events);
        assert_eq!(stats.total_requests, 4);
        assert_eq!(stats.total_secrets_redacted, 2);
        assert_eq!(stats.dangerous_sinks_blocked, 1);
        assert_eq!(stats.sandbox_violations_blocked, 1);
        assert_eq!(stats.passthrough_requests, 1);
        assert_eq!(stats.total_estimated_cost_saved, 5500.0);
        assert_eq!(stats.time_period_start, Some(1700000000));
        assert_eq!(stats.time_period_end, Some(1700000150));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("all").unwrap(), None);
        assert_eq!(
            parse_duration("24h").unwrap(),
            Some(std::time::Duration::from_secs(24 * 3600))
        );
        assert_eq!(
            parse_duration("7d").unwrap(),
            Some(std::time::Duration::from_secs(7 * 86400))
        );
        assert_eq!(
            parse_duration("30m").unwrap(),
            Some(std::time::Duration::from_secs(30 * 60))
        );
        assert!(parse_duration("invalid_dur").is_err());
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256 of "abc" is ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
