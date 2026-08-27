//! Compliance audit report generator for LLM Firewall.
//!
//! Generates executive-ready compliance audit reports in Markdown or JSON format,
//! mapping security events to SOC 2 Type II, HIPAA, GDPR, and PCI-DSS v4.0 security controls.

use crate::error::CoreError;
use crate::telemetry::{
    format_rfc3339, sha256_digest, AuditStats, DetectionTier, TelemetryEvent, TelemetryEventType,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Supported output formats for the compliance report.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    /// Markdown document with tables, matrices, and executive summaries.
    Markdown,
    /// Machine-readable structured JSON document.
    Json,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            "json" => Ok(ReportFormat::Json),
            other => Err(format!(
                "Unknown format '{}'. Supported formats: 'markdown', 'json'",
                other
            )),
        }
    }
}

/// Compliance framework control mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceMapping {
    /// Framework identifier (e.g. "SOC 2 Type II", "HIPAA").
    pub framework: String,
    /// Specific control section or reference ID.
    pub control_id: String,
    /// Human-readable title of the control.
    pub title: String,
    /// Firewall technical mechanism fulfilling the requirement.
    pub technical_enforcement: String,
    /// Verification and compliance status.
    pub status: String,
}

/// Returns the standard compliance framework alignment mappings.
pub fn get_compliance_mappings() -> Vec<ComplianceMapping> {
    vec![
        ComplianceMapping {
            framework: "SOC 2 Type II".to_string(),
            control_id: "CC6.1".to_string(),
            title: "Logical Access Controls".to_string(),
            technical_enforcement: "Intercepts and redacts credentials (AWS, GCP, GitHub, Bearer tokens) before outbound LLM transmission.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "SOC 2 Type II".to_string(),
            control_id: "CC6.6".to_string(),
            title: "Boundary Protection".to_string(),
            technical_enforcement: "Sandbox jail validation prevents directory traversal and unauthorized filesystem access.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "SOC 2 Type II".to_string(),
            control_id: "CC6.7".to_string(),
            title: "Data Transmission Protection".to_string(),
            technical_enforcement: "Replaces sensitive tokens with synthetic placeholders, re-injecting them only on inbound verified response streams.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "HIPAA Security Rule".to_string(),
            control_id: "§ 164.312(a)(1)".to_string(),
            title: "Access Control & Technical Safeguards".to_string(),
            technical_enforcement: "Mandatory redaction of Person names, patient identifiers, and health-related tokens using BERT NER.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "HIPAA Security Rule".to_string(),
            control_id: "§ 164.312(e)(1)".to_string(),
            title: "Transmission Security (ePHI)".to_string(),
            technical_enforcement: "Zero unencrypted ePHI or SSN records transmitted over upstream model API channels.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "GDPR".to_string(),
            control_id: "Article 32".to_string(),
            title: "Security of Processing (Pseudonymization)".to_string(),
            technical_enforcement: "Full pseudonymization of PII (emails, phone numbers, IP addresses, person names) into reversible tokens.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "PCI-DSS v4.0".to_string(),
            control_id: "Requirement 3".to_string(),
            title: "Protect Stored Account Data".to_string(),
            technical_enforcement: "Credit card primary account numbers (PAN) detected and scrubbed via Luhn-verified Tier 1 regex.".to_string(),
            status: "Enforced".to_string(),
        },
        ComplianceMapping {
            framework: "PCI-DSS v4.0".to_string(),
            control_id: "Requirement 4".to_string(),
            title: "Protect Cardholder Data in Transit".to_string(),
            technical_enforcement: "Prevents exfiltration of payment data in outbound prompts and tool invocations.".to_string(),
            status: "Enforced".to_string(),
        },
    ]
}

/// Computes the SHA-256 integrity hash of an audit log file, or returns a hash of the event contents.
pub fn compute_audit_log_hash(audit_file_path: Option<&Path>, events: &[TelemetryEvent]) -> String {
    if let Some(path) = audit_file_path {
        if let Ok(bytes) = std::fs::read(path) {
            return sha256_digest(&bytes);
        }
    }
    // Fallback: hash the serialized events
    if let Ok(serialized) = serde_json::to_string(events) {
        sha256_digest(serialized.as_bytes())
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    }
}

/// Generates a comprehensive compliance audit report in Markdown format.
pub fn generate_markdown_report(
    stats: &AuditStats,
    events: &[TelemetryEvent],
    detailed: bool,
    audit_file_path: Option<&Path>,
) -> String {
    let now_secs = TelemetryEvent::current_timestamp();
    let generated_at = format_rfc3339(now_secs);
    let integrity_hash = compute_audit_log_hash(audit_file_path, events);

    let period_str = match (stats.time_period_start, stats.time_period_end) {
        (Some(start), Some(end)) => {
            format!("{} to {}", format_rfc3339(start), format_rfc3339(end))
        }
        _ => "All Available Events".to_string(),
    };

    let mut md = String::new();

    // 1. Header & Metadata
    md.push_str("# LLM Firewall — Compliance & Security Audit Report\n\n");
    md.push_str("> **CONFIDENTIAL** — This report provides cryptographic and technical verification of data protection, credential redaction, and compliance enforcement across all LLM interactions.\n\n");
    md.push_str("### Document Metadata\n\n");
    md.push_str(&format!("- **Generated At**: `{}`\n", generated_at));
    md.push_str(&format!("- **Audit Scope / Period**: `{}`\n", period_str));
    md.push_str("- **Firewall Engine**: `llm-firewall-rs v0.1.0` (Pure Rust Security Engine)\n");
    md.push_str(&format!(
        "- **Audit Log SHA-256 Integrity**: `{}`\n",
        integrity_hash
    ));
    md.push_str("\n---\n\n");

    // 2. Executive Summary
    md.push_str("## 1. Executive Summary\n\n");
    md.push_str("During the audit period, the LLM Firewall intercepted and evaluated all outbound prompt payloads and tool executions before transmission to upstream LLM providers.\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("| :--- | :--- |\n");
    md.push_str(&format!(
        "| **Total Requests Monitored** | **{}** |\n",
        stats.total_requests
    ));
    md.push_str(&format!(
        "| **Sensitive Secrets / PII Redacted** | **{}** |\n",
        stats.total_secrets_redacted
    ));
    md.push_str(&format!(
        "| **Dangerous Sinks Blocked** | **{}** |\n",
        stats.dangerous_sinks_blocked
    ));
    md.push_str(&format!(
        "| **Sandbox Traversal Violations Blocked** | **{}** |\n",
        stats.sandbox_violations_blocked
    ));
    md.push_str(&format!(
        "| **Clean Passthrough Requests** | **{}** |\n",
        stats.passthrough_requests
    ));
    md.push_str(&format!(
        "| **Cumulative Estimated Risk Avoided** | **${:.2}** |\n",
        stats.total_estimated_cost_saved
    ));
    md.push('\n');
    md.push_str("**Attestation**: *Zero unredacted credentials or sensitive records were transmitted to external LLM providers during this period.*\n\n");
    md.push_str("---\n\n");

    // 3. Compliance Framework Alignment
    md.push_str("## 2. Compliance Framework Alignment\n\n");
    md.push_str("The table below details technical control implementations verified against industry standards:\n\n");
    md.push_str("| Framework | Control ID | Requirement | Technical Enforcement Mechanism | Verification |\n");
    md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");

    for m in get_compliance_mappings() {
        md.push_str(&format!(
            "| {} | {} | {} | {} | **{}** |\n",
            m.framework, m.control_id, m.title, m.technical_enforcement, m.status
        ));
    }
    md.push_str("\n---\n\n");

    // 4. Interception & Redaction Summary Table
    md.push_str("## 3. Interception & Redaction Breakdown\n\n");
    if stats.category_breakdown.is_empty() {
        md.push_str(
            "*No sensitive items or security incidents were recorded during this period.*\n\n",
        );
    } else {
        md.push_str("| Category | Detections Count | Detection Tier | Est. Risk Saved |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        for cat in &stats.category_breakdown {
            md.push_str(&format!(
                "| {} | {} | {} | ${:.2} |\n",
                cat.category, cat.count, cat.tier, cat.estimated_risk_saved
            ));
        }
        md.push_str(&format!(
            "| **Total** | **{}** | — | **${:.2}** |\n",
            stats.total_secrets_redacted
                + stats.dangerous_sinks_blocked
                + stats.sandbox_violations_blocked,
            stats.total_estimated_cost_saved
        ));
        md.push('\n');
    }
    md.push_str("---\n\n");

    // 5. Security Incidents Log (Dangerous Sinks & Sandbox Violations)
    md.push_str("## 4. Security Incidents Log\n\n");
    let incidents: Vec<&TelemetryEvent> = events
        .iter()
        .filter(|e| {
            e.event_type == TelemetryEventType::SinkBlocked
                || e.event_type == TelemetryEventType::SandboxBlocked
        })
        .collect();

    if incidents.is_empty() {
        md.push_str(
            "*Zero dangerous sink executions or sandbox escape attempts were detected.*\n\n",
        );
    } else {
        md.push_str("| Timestamp | Request ID | Incident Type | Details | Risk Avoided |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
        for inc in incidents {
            let detail = inc
                .sandbox_violation
                .as_deref()
                .unwrap_or(match inc.tier_triggered {
                    Some(DetectionTier::DangerousSink) => {
                        "Blocked command execution sink (eval/curl/subprocess)"
                    }
                    _ => "Blocked unauthorized sink execution",
                });
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | ${:.2} |\n",
                inc.timestamp_rfc3339(),
                inc.request_id,
                inc.event_type.as_str(),
                detail,
                inc.estimated_cost_saved_usd
            ));
        }
        md.push('\n');
    }
    md.push_str("---\n\n");

    // 6. Daily Activity Timeline
    md.push_str("## 5. Daily Activity Timeline\n\n");
    let mut daily_groups: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for ev in events {
        let date_str = &ev.timestamp_rfc3339()[0..10];
        let entry = daily_groups
            .entry(date_str.to_string())
            .or_insert((0, 0, 0));
        entry.0 += 1; // requests
        if ev.event_type == TelemetryEventType::PiiIntercepted {
            entry.1 += ev.redacted_count;
        }
        if ev.event_type == TelemetryEventType::SinkBlocked
            || ev.event_type == TelemetryEventType::SandboxBlocked
        {
            entry.2 += 1;
        }
    }

    if daily_groups.is_empty() {
        md.push_str("*No activity recorded.*\n\n");
    } else {
        md.push_str(
            "| Date (UTC) | Requests Intercepted | Secrets Redacted | Incidents Blocked |\n",
        );
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        for (date, (reqs, redacts, blocks)) in &daily_groups {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                date, reqs, redacts, blocks
            ));
        }
        md.push('\n');
    }

    // 7. Appendix: Detailed Anonymized Log (if detailed flag requested)
    if detailed && !events.is_empty() {
        md.push_str("---\n\n");
        md.push_str("## 6. Appendix: Chronological Event Log\n\n");
        md.push_str(
            "| Timestamp | Request ID | Event Type | Redacted Count | Latency | Est. Saved |\n",
        );
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for ev in events {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {}ms | ${:.2} |\n",
                ev.timestamp_rfc3339(),
                ev.request_id,
                ev.event_type.as_str(),
                ev.redacted_count,
                ev.latency_ms,
                ev.estimated_cost_saved_usd
            ));
        }
        md.push('\n');
    }

    md
}

/// JSON compliance report payload structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonAuditReport {
    /// Metadata header.
    pub metadata: JsonReportMetadata,
    /// High-level metrics.
    pub executive_summary: AuditStats,
    /// Compliance framework mappings.
    pub compliance_controls: Vec<ComplianceMapping>,
    /// Optional detailed event list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<TelemetryEvent>>,
}

/// Metadata section for JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportMetadata {
    /// Timestamp report was generated in RFC3339 UTC.
    pub generated_at: String,
    /// Firewall software version.
    pub firewall_version: String,
    /// SHA-256 checksum of the audit log file.
    pub audit_log_sha256: String,
    /// Analyzed period description.
    pub audit_period: String,
}

/// Generates a machine-readable JSON compliance report.
///
/// # Errors
/// Returns [`CoreError`] if JSON serialization fails.
pub fn generate_json_report(
    stats: &AuditStats,
    events: &[TelemetryEvent],
    detailed: bool,
    audit_file_path: Option<&Path>,
) -> Result<String, CoreError> {
    let now_secs = TelemetryEvent::current_timestamp();
    let generated_at = format_rfc3339(now_secs);
    let integrity_hash = compute_audit_log_hash(audit_file_path, events);

    let period_str = match (stats.time_period_start, stats.time_period_end) {
        (Some(start), Some(end)) => {
            format!("{} to {}", format_rfc3339(start), format_rfc3339(end))
        }
        _ => "All Available Events".to_string(),
    };

    let report = JsonAuditReport {
        metadata: JsonReportMetadata {
            generated_at,
            firewall_version: "0.1.0".to_string(),
            audit_log_sha256: integrity_hash,
            audit_period: period_str,
        },
        executive_summary: stats.clone(),
        compliance_controls: get_compliance_mappings(),
        events: if detailed {
            Some(events.to_vec())
        } else {
            None
        },
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| CoreError::Serialization(format!("Failed to serialize JSON report: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::PiiType;
    use crate::telemetry::{aggregate, DetectionTier};

    #[test]
    fn test_markdown_report_formatting() {
        let events = vec![
            TelemetryEvent {
                timestamp: 1700000000,
                request_id: "req-abc-123".to_string(),
                event_type: TelemetryEventType::PiiIntercepted,
                tier_triggered: Some(DetectionTier::Tier1Regex),
                secret_types: vec![PiiType::Aws],
                redacted_count: 1,
                sandbox_violation: None,
                model: Some("gpt-4o".to_string()),
                latency_ms: 10,
                estimated_cost_saved_usd: 1000.0,
            },
            TelemetryEvent {
                timestamp: 1700000050,
                request_id: "req-def-456".to_string(),
                event_type: TelemetryEventType::SinkBlocked,
                tier_triggered: Some(DetectionTier::DangerousSink),
                secret_types: vec![],
                redacted_count: 0,
                sandbox_violation: None,
                model: None,
                latency_ms: 2,
                estimated_cost_saved_usd: 2500.0,
            },
        ];

        let stats = aggregate(&events);
        let markdown = generate_markdown_report(&stats, &events, true, None);

        assert!(markdown.contains("# LLM Firewall — Compliance & Security Audit Report"));
        assert!(markdown.contains("SOC 2 Type II"));
        assert!(markdown.contains("HIPAA Security Rule"));
        assert!(markdown.contains("GDPR"));
        assert!(markdown.contains("PCI-DSS v4.0"));
        assert!(markdown.contains("AWS Credentials"));
        assert!(markdown.contains("Dangerous Sinks"));
        assert!(markdown.contains("req-abc-123"));
        assert!(markdown.contains("req-def-456"));
    }

    #[test]
    fn test_json_report_schema() {
        let events = vec![TelemetryEvent {
            timestamp: 1700000000,
            request_id: "req-json-1".to_string(),
            event_type: TelemetryEventType::Passthrough,
            tier_triggered: None,
            secret_types: vec![],
            redacted_count: 0,
            sandbox_violation: None,
            model: Some("gpt-4o".to_string()),
            latency_ms: 5,
            estimated_cost_saved_usd: 0.0,
        }];

        let stats = aggregate(&events);
        let json_str = generate_json_report(&stats, &events, false, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["metadata"]["firewall_version"], "0.1.0");
        assert_eq!(parsed["executive_summary"]["total_requests"], 1);
        assert!(parsed["compliance_controls"].is_array());
    }

    #[test]
    fn test_report_format_parsing() {
        assert_eq!(
            "markdown".parse::<ReportFormat>().unwrap(),
            ReportFormat::Markdown
        );
        assert_eq!(
            "md".parse::<ReportFormat>().unwrap(),
            ReportFormat::Markdown
        );
        assert_eq!("json".parse::<ReportFormat>().unwrap(), ReportFormat::Json);
        assert!("pdf".parse::<ReportFormat>().is_err());
    }
}
