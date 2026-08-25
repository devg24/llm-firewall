use serde::Deserialize;
use std::path::Path;

pub const MAX_REGEX_AST_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_REGEX_DFA_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GuardianConfig {
    pub domain: Option<String>,
    pub thresholds: Option<ThresholdOverrides>,
    pub regex: Option<RegexConfig>,
    pub rules: Option<Vec<CustomRegexRule>>,
    pub allowlist: Option<AllowlistConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThresholdOverrides {
    pub pattern: Option<f32>,
    pub entropy: Option<f32>,
    pub ner: Option<f32>,
    pub contextual: Option<f32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegexConfig {
    #[serde(default)]
    pub rules: Vec<CustomRegexRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRegexRule {
    pub id: String,
    pub pattern: String,
    #[serde(default)]
    pub pii_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowlistConfig {
    pub terms: Option<Vec<String>>,
    pub patterns: Option<Vec<String>>,
}

pub fn parse_guardian_toml_str(content: &str) -> Option<GuardianConfig> {
    let mut config: GuardianConfig = match toml::from_str(content) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse .guardian.toml content; falling back to zero-config defaults");
            return None;
        }
    };

    let validate_regex = |pattern: &str| -> Result<regex::Regex, regex::Error> {
        regex::RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_AST_SIZE)
            .dfa_size_limit(MAX_REGEX_DFA_SIZE)
            .build()
    };

    if let Some(ref mut regex_cfg) = config.regex {
        regex_cfg.rules.retain(|rule| {
            if let Err(e) = validate_regex(&rule.pattern) {
                tracing::warn!(rule_id = %rule.id, pattern = %rule.pattern, error = %e, "Invalid regex pattern in .guardian.toml; skipping rule");
                false
            } else {
                true
            }
        });
    }

    if let Some(ref mut direct_rules) = config.rules {
        direct_rules.retain(|rule| {
            if let Err(e) = validate_regex(&rule.pattern) {
                tracing::warn!(rule_id = %rule.id, pattern = %rule.pattern, error = %e, "Invalid regex pattern in .guardian.toml; skipping rule");
                false
            } else {
                true
            }
        });
    }

    if let Some(ref mut allowlist) = config.allowlist {
        if let Some(ref mut patterns) = allowlist.patterns {
            patterns.retain(|pattern| {
                if let Err(e) = validate_regex(pattern) {
                    tracing::warn!(pattern = %pattern, error = %e, "Invalid allowlist regex pattern in .guardian.toml; skipping pattern");
                    false
                } else {
                    true
                }
            });
        }
    }

    Some(config)
}

pub fn parse_guardian_toml(path: &Path) -> Option<GuardianConfig> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    parse_guardian_toml_str(&content)
}
