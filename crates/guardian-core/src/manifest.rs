use crate::domain::DomainProfile;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const CRYPTO_MARKERS: &[&str] = &[
    "ethers",
    "solana",
    "web3",
    "alloy",
    "bitcoin",
    "alloy-primitives",
    "@solana/web3.js",
    "viem",
    "wagmi",
    "web3.py",
    "eth-account",
    "bip39",
    "secp256k1",
    "go-ethereum",
];

const HEALTHCARE_MARKERS: &[&str] = &[
    "fhir",
    "hl7",
    "medplum",
    "bonfhir",
    "dicom",
    "python-hl7",
    "fhirclient",
    "healthgorilla",
];

const IGNORED_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "vendor",
    ".turbo",
    ".next",
    "coverage",
    ".cache",
];

const MAX_SCAN_DEPTH: usize = 5;

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
    // Fail-safe fallback on malformed configs
    let mut config: GuardianConfig = match toml::from_str(content) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse .guardian.toml content; falling back to zero-config defaults");
            return None;
        }
    };

    // ReDoS pre-validation: Rust's regex crate provides linear O(n) guarantees
    // by using finite automata rather than backtracking, natively avoiding ReDoS.
    // Validate rules under both [regex] and [[rules]]
    let validate_regex = |pattern: &str| -> Result<regex::Regex, regex::Error> {
        regex::RegexBuilder::new(pattern)
            .size_limit(10 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
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

    // Validate allowlist patterns
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

fn check_text_for_markers(text: &str, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let text_lower = text.to_lowercase();
    for marker in CRYPTO_MARKERS {
        if text_lower.contains(marker) {
            *is_crypto = true;
        }
    }
    for marker in HEALTHCARE_MARKERS {
        if text_lower.contains(marker) {
            *is_healthcare = true;
        }
    }
}

fn scan_cargo_toml(path: &Path, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Ok(toml_val) = toml::from_str::<toml::Value>(&content) {
        let mut sections_to_check = vec!["dependencies", "dev-dependencies", "build-dependencies"];

        // Target specific dependencies
        if let Some(targets) = toml_val.get("target").and_then(|t| t.as_table()) {
            for (_, target_val) in targets {
                if let Some(target_tbl) = target_val.as_table() {
                    for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
                        if let Some(deps) = target_tbl.get(*section) {
                            let dep_str = deps.to_string();
                            check_text_for_markers(&dep_str, is_crypto, is_healthcare);
                        }
                    }
                }
            }
        }

        // Workspace dependencies
        if let Some(ws) = toml_val.get("workspace").and_then(|w| w.as_table()) {
            if let Some(deps) = ws.get("dependencies") {
                let dep_str = deps.to_string();
                check_text_for_markers(&dep_str, is_crypto, is_healthcare);
            }
        }

        for section in sections_to_check.drain(..) {
            if let Some(deps) = toml_val.get(section) {
                let dep_str = deps.to_string();
                check_text_for_markers(&dep_str, is_crypto, is_healthcare);
            }
        }
    } else {
        tracing::warn!(path = ?path, "Malformed Cargo.toml file; continuing domain detection");
    }
}

fn scan_package_json(path: &Path, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&content) {
        let sections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];
        for section in &sections {
            if let Some(deps) = json_val.get(*section) {
                let dep_str = deps.to_string();
                check_text_for_markers(&dep_str, is_crypto, is_healthcare);
            }
        }
    } else {
        tracing::warn!(path = ?path, "Malformed package.json file; continuing domain detection");
    }
}

fn scan_go_mod(path: &Path, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        check_text_for_markers(trimmed, is_crypto, is_healthcare);
    }
}

fn scan_requirements_txt(path: &Path, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let pkg_part = trimmed
            .split(['=', '>', '<', '~', '!', ';', ' '])
            .next()
            .unwrap_or(trimmed);
        check_text_for_markers(pkg_part, is_crypto, is_healthcare);
    }
}

fn scan_pyproject_toml(path: &Path, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Ok(toml_val) = toml::from_str::<toml::Value>(&content) {
        if let Some(project) = toml_val.get("project").and_then(|p| p.as_table()) {
            if let Some(deps) = project.get("dependencies") {
                check_text_for_markers(&deps.to_string(), is_crypto, is_healthcare);
            }
            if let Some(opt_deps) = project.get("optional-dependencies") {
                check_text_for_markers(&opt_deps.to_string(), is_crypto, is_healthcare);
            }
        }
        if let Some(tool) = toml_val.get("tool").and_then(|t| t.as_table()) {
            if let Some(poetry) = tool.get("poetry").and_then(|p| p.as_table()) {
                if let Some(deps) = poetry.get("dependencies") {
                    check_text_for_markers(&deps.to_string(), is_crypto, is_healthcare);
                }
                if let Some(group) = poetry.get("group").and_then(|g| g.as_table()) {
                    check_text_for_markers(&group.to_string(), is_crypto, is_healthcare);
                }
            }
        }
    }
}

pub fn detect_domain_from_manifests(workspace_root: &Path) -> DomainProfile {
    let mut is_crypto = false;
    let mut is_healthcare = false;

    // Check Guardian config for explicit override first
    let guardian_toml = workspace_root.join(".guardian.toml");
    if let Some(config) = parse_guardian_toml(&guardian_toml) {
        if let Some(domain_str) = config.domain {
            return match domain_str.to_lowercase().as_str() {
                "crypto" | "fintech" => DomainProfile::CryptoFintech,
                "healthcare" | "health" => DomainProfile::Healthcare,
                _ => DomainProfile::Standard,
            };
        }
    }

    let mut stack: Vec<(PathBuf, usize)> = vec![(workspace_root.to_path_buf(), 0)];
    let mut visited: HashSet<PathBuf> = HashSet::new();

    if let Ok(canonical) = workspace_root.canonicalize() {
        visited.insert(canonical);
    } else {
        visited.insert(workspace_root.to_path_buf());
    }

    while let Some((current_dir, depth)) = stack.pop() {
        if !current_dir.exists() || !current_dir.is_dir() {
            continue;
        }

        // 1. Scan manifests in current_dir
        let cargo_path = current_dir.join("Cargo.toml");
        if cargo_path.is_file() {
            scan_cargo_toml(&cargo_path, &mut is_crypto, &mut is_healthcare);
        }

        let pkg_path = current_dir.join("package.json");
        if pkg_path.is_file() {
            scan_package_json(&pkg_path, &mut is_crypto, &mut is_healthcare);
        }

        let go_mod_path = current_dir.join("go.mod");
        if go_mod_path.is_file() {
            scan_go_mod(&go_mod_path, &mut is_crypto, &mut is_healthcare);
        }

        let req_path = current_dir.join("requirements.txt");
        if req_path.is_file() {
            scan_requirements_txt(&req_path, &mut is_crypto, &mut is_healthcare);
        }

        let pyproject_path = current_dir.join("pyproject.toml");
        if pyproject_path.is_file() {
            scan_pyproject_toml(&pyproject_path, &mut is_crypto, &mut is_healthcare);
        }

        // 2. Recurse into subdirectories if depth allows
        if depth < MAX_SCAN_DEPTH {
            if let Ok(entries) = std::fs::read_dir(&current_dir) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_dir() {
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            if !IGNORED_DIRS.contains(&name_str.as_ref())
                                && !name_str.starts_with('.')
                            {
                                let sub_path = entry.path();
                                let canonical =
                                    sub_path.canonicalize().unwrap_or_else(|_| sub_path.clone());
                                if visited.insert(canonical) {
                                    stack.push((sub_path, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if is_crypto {
        DomainProfile::CryptoFintech
    } else if is_healthcare {
        DomainProfile::Healthcare
    } else {
        DomainProfile::Standard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_detect_crypto_from_cargo_toml() {
        let dir = tempdir().unwrap();
        let cargo_toml = r#"
        [dependencies]
        ethers = "2.0"
        "#;
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }

    #[test]
    fn test_detect_healthcare_from_package_json() {
        let dir = tempdir().unwrap();
        let pkg_json = r#"
        {
            "dependencies": {
                "fhir": "1.0.0"
            }
        }
        "#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::Healthcare
        );
    }

    #[test]
    fn test_detect_crypto_from_go_mod() {
        let dir = tempdir().unwrap();
        let go_mod = r#"
        module example.com/mycrypto

        go 1.22

        require (
            github.com/ethereum/go-ethereum v1.13.5
        )
        "#;
        fs::write(dir.path().join("go.mod"), go_mod).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }

    #[test]
    fn test_detect_python_requirements_and_pyproject() {
        let dir = tempdir().unwrap();
        let reqs = "web3.py>=6.0.0\nrequests==2.31.0\n";
        fs::write(dir.path().join("requirements.txt"), reqs).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );

        let dir2 = tempdir().unwrap();
        let pyproj = r#"
        [project]
        dependencies = [
            "medplum>=0.1.0",
        ]
        "#;
        fs::write(dir2.path().join("pyproject.toml"), pyproj).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir2.path()),
            DomainProfile::Healthcare
        );
    }

    #[test]
    fn test_malformed_guardian_toml_fallback() {
        let dir = tempdir().unwrap();
        let bad_toml = r#"
        [regex
        rules = [
        "#;
        fs::write(dir.path().join(".guardian.toml"), bad_toml).unwrap();
        // Should fallback silently and return standard if no domain is detected
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::Standard
        );
        assert!(parse_guardian_toml(&dir.path().join(".guardian.toml")).is_none());
    }

    #[test]
    fn test_guardian_toml_custom_rules_and_thresholds() {
        let toml_str = r#"
        domain = "healthcare"

        [thresholds]
        entropy = 4.7
        ner = 0.85

        [[rules]]
        id = "company_secret"
        pattern = "SECRET_[A-Z0-9]{8}"
        pii_type = "CUSTOM"

        [allowlist]
        terms = ["ALLOWED_TOKEN", "PUBLIC_VAR"]
        patterns = ["DEBUG_.*"]
        "#;

        let cfg = parse_guardian_toml_str(toml_str).expect("Should parse valid toml");
        assert_eq!(cfg.domain.as_deref(), Some("healthcare"));
        let th = cfg.thresholds.unwrap();
        assert_eq!(th.entropy, Some(4.7));
        assert_eq!(th.ner, Some(0.85));

        let rules = cfg.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "company_secret");

        let allowlist = cfg.allowlist.unwrap();
        assert_eq!(
            allowlist.terms.unwrap(),
            vec!["ALLOWED_TOKEN", "PUBLIC_VAR"]
        );
        assert_eq!(allowlist.patterns.unwrap(), vec!["DEBUG_.*"]);
    }

    #[test]
    fn test_guardian_toml_invalid_regex_rejected() {
        let bad_regex = r#"
        [[rules]]
        id = "bad"
        pattern = "(unclosed"
        "#;
        let config = parse_guardian_toml_str(bad_regex).expect("Should parse");
        assert!(config.rules.unwrap().is_empty());

        let bad_allowlist_regex = r#"
        [allowlist]
        patterns = ["[a-z"]
        "#;
        let config2 = parse_guardian_toml_str(bad_allowlist_regex).expect("Should parse");
        assert!(config2.allowlist.unwrap().patterns.unwrap().is_empty());
    }

    #[test]
    fn test_monorepo_discovery() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("crates").join("subcrate");
        fs::create_dir_all(&sub).unwrap();
        let cargo_toml = r#"
        [dependencies]
        solana = "1.0"
        "#;
        fs::write(sub.join("Cargo.toml"), cargo_toml).unwrap();

        // Ignored node_modules should not crash
        let ignored_dir = dir.path().join("node_modules").join("fake-crypto");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(
            ignored_dir.join("package.json"),
            r#"{"dependencies":{"ethers":"1.0"}}"#,
        )
        .unwrap();

        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }
}
