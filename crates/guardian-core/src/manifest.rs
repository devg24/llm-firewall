use std::path::{Path, PathBuf};
use serde::Deserialize;
use crate::domain::DomainProfile;

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `workspace` reserved for explicit monorepo member expansion (Epic 4)
struct CargoToml {
    dependencies: Option<toml::Value>,
    #[serde(rename = "dev-dependencies")]
    dev_dependencies: Option<toml::Value>,
    workspace: Option<WorkspaceToml>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields reserved for explicit monorepo member expansion (Epic 4)
struct WorkspaceToml {
    members: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PackageJson {
    dependencies: Option<serde_json::Value>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct GuardianConfig {
    pub regex: Option<RegexConfig>,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegexConfig {
    pub rules: Vec<RegexRule>,
}

#[derive(Debug, Deserialize)]
pub struct RegexRule {
    pub id: String,
    pub pattern: String,
}

pub fn parse_guardian_toml(path: &Path) -> Option<GuardianConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    // Fail-safe fallback on malformed configs
    let config: GuardianConfig = toml::from_str(&content).ok()?;
    
    // ReDoS pre-validation: Rust's regex crate provides O(n) guarantees 
    // by using finite automata rather than backtracking, natively avoiding ReDoS.
    // We validate that they compile successfully here to fail-safe early.
    if let Some(ref regex_cfg) = config.regex {
        for rule in &regex_cfg.rules {
            if regex::Regex::new(&rule.pattern).is_err() {
                // If any custom regex is invalid, we gracefully fallback and ignore the config
                return None; 
            }
        }
    }
    Some(config)
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

    let mut stack: Vec<PathBuf> = vec![workspace_root.to_path_buf()];
    
    while let Some(current_dir) = stack.pop() {
        if !current_dir.exists() || !current_dir.is_dir() {
            continue;
        }

        // Parse Cargo.toml
        let cargo_path = current_dir.join("Cargo.toml");
        if let Ok(content) = std::fs::read_to_string(&cargo_path) {
            if let Ok(cargo) = toml::from_str::<CargoToml>(&content) {
                let deps_json = serde_json::to_string(&cargo.dependencies).unwrap_or_default();
                let dev_deps_json = serde_json::to_string(&cargo.dev_dependencies).unwrap_or_default();
                let deps = format!("{} {}", deps_json, dev_deps_json);
                if deps.contains("ethers") || deps.contains("solana") || deps.contains("web3") {
                    is_crypto = true;
                }
                if deps.contains("healthcare") || deps.contains("fhir") || deps.contains("hl7") {
                    is_healthcare = true;
                }
                // Handle workspaces implicitly by letting the directory walker find sub-crates
                // Or handle explicitly if we want to limit depth
            }
        }

        // Parse package.json
        let pkg_path = current_dir.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            if let Ok(pkg) = serde_json::from_str::<PackageJson>(&content) {
                let deps_json = serde_json::to_string(&pkg.dependencies).unwrap_or_default();
                let dev_deps_json = serde_json::to_string(&pkg.dev_dependencies).unwrap_or_default();
                let deps = format!("{} {}", deps_json, dev_deps_json);
                if deps.contains("ethers") || deps.contains("solana") || deps.contains("web3") {
                    is_crypto = true;
                }
                if deps.contains("healthcare") || deps.contains("fhir") || deps.contains("hl7") {
                    is_healthcare = true;
                }
            }
        }
        
        // Very basic recursion for monorepos (exclude heavy folders)
        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str != "node_modules" && name_str != "target" && name_str != ".git" {
                            stack.push(entry.path());
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
        assert_eq!(detect_domain_from_manifests(dir.path()), DomainProfile::CryptoFintech);
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
        assert_eq!(detect_domain_from_manifests(dir.path()), DomainProfile::Healthcare);
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
        assert_eq!(detect_domain_from_manifests(dir.path()), DomainProfile::Standard);
    }
    
    #[test]
    fn test_monorepo_discovery() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subcrate");
        fs::create_dir(&sub).unwrap();
        let cargo_toml = r#"
        [dependencies]
        solana = "1.0"
        "#;
        fs::write(sub.join("Cargo.toml"), cargo_toml).unwrap();
        assert_eq!(detect_domain_from_manifests(dir.path()), DomainProfile::CryptoFintech);
    }
}
