//! Pre-flight security plan generation and workspace sandbox boundary enforcement.
//!
//! This module provides:
//! - Strongly-typed data models for pre-flight security plans ([`PreflightPlan`]),
//!   sensitive workspace zones ([`SensitiveZone`]), strategies ([`ZoneStrategy`]),
//!   and sandbox boundaries ([`SandboxPolicy`]).
//! - Workspace scanner ([`generate_preflight_plan`]) identifying secret tokens and high-risk files.
//! - Canonical sandbox path validation ([`validate_sandbox_path`]) preventing directory traversal
//!   and symlink breakout attacks.

use crate::error::CoreError;
use crate::redact::{collect_regex_matches, init_regexes, PiiType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Default maximum file size scanned during pre-flight plan generation (5 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Default per-file timeout in milliseconds (500 ms).
pub const DEFAULT_PER_FILE_TIMEOUT_MS: u64 = 500;

/// Mitigation strategy for a sensitive workspace zone.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneStrategy {
    /// Replace detected secrets with reversible token placeholders.
    Redact,
    /// Replace detected secrets with deterministic synthetic mock values.
    Mock,
    /// Block requests or tool calls accessing this zone entirely.
    Block,
}

/// A predicted sensitive zone (file path and detected secret categories) within the workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensitiveZone {
    /// Path of the file relative to the workspace root.
    pub relative_path: PathBuf,
    /// Types of sensitive tokens/secrets detected in this zone.
    pub secret_types: Vec<PiiType>,
    /// Total count of secret matches discovered.
    pub match_count: usize,
    /// Mitigation strategy assigned to this zone.
    pub strategy: ZoneStrategy,
}

/// Strict directory boundary policy for sandbox jailing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Canonical root directory of the workspace sandbox.
    pub root: PathBuf,
    /// Whether out-of-boundary access is strictly prohibited.
    pub enforce_jailing: bool,
    /// Optional allowed subpaths or exceptions within or outside the root.
    #[serde(default)]
    pub allow_subpaths: Vec<PathBuf>,
}

impl SandboxPolicy {
    /// Validates a target path against this sandbox policy.
    ///
    /// # Errors
    /// Returns [`SandboxViolation`] if `enforce_jailing` is active and the target escapes the sandbox.
    pub fn validate_path(&self, target: &Path) -> Result<PathBuf, SandboxViolation> {
        if !self.enforce_jailing {
            return Ok(target.to_path_buf());
        }
        let canonical_target = validate_sandbox_path(target, &self.root)?;

        // If allow_subpaths is specified, verify target is inside root or an allowed subpath
        if !self.allow_subpaths.is_empty() {
            let canonical_root = std::fs::canonicalize(&self.root).map_err(|e| {
                SandboxViolation::InvalidPath(format!("Failed to canonicalize root: {}", e))
            })?;
            let inside_subpath = self.allow_subpaths.iter().any(|sub| {
                if let Ok(canon_sub) = std::fs::canonicalize(sub) {
                    canonical_target.starts_with(&canon_sub)
                } else {
                    false
                }
            });
            if !canonical_target.starts_with(&canonical_root) && !inside_subpath {
                return Err(SandboxViolation::OutsideWorkspaceBoundary {
                    target: canonical_target,
                    root: canonical_root,
                });
            }
        }

        Ok(canonical_target)
    }
}

/// Errors occurring during sandbox path boundary validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    /// The target path is located outside the allowed workspace boundary.
    OutsideWorkspaceBoundary {
        /// Canonical or normalized target path attempted.
        target: PathBuf,
        /// Canonical workspace root.
        root: PathBuf,
    },
    /// A symlink dereferences to a target outside the workspace boundary.
    SymlinkBreakout {
        /// The symlink path inside the workspace.
        symlink: PathBuf,
        /// The physical target the symlink points to.
        target: PathBuf,
        /// Canonical workspace root.
        root: PathBuf,
    },
    /// The path could not be parsed, canonicalized, or is invalid.
    InvalidPath(String),
}

impl fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxViolation::OutsideWorkspaceBoundary { target, root } => {
                write!(
                    f,
                    "Path '{}' is outside workspace boundary '{}'",
                    target.display(),
                    root.display()
                )
            }
            SandboxViolation::SymlinkBreakout {
                symlink,
                target,
                root,
            } => {
                write!(
                    f,
                    "Symlink '{}' resolves to '{}' which escapes workspace root '{}'",
                    symlink.display(),
                    target.display(),
                    root.display()
                )
            }
            SandboxViolation::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
        }
    }
}

impl std::error::Error for SandboxViolation {}

/// Represents a pre-flight security plan for unattended AI agent execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreflightPlan {
    /// Schema version of the pre-flight plan (default `1`).
    pub version: u32,
    /// Canonicalized absolute root path of the scanned workspace.
    pub workspace_root: PathBuf,
    /// Unix timestamp (seconds) when the plan was created.
    pub created_at: u64,
    /// List of predicted sensitive zones found in the workspace.
    pub sensitive_zones: Vec<SensitiveZone>,
    /// Sandbox boundary and enforcement policy.
    pub sandbox: SandboxPolicy,
    /// Whether the plan has been reviewed and approved for silent unattended operation.
    pub approved: bool,
}

impl PreflightPlan {
    /// Parses a [`PreflightPlan`] from a JSON string.
    ///
    /// # Errors
    /// Returns [`CoreError::Serialization`] if parsing fails.
    pub fn from_json_str(s: &str) -> Result<Self, CoreError> {
        serde_json::from_str(s).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Serializes this [`PreflightPlan`] to a formatted JSON string.
    ///
    /// # Errors
    /// Returns [`CoreError::Serialization`] if serialization fails.
    pub fn to_json_string(&self) -> Result<String, CoreError> {
        serde_json::to_string_pretty(self).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Loads a [`PreflightPlan`] from a file on disk.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    ///
    /// # Errors
    /// Returns [`CoreError::Serialization`] or [`CoreError::Internal`] if reading or parsing fails.
    pub fn load_from_file(path: &Path) -> Result<Option<Self>, CoreError> {
        if !path.exists() {
            return Ok(None);
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(path = ?path, error = %e, "Failed to read preflight plan file");
                return Err(CoreError::Serialization(format!(
                    "Failed to read preflight plan: {}",
                    e
                )));
            }
        };
        match Self::from_json_str(&content) {
            Ok(plan) => Ok(Some(plan)),
            Err(e) => {
                tracing::warn!(path = ?path, error = %e, "Malformed preflight plan file");
                Err(e)
            }
        }
    }

    /// Saves this [`PreflightPlan`] to a file on disk, creating parent directories if necessary.
    ///
    /// # Errors
    /// Returns [`CoreError::Serialization`] or [`CoreError::Internal`] if saving fails.
    pub fn save_to_file(&self, path: &Path) -> Result<(), CoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    CoreError::Internal(format!("Failed to create parent directories: {}", e))
                })?;
            }
        }
        let json_str = self.to_json_string()?;
        std::fs::write(path, json_str)
            .map_err(|e| CoreError::Internal(format!("Failed to write preflight plan file: {}", e)))
    }
}

/// Canonicalizes a path using the filesystem.
///
/// # Errors
/// Returns [`std::io::Error`] if the path cannot be canonicalized.
pub fn canonicalize_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    std::fs::canonicalize(path)
}

/// Safely resolves and normalizes a non-existent virtual target path relative to a canonical root.
///
/// Ensures no `..` traversal escapes the canonical sandbox root.
///
/// # Errors
/// Returns [`SandboxViolation`] if the path escapes the sandbox root.
pub fn normalize_virtual_path(path: &Path, root: &Path) -> Result<PathBuf, SandboxViolation> {
    // 1. Find deepest existing ancestor directory
    let mut current = path.to_path_buf();
    let mut existing_ancestor = None;

    loop {
        if current.exists() {
            existing_ancestor = Some(current.clone());
            break;
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let (base_canonical, relative_tail) = match existing_ancestor {
        Some(anc) => {
            let canon = std::fs::canonicalize(&anc).map_err(|e| {
                SandboxViolation::InvalidPath(format!("Failed to canonicalize ancestor: {}", e))
            })?;
            let rel = path.strip_prefix(&anc).unwrap_or(path).to_path_buf();
            (canon, rel)
        }
        None => {
            if path.is_absolute() {
                return Err(SandboxViolation::OutsideWorkspaceBoundary {
                    target: path.to_path_buf(),
                    root: root.to_path_buf(),
                });
            }
            let rel = path.to_path_buf();
            (root.to_path_buf(), rel)
        }
    };

    if !base_canonical.starts_with(root) {
        return Err(SandboxViolation::OutsideWorkspaceBoundary {
            target: base_canonical,
            root: root.to_path_buf(),
        });
    }

    // 2. Lexically normalize remaining components on top of base_canonical
    let mut normalized = base_canonical;
    for component in relative_tail.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized == root || !normalized.starts_with(root) {
                    return Err(SandboxViolation::OutsideWorkspaceBoundary {
                        target: normalized.join(".."),
                        root: root.to_path_buf(),
                    });
                }
                normalized.pop();
            }
            Component::Normal(c) => {
                normalized.push(c);
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    if normalized.starts_with(root) {
        Ok(normalized)
    } else {
        Err(SandboxViolation::OutsideWorkspaceBoundary {
            target: normalized,
            root: root.to_path_buf(),
        })
    }
}

/// Validates that a target path resides within the workspace sandbox boundary.
///
/// Resolves symlinks and checks boundary containment. If the target does not exist,
/// normalizes prospective subpaths safely.
///
/// # Errors
/// Returns [`SandboxViolation::OutsideWorkspaceBoundary`] or [`SandboxViolation::SymlinkBreakout`]
/// if the target escapes the sandbox root.
pub fn validate_sandbox_path(target: &Path, root: &Path) -> Result<PathBuf, SandboxViolation> {
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        SandboxViolation::InvalidPath(format!("Failed to canonicalize root: {}", e))
    })?;

    let absolute_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        canonical_root.join(target)
    };

    if absolute_target.exists() {
        let is_symlink = match std::fs::symlink_metadata(&absolute_target) {
            Ok(meta) => meta.file_type().is_symlink(),
            Err(_) => false,
        };

        let canonical_target = std::fs::canonicalize(&absolute_target).map_err(|e| {
            SandboxViolation::InvalidPath(format!("Failed to canonicalize target: {}", e))
        })?;

        if canonical_target.starts_with(&canonical_root) {
            Ok(canonical_target)
        } else if is_symlink {
            Err(SandboxViolation::SymlinkBreakout {
                symlink: absolute_target,
                target: canonical_target,
                root: canonical_root,
            })
        } else {
            Err(SandboxViolation::OutsideWorkspaceBoundary {
                target: canonical_target,
                root: canonical_root,
            })
        }
    } else {
        normalize_virtual_path(&absolute_target, &canonical_root)
    }
}

/// Helper returning `true` if `target` resides within the `root` sandbox boundary.
pub fn is_path_within_sandbox(target: &Path, root: &Path) -> bool {
    validate_sandbox_path(target, root).is_ok()
}

/// Scans a workspace directory and generates a pre-flight security plan predicting sensitive zones.
///
/// Respects `.gitignore`, `.ignore`, and standard ignored build/cache directories.
///
/// # Errors
/// Returns [`CoreError`] if scanning encounters fatal errors.
pub fn generate_preflight_plan(
    workspace_root: &Path,
    max_file_size: u64,
    _per_file_timeout_ms: u64,
) -> Result<PreflightPlan, CoreError> {
    init_regexes();

    let canonical_root =
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf());

    let mut builder = ignore::WalkBuilder::new(&canonical_root);
    builder
        .hidden(false)
        .parents(true)
        .ignore(true)
        .git_global(true)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .filter_entry(|entry| {
            if let Some(name) = entry.file_name().to_str() {
                let ignored_dirs = [
                    "target",
                    "node_modules",
                    ".git",
                    ".venv",
                    ".cargo",
                    "dist",
                    "build",
                    "vendor",
                    ".turbo",
                    ".next",
                    ".llm-firewall-certs",
                ];
                if entry.file_type().is_some_and(|ft| ft.is_dir()) && ignored_dirs.contains(&name) {
                    return false;
                }
            }
            true
        });

    let mut sensitive_zones = Vec::new();

    for entry in builder.build().flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            let path = entry.into_path();

            if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                if metadata.len() > max_file_size {
                    continue;
                }
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            let is_high_risk_name = file_name.starts_with(".env")
                || file_name.ends_with(".pem")
                || file_name.ends_with(".key")
                || file_name.ends_with(".pfx")
                || file_name.ends_with(".p12")
                || file_name.ends_with(".pkcs12")
                || file_name.starts_with("credentials.")
                || file_name.starts_with("id_rsa")
                || file_name.starts_with("id_ed25519")
                || file_name.starts_with("id_ecdsa")
                || file_name.starts_with("id_dsa");

            let mut type_counts: HashMap<PiiType, usize> = HashMap::new();

            if let Ok(content) = std::fs::read_to_string(&path) {
                let matches = collect_regex_matches(&content);
                for m in matches {
                    *type_counts.entry(m.pii_type).or_insert(0) += 1;
                }
            }

            if !type_counts.is_empty() || is_high_risk_name {
                let mut secret_types: Vec<PiiType> = type_counts.keys().copied().collect();
                secret_types.sort_by_key(|t| t.as_str());
                if secret_types.is_empty() && is_high_risk_name {
                    secret_types.push(PiiType::Custom);
                }

                let total_matches: usize = type_counts.values().sum();
                let match_count = if total_matches == 0 && is_high_risk_name {
                    1
                } else {
                    total_matches
                };

                let relative_path = path
                    .strip_prefix(&canonical_root)
                    .unwrap_or(&path)
                    .to_path_buf();

                sensitive_zones.push(SensitiveZone {
                    relative_path,
                    secret_types,
                    match_count,
                    strategy: ZoneStrategy::Redact,
                });
            }
        }
    }

    sensitive_zones.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(PreflightPlan {
        version: 1,
        workspace_root: canonical_root.clone(),
        created_at: now,
        sensitive_zones,
        sandbox: SandboxPolicy {
            root: canonical_root,
            enforce_jailing: true,
            allow_subpaths: Vec::new(),
        },
        approved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_preflight_plan_serialization_roundtrip() {
        let plan = PreflightPlan {
            version: 1,
            workspace_root: PathBuf::from("/test/workspace"),
            created_at: 1700000000,
            sensitive_zones: vec![
                SensitiveZone {
                    relative_path: PathBuf::from(".env.production"),
                    secret_types: vec![PiiType::Aws, PiiType::Bearer],
                    match_count: 5,
                    strategy: ZoneStrategy::Redact,
                },
                SensitiveZone {
                    relative_path: PathBuf::from("config/db.json"),
                    secret_types: vec![PiiType::Custom],
                    match_count: 2,
                    strategy: ZoneStrategy::Mock,
                },
            ],
            sandbox: SandboxPolicy {
                root: PathBuf::from("/test/workspace"),
                enforce_jailing: true,
                allow_subpaths: vec![PathBuf::from("/test/workspace/extra")],
            },
            approved: true,
        };

        let json = plan.to_json_string().unwrap();
        let parsed = PreflightPlan::from_json_str(&json).unwrap();
        assert_eq!(plan, parsed);
    }

    #[test]
    fn test_generate_preflight_plan_detects_secrets() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // 1. Create a .env file with an AWS secret
        let mut env_file = File::create(root.join(".env")).unwrap();
        writeln!(
            env_file,
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        .unwrap();

        // 2. Create a clean file
        let mut clean_file = File::create(root.join("main.rs")).unwrap();
        writeln!(clean_file, "fn main() {{ println!(\"Hello\"); }}").unwrap();

        // 3. Create a high-risk key file
        let mut key_file = File::create(root.join("server.key")).unwrap();
        writeln!(key_file, "DUMMY_KEY_CONTENT").unwrap();

        let plan =
            generate_preflight_plan(root, DEFAULT_MAX_FILE_SIZE, DEFAULT_PER_FILE_TIMEOUT_MS)
                .unwrap();

        assert_eq!(plan.sensitive_zones.len(), 2);
        let paths: Vec<String> = plan
            .sensitive_zones
            .iter()
            .map(|z| z.relative_path.to_str().unwrap().to_string())
            .collect();
        assert!(paths.contains(&".env".to_string()));
        assert!(paths.contains(&"server.key".to_string()));
    }

    #[test]
    fn test_validate_sandbox_path_inside_workspace() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let file_path = root.join("src/lib.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        File::create(&file_path).unwrap();

        let result = validate_sandbox_path(&file_path, root);
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with(std::fs::canonicalize(root).unwrap()));
    }

    #[test]
    fn test_validate_sandbox_path_rejects_traversal() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let traversal = PathBuf::from("../../etc/passwd");
        let result = validate_sandbox_path(&traversal, root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::OutsideWorkspaceBoundary { .. } => {}
            other => panic!("Expected OutsideWorkspaceBoundary, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_sandbox_path_symlink_breakout() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let external_dir = tempdir().unwrap();
        let external_file = external_dir.path().join("secret.txt");
        File::create(&external_file).unwrap();

        let symlink_path = root.join("external_link");
        std::os::unix::fs::symlink(&external_file, &symlink_path).unwrap();

        let result = validate_sandbox_path(&symlink_path, root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::SymlinkBreakout { .. } => {}
            other => panic!("Expected SymlinkBreakout, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_sandbox_path_nonexistent_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let non_existent = root.join("future_dir/future_file.txt");
        let result = validate_sandbox_path(&non_existent, root);
        assert!(result.is_ok());
        let canonical_root = std::fs::canonicalize(root).unwrap();
        assert!(result.unwrap().starts_with(&canonical_root));

        // Non-existent traversal breakout
        let non_existent_escape = root.join("subdir/../../../../etc/shadow");
        let escape_result = validate_sandbox_path(&non_existent_escape, root);
        assert!(escape_result.is_err());
    }

    #[test]
    fn test_load_and_save_preflight_plan() {
        let dir = tempdir().unwrap();
        let plan_file = dir.path().join(".guardian-plan.json");

        assert_eq!(PreflightPlan::load_from_file(&plan_file).unwrap(), None);

        let plan = PreflightPlan {
            version: 1,
            workspace_root: dir.path().to_path_buf(),
            created_at: 12345678,
            sensitive_zones: vec![],
            sandbox: SandboxPolicy {
                root: dir.path().to_path_buf(),
                enforce_jailing: true,
                allow_subpaths: vec![],
            },
            approved: true,
        };

        plan.save_to_file(&plan_file).unwrap();
        let loaded = PreflightPlan::load_from_file(&plan_file).unwrap();
        assert!(loaded.is_some());
        assert!(loaded.unwrap().approved);
    }
}
