use crate::config::parse_guardian_toml;
use crate::domain::DomainProfile;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

#[derive(Deserialize)]
struct DomainMarkers {
    crypto: Vec<String>,
    healthcare: Vec<String>,
}

use std::sync::OnceLock;

fn get_markers() -> &'static DomainMarkers {
    static MARKERS: OnceLock<DomainMarkers> = OnceLock::new();
    MARKERS.get_or_init(|| {
        let bytes = include_bytes!("../assets/domain-markers.json");
        serde_json::from_slice(bytes).expect("Failed to parse embedded domain-markers.json")
    })
}

fn check_text_for_markers(text: &str, is_crypto: &mut bool, is_healthcare: &mut bool) {
    let text_lower = text.to_lowercase();
    let markers = get_markers();
    for marker in &markers.crypto {
        if text_lower.contains(marker) {
            *is_crypto = true;
        }
    }
    for marker in &markers.healthcare {
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
