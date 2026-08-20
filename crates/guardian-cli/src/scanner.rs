use guardian_core::{collect_regex_matches, init_regexes, PiiType};
use ignore::WalkBuilder;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

pub const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
pub const PER_FILE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct ScannerConfig {
    pub root: PathBuf,
    pub max_file_size: u64,
    pub per_file_timeout: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            max_file_size: MAX_FILE_SIZE,
            per_file_timeout: PER_FILE_TIMEOUT,
        }
    }
}

pub fn discover_files(config: &ScannerConfig) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let walker = WalkBuilder::new(&config.root)
        .hidden(false)
        .parents(true)
        .ignore(true)
        .git_global(true)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .build();

    for entry in walker.flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() <= config.max_file_size {
                    files.push(entry.into_path());
                }
            }
        }
    }
    files
}

pub struct ScanFinding {
    pub file: PathBuf,
    pub pii_type: PiiType,
    pub count: usize,
}

pub async fn run_scan(config: &ScannerConfig) -> Vec<ScanFinding> {
    init_regexes();
    let config_clone = config.clone();
    let files = tokio::task::spawn_blocking(move || discover_files(&config_clone))
        .await
        .unwrap_or_default();

    let mut findings = Vec::new();

    let mut tasks = Vec::new();
    for file_path in files {
        let timeout_dur = config.per_file_timeout;
        tasks.push(tokio::spawn(async move {
            let res = tokio::time::timeout(timeout_dur, async {
                let content_res = tokio::fs::read_to_string(&file_path).await;
                if let Ok(content) = content_res {
                    // CPU bound regex scan
                    tokio::task::spawn_blocking(move || {
                        let matches = collect_regex_matches(&content);
                        let mut counts = HashMap::new();
                        for m in matches {
                            *counts.entry(m.pii_type).or_insert(0) += 1;
                        }
                        counts
                    })
                    .await
                    .unwrap_or_default()
                } else {
                    HashMap::new()
                }
            })
            .await;

            match res {
                Ok(counts) => (file_path, counts),
                Err(_) => (file_path, HashMap::new()), // timeout
            }
        }));
    }

    for task in tasks {
        if let Ok((file_path, counts)) = task.await {
            for (pii_type, count) in counts {
                findings.push(ScanFinding {
                    file: file_path.clone(),
                    pii_type,
                    count,
                });
            }
        }
    }

    findings
}

pub fn calculate_breach_cost(findings: &[ScanFinding]) -> u64 {
    let mut total_cost = 0;
    for finding in findings {
        let cost = match finding.pii_type {
            PiiType::Aws => 5000,
            PiiType::Gcp => 5000,
            PiiType::Github => 2000,
            PiiType::Cc => 500,
            PiiType::Email => 10,
            PiiType::Phone => 10,
            PiiType::Ssn => 1000,
            _ => 10,
        };
        total_cost += cost * finding.count as u64;
    }
    total_cost
}

pub fn print_report(findings: &[ScanFinding]) {
    if findings.is_empty() {
        println!("No secrets found. Great job!");
        return;
    }
    println!("=== First-Run Scare Report ===");

    for finding in findings {
        println!(
            "File: {} | Type: {:?} | Count: {}",
            finding.file.display(),
            finding.pii_type,
            finding.count
        );
    }

    let total_cost = calculate_breach_cost(findings);
    println!("------------------------------");
    println!("Estimated Breach Cost: ${}", total_cost);
    println!("==============================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_discover_files_respects_gitignore() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let mut file1 = File::create(root.join("file1.txt")).unwrap();
        writeln!(file1, "test").unwrap();

        let mut file2 = File::create(root.join("secret.key")).unwrap();
        writeln!(file2, "secret").unwrap();

        let mut gitignore = File::create(root.join(".gitignore")).unwrap();
        writeln!(gitignore, "*.key").unwrap();

        let config = ScannerConfig {
            root: root.to_path_buf(),
            ..Default::default()
        };

        let files = discover_files(&config);

        let file_names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();

        assert!(file_names.contains(&"file1.txt".to_string()));
        assert!(!file_names.contains(&"secret.key".to_string()));
    }

    #[test]
    fn test_discover_files_respects_size_limit() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let mut file1 = File::create(root.join("small.txt")).unwrap();
        writeln!(file1, "small").unwrap();

        let mut file2 = File::create(root.join("large.txt")).unwrap();
        let data = vec![0u8; 1024];
        file2.write_all(&data).unwrap();

        let config = ScannerConfig {
            root: root.to_path_buf(),
            max_file_size: 512,
            ..Default::default()
        };

        let files = discover_files(&config);

        let file_names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();

        assert!(file_names.contains(&"small.txt".to_string()));
        assert!(!file_names.contains(&"large.txt".to_string()));
    }

    #[test]
    fn test_calculate_breach_cost() {
        let findings = vec![
            ScanFinding {
                file: PathBuf::from("test1"),
                pii_type: PiiType::Aws,
                count: 2, // 2 * 5000 = 10000
            },
            ScanFinding {
                file: PathBuf::from("test2"),
                pii_type: PiiType::Github,
                count: 1, // 1 * 2000 = 2000
            },
        ];
        let cost = calculate_breach_cost(&findings);
        assert_eq!(cost, 12000);
    }
}
