//! Pre-flight security plan CLI command and interactive approval flow.
//!
//! Provides the `preflight` subcommand for scanning a workspace, generating a bulk
//! approval security plan, rendering terminal summary tables, and persisting `.guardian-plan.json`.

use guardian_core::plan::{
    generate_preflight_plan, PreflightPlan, DEFAULT_MAX_FILE_SIZE, DEFAULT_PER_FILE_TIMEOUT_MS,
};
use std::io::{self, Write};
use std::path::PathBuf;

/// CLI arguments for the `preflight` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightCliArgs {
    /// Workspace root directory to scan (default: `.`).
    pub path: PathBuf,
    /// Auto-approve the generated plan without interactive prompt.
    pub yes: bool,
    /// Output the plan to stdout without writing `.guardian-plan.json`.
    pub dry_run: bool,
    /// Display the current saved pre-flight plan status.
    pub show: bool,
    /// Clear and remove any existing `.guardian-plan.json`.
    pub clear: bool,
    /// Custom path for the pre-flight plan JSON file.
    pub output: Option<PathBuf>,
}

impl Default for PreflightCliArgs {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            yes: false,
            dry_run: false,
            show: false,
            clear: false,
            output: None,
        }
    }
}

/// Parses CLI arguments for the `preflight` subcommand.
///
/// # Errors
/// Returns an error message string if unknown arguments or missing values are encountered.
pub fn parse_preflight_args(args: &[String]) -> Result<PreflightCliArgs, String> {
    let mut parsed = PreflightCliArgs::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-y" | "--yes" => {
                parsed.yes = true;
            }
            "--dry-run" => {
                parsed.dry_run = true;
            }
            "--show" => {
                parsed.show = true;
            }
            "--clear" => {
                parsed.clear = true;
            }
            "-p" | "--path" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --path argument".to_string());
                }
                parsed.path = PathBuf::from(&args[i]);
            }
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --output argument".to_string());
                }
                parsed.output = Some(PathBuf::from(&args[i]));
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--path=") => {
                let val = other.trim_start_matches("--path=");
                parsed.path = PathBuf::from(val);
            }
            other if other.starts_with("-p=") => {
                let val = other.trim_start_matches("-p=");
                parsed.path = PathBuf::from(val);
            }
            other if other.starts_with("--output=") => {
                let val = other.trim_start_matches("--output=");
                parsed.output = Some(PathBuf::from(val));
            }
            other if other.starts_with("-o=") => {
                let val = other.trim_start_matches("-o=");
                parsed.output = Some(PathBuf::from(val));
            }
            other => {
                return Err(format!("Unknown option: '{}'", other));
            }
        }
        i += 1;
    }

    Ok(parsed)
}

/// Prints help information for the `preflight` subcommand.
pub fn print_help() {
    println!(
        r#"llm-firewall preflight — Generate and approve pre-flight security plans

USAGE:
    llm-firewall preflight [OPTIONS]

OPTIONS:
    -p, --path <DIR>       Target workspace directory to scan (default: .)
    -y, --yes              Auto-approve plan without interactive confirmation prompt
        --dry-run          Print formatted plan JSON to stdout without writing to disk
        --show             Inspect and display active .guardian-plan.json status
        --clear            Remove .guardian-plan.json from workspace
    -o, --output <FILE>    Custom path for the pre-flight plan file
    -h, --help             Print help information
"#
    );
}

/// Formats and renders an ANSI terminal summary table of the pre-flight security plan.
pub fn print_preflight_plan_table(plan: &PreflightPlan) {
    println!("================================================================================");
    println!("           LLM FIREWALL — PRE-FLIGHT SECURITY PLAN GENERATION                   ");
    println!("================================================================================");
    println!("Workspace Root: {}", plan.workspace_root.display());
    println!(
        "Sandbox Status: {}",
        if plan.sandbox.enforce_jailing {
            "ENFORCED (Jailed to workspace root)"
        } else {
            "PERMISSIVE"
        }
    );
    println!("--------------------------------------------------------------------------------");

    if plan.sensitive_zones.is_empty() {
        println!("No sensitive file zones detected. Workspace appears clean.");
    } else {
        println!(
            "Found {} sensitive file zone{}:",
            plan.sensitive_zones.len(),
            if plan.sensitive_zones.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        println!();
        println!(
            "  {:<26} {:<28} {:<9} {:<10}",
            "FILE PATH", "SECRET TYPES", "MATCHES", "STRATEGY"
        );
        println!("  -----------------------------------------------------------------------------");

        for zone in &plan.sensitive_zones {
            let path_str = zone.relative_path.display().to_string();
            let truncated_path = if path_str.len() > 24 {
                format!("...{}", &path_str[path_str.len() - 21..])
            } else {
                path_str
            };

            let types_str = format!(
                "[{}]",
                zone.secret_types
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let truncated_types = if types_str.len() > 26 {
                format!("{}...]", &types_str[..22])
            } else {
                types_str
            };

            let strategy_str = match zone.strategy {
                guardian_core::plan::ZoneStrategy::Redact => "Redact",
                guardian_core::plan::ZoneStrategy::Mock => "Mock",
                guardian_core::plan::ZoneStrategy::Block => "Block",
            };

            println!(
                "  {:<26} {:<28} {:<9} {:<10}",
                truncated_path, truncated_types, zone.match_count, strategy_str
            );
        }
    }

    println!();
    println!("Sandbox Boundaries:");
    println!(
        "  - All file access outside {} will be BLOCKED.",
        plan.workspace_root.display()
    );
    println!("  - Symlink breakouts pointing outside workspace root will be QUARANTINED.");
    println!("--------------------------------------------------------------------------------");
}

/// Prompts the user via stdin for approval of the pre-flight plan.
///
/// # Errors
/// Returns [`std::io::Error`] if reading from stdin fails.
pub fn read_approval_from_stdin() -> io::Result<bool> {
    print!("Approve this pre-flight security plan for unattended session? [y/N]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    Ok(trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes"))
}

/// Executes the `preflight` subcommand logic.
///
/// # Errors
/// Returns an error if scanning, reading, writing, or user interaction fails.
pub async fn run_preflight(args: PreflightCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = std::fs::canonicalize(&args.path).unwrap_or(args.path);
    let plan_path = args
        .output
        .unwrap_or_else(|| workspace_root.join(".guardian-plan.json"));

    // 1. Handle --clear
    if args.clear {
        if plan_path.exists() {
            std::fs::remove_file(&plan_path)?;
            println!("🗑️  Cleared {}", plan_path.display());
        } else {
            println!("No pre-flight plan found at {}", plan_path.display());
        }
        return Ok(());
    }

    // 2. Handle --show
    if args.show {
        match PreflightPlan::load_from_file(&plan_path) {
            Ok(Some(plan)) => {
                print_preflight_plan_table(&plan);
                println!(
                    "Plan Status: {}",
                    if plan.approved {
                        "✅ APPROVED (Silent unattended mode enabled)"
                    } else {
                        "⏳ PENDING APPROVAL (Not active)"
                    }
                );
            }
            Ok(None) => {
                println!(
                    "No active pre-flight plan found at {}.\nRun 'llm-firewall preflight' to generate one.",
                    plan_path.display()
                );
            }
            Err(e) => {
                eprintln!("Failed to load pre-flight plan: {}", e);
            }
        }
        return Ok(());
    }

    // 3. Generate new pre-flight security plan
    let mut plan = generate_preflight_plan(
        &workspace_root,
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_PER_FILE_TIMEOUT_MS,
    )?;

    // 4. Handle --dry-run
    if args.dry_run {
        print_preflight_plan_table(&plan);
        println!();
        println!("--- Pre-flight Plan JSON (Dry Run) ---");
        println!("{}", plan.to_json_string()?);
        return Ok(());
    }

    // 5. Render summary table
    print_preflight_plan_table(&plan);

    // 6. Handle approval
    if args.yes {
        plan.approved = true;
        plan.save_to_file(&plan_path)?;
        println!(
            "✅ Pre-flight plan approved and saved to {}.",
            plan_path.file_name().unwrap_or_default().to_string_lossy()
        );
        println!("   Proxy will operate silently within these pre-approved bounds.");
        return Ok(());
    }

    // Interactive approval prompt
    let approved = read_approval_from_stdin()?;
    if approved {
        plan.approved = true;
        plan.save_to_file(&plan_path)?;
        println!(
            "\n✅ Pre-flight plan approved and saved to {}.",
            plan_path.file_name().unwrap_or_default().to_string_lossy()
        );
        println!("   Proxy will operate silently within these pre-approved bounds.");
    } else {
        println!("\n❌ Pre-flight plan rejected. No changes saved.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::plan::{SandboxPolicy, SensitiveZone, ZoneStrategy};
    use guardian_core::PiiType;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_preflight_cli_args_defaults() {
        let args = parse_preflight_args(&[]).unwrap();
        assert_eq!(args.path, Path::new("."));
        assert!(!args.yes);
        assert!(!args.dry_run);
        assert!(!args.show);
        assert!(!args.clear);
        assert_eq!(args.output, None);
    }

    #[test]
    fn test_preflight_cli_args_parsing() {
        let args = parse_preflight_args(&[
            "--path".to_string(),
            "/custom/path".to_string(),
            "-y".to_string(),
            "--dry-run".to_string(),
            "-o".to_string(),
            "/custom/plan.json".to_string(),
        ])
        .unwrap();

        assert_eq!(args.path, Path::new("/custom/path"));
        assert!(args.yes);
        assert!(args.dry_run);
        assert_eq!(args.output, Some(PathBuf::from("/custom/plan.json")));
    }

    #[test]
    fn test_print_preflight_plan_table() {
        let plan = PreflightPlan {
            version: 1,
            workspace_root: PathBuf::from("/tmp/test-workspace"),
            created_at: 1700000000,
            sensitive_zones: vec![SensitiveZone {
                relative_path: PathBuf::from(".env.production"),
                secret_types: vec![PiiType::Aws, PiiType::Bearer],
                match_count: 3,
                strategy: ZoneStrategy::Redact,
            }],
            sandbox: SandboxPolicy {
                root: PathBuf::from("/tmp/test-workspace"),
                enforce_jailing: true,
                allow_subpaths: vec![],
            },
            approved: true,
        };

        // Ensure table printing does not panic
        print_preflight_plan_table(&plan);
    }

    #[tokio::test]
    async fn test_dry_run_does_not_persist_file() {
        let dir = tempdir().unwrap();
        let plan_file = dir.path().join(".guardian-plan.json");

        let args = PreflightCliArgs {
            path: dir.path().to_path_buf(),
            dry_run: true,
            output: Some(plan_file.clone()),
            ..Default::default()
        };

        let result = run_preflight(args).await;
        assert!(result.is_ok());
        assert!(!plan_file.exists());
    }

    #[tokio::test]
    async fn test_yes_flag_persists_approved_plan() {
        let dir = tempdir().unwrap();
        let plan_file = dir.path().join(".guardian-plan.json");

        let args = PreflightCliArgs {
            path: dir.path().to_path_buf(),
            yes: true,
            output: Some(plan_file.clone()),
            ..Default::default()
        };

        let result = run_preflight(args).await;
        assert!(result.is_ok());
        assert!(plan_file.exists());

        let loaded = PreflightPlan::load_from_file(&plan_file).unwrap();
        assert!(loaded.is_some());
        assert!(loaded.unwrap().approved);
    }
}
