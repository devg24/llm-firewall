#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "scan" => {
                let config = guardian_cli::scanner::ScannerConfig::default();
                let findings = guardian_cli::scanner::run_scan(&config).await;
                guardian_cli::scanner::print_report(&findings);
                return;
            }
            "preflight" => {
                let preflight_args = guardian_cli::preflight::parse_preflight_args(&args[2..])
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                if let Err(e) = guardian_cli::preflight::run_preflight(preflight_args).await {
                    eprintln!("Preflight failed: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "stats" => {
                let stats_args =
                    guardian_cli::stats::parse_stats_args(&args[2..]).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                if let Err(e) = guardian_cli::stats::run_stats(stats_args) {
                    eprintln!("Stats error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "report" => {
                let report_args = guardian_cli::report::parse_report_args(&args[2..])
                    .unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                if let Err(e) = guardian_cli::report::run_report(report_args) {
                    eprintln!("Report error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "on" => {
                guardian_cli::run_server_with_trust().await;
                return;
            }
            "--help" | "-h" => {
                println!("LLM Firewall — Security & Compliance Proxy for Local LLMs");
                println!();
                println!("USAGE:");
                println!("    guardian [COMMAND] [OPTIONS]");
                println!();
                println!("COMMANDS:");
                println!("    scan                  Scan repository for unprotected secrets and sensitive files");
                println!("    preflight             Generate or approve an unattended pre-flight security plan");
                println!("    stats                 Display aggregate security metrics and estimated risk avoided");
                println!("    report                Generate SOC 2 / HIPAA / GDPR compliance audit reports");
                println!("    on                    Start transparent MITM proxy with automatic CA installation");
                println!("    [default]             Start standard proxy server");
                return;
            }
            _ => {}
        }
    }

    guardian_cli::run_server().await;
}
