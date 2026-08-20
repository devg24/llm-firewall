#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "scan" {
        let config = guardian_cli::scanner::ScannerConfig::default();
        let findings = guardian_cli::scanner::run_scan(&config).await;
        guardian_cli::scanner::print_report(&findings);
        return;
    }

    if args.len() > 1 && args[1] == "on" {
        guardian_cli::run_server_with_trust().await;
    } else {
        guardian_cli::run_server().await;
    }
}
