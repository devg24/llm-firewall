//! `guardian-cli` — Command-line interface and main entrypoint for LLM Firewall.
//!
//! This crate provides:
//! - Environment variable parsing (`PORT`, `UPSTREAM_URL`, `MODEL_DIR`)
//! - Logging initialization via `tracing-subscriber`
//! - The main server runtime function [`run_server`]

use guardian_core::ml;
use guardian_proxy::{create_app, AppState};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod ca;
pub mod exec;
pub mod patcher;
pub mod preflight;
pub mod report;
pub mod scanner;
pub mod stats;
/// Initializes stdout logging with an `EnvFilter` defaulting to `"info"`.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .try_init();
}

/// Parses the port string from environment or returns default `3000`.
pub fn parse_port(port_env: Option<String>) -> Result<u16, String> {
    match port_env {
        Some(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                Ok(3000)
            } else {
                trimmed
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port '{}': {}", trimmed, e))
            }
        }
        None => Ok(3000),
    }
}

/// Parses the `UPSTREAM_URL` environment variable or returns default `https://api.openai.com`.
pub fn parse_upstream_url(
    url_env: Result<String, std::env::VarError>,
) -> Result<reqwest::Url, String> {
    match url_env {
        Ok(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                reqwest::Url::parse("https://api.openai.com").map_err(|e| e.to_string())
            } else {
                let parsed = reqwest::Url::parse(trimmed)
                    .map_err(|e| format!("Invalid UPSTREAM_URL '{}': {}", trimmed, e))?;
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    return Err(format!(
                        "Invalid UPSTREAM_URL '{}': Scheme must be http or https",
                        trimmed
                    ));
                }
                if parsed.host().is_none() {
                    return Err(format!("Invalid UPSTREAM_URL '{}': Missing host", trimmed));
                }
                Ok(parsed)
            }
        }
        Err(std::env::VarError::NotPresent) => {
            reqwest::Url::parse("https://api.openai.com").map_err(|e| e.to_string())
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("UPSTREAM_URL environment variable is not valid unicode".to_string())
        }
    }
}

/// Runs the firewall proxy server, reading configuration from environment variables.
pub async fn run_server() {
    init_logging();
    run_server_internal().await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Graceful shutdown initiated...");
}

async fn run_server_internal() {
    guardian_core::init_regexes();

    let port_var = match std::env::var("PORT") {
        Ok(val) => Some(val),
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::error!("Fatal: PORT environment variable is not valid unicode");
            return;
        }
        Err(std::env::VarError::NotPresent) => None,
    };

    let port = parse_port(port_var).unwrap_or_else(|e| {
        tracing::error!("Fatal: {}", e);
        std::process::exit(1);
    });

    let upstream_var = std::env::var("UPSTREAM_URL");
    let upstream_url = parse_upstream_url(upstream_var).unwrap_or_else(|e| {
        tracing::error!("Fatal: {}", e);
        std::process::exit(1);
    });

    let (state, telemetry_writer) = match build_app_state(upstream_url) {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Fatal: Failed to initialize application state: {}", e);
            std::process::exit(1);
        }
    };

    let telemetry_tx = state.telemetry_tx.clone();
    let app = create_app(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to port {}: {}", port, e);
            return;
        }
    };

    let bound_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!(
        "Server started successfully and listening on {}",
        bound_addr
    );

    guardian_proxy::connect::accept_loop(listener, app, state, shutdown_signal()).await;

    drop(telemetry_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), telemetry_writer.handle).await;
}

/// Builds the shared [`AppState`] and initializes the audit telemetry writer.
pub fn build_app_state(
    upstream_url: reqwest::Url,
) -> Result<(AppState, guardian_core::telemetry::TelemetryWriter), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(300))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()?;

    let mut model_dir = std::env::var("MODEL_DIR")
        .unwrap_or_default()
        .trim()
        .to_string();
    if model_dir.is_empty() {
        model_dir = "./model".to_string();
    }
    let model_path = std::path::Path::new(&model_dir);
    let shared_model = if model_path.exists() {
        match ml::SharedModel::load_from_dir(model_path) {
            Ok(m) => {
                tracing::info!("Successfully loaded BERT model from {}", model_dir);
                Some(std::sync::Arc::new(m))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load ML model from {}: {}. Continuing in regex-only mode.",
                    model_dir,
                    e
                );
                None
            }
        }
    } else {
        tracing::info!(
            "Model directory '{}' not found. Running in regex-only mode.",
            model_dir
        );
        None
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let guardian_toml_path = cwd.join(".guardian.toml");
    let guardian_config = guardian_core::manifest::parse_guardian_toml(&guardian_toml_path);
    if guardian_config.is_some() {
        tracing::info!(path = ?guardian_toml_path, "Loaded custom .guardian.toml configuration");
    }

    let domain = guardian_core::manifest::detect_domain_from_manifests(&cwd);
    tracing::info!(
        domain = ?domain,
        entropy_threshold = domain.thresholds().entropy_tier,
        "Active project domain profile"
    );

    let preflight_plan_path = cwd.join(".guardian-plan.json");
    let preflight_plan =
        match guardian_core::plan::PreflightPlan::load_from_file(&preflight_plan_path) {
            Ok(Some(plan)) if plan.approved => {
                tracing::info!(
                    version = plan.version,
                    zones = plan.sensitive_zones.len(),
                    "Loaded active pre-flight security plan (.guardian-plan.json)"
                );
                Some(std::sync::Arc::new(plan))
            }
            Ok(Some(_)) => {
                tracing::warn!(
                ".guardian-plan.json exists but is not approved. Operating without preflight plan."
            );
                None
            }
            Ok(None) => None,
            Err(e) => {
                return Err(format!(".guardian-plan.json is corrupt or unreadable: {}", e).into());
            }
        };

    let audit_log_path = guardian_core::telemetry::default_audit_log_path();
    let (telemetry_tx, telemetry_writer) =
        guardian_core::telemetry::TelemetryWriter::new(audit_log_path);

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let cert_dir = std::path::PathBuf::from(home).join(".llm-firewall-certs");
    let ca_key_pair = ca::LocalCA::load_key_pair(&cert_dir)
        .ok()
        .map(std::sync::Arc::new);
    let ca_cert_der = ca::LocalCA::load_cert_der(&cert_dir)
        .ok()
        .map(std::sync::Arc::new);

    let state = AppState {
        client,
        upstream_url,
        model: shared_model,
        domain,
        guardian_config,
        preflight_plan,
        telemetry_tx: Some(telemetry_tx),
        ca_key_pair,
        ca_cert_der,
    };

    Ok((state, telemetry_writer))
}

/// A running ephemeral proxy server instance.
pub struct EphemeralServer {
    /// Port number the ephemeral server is listening on.
    pub port: u16,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_handle: tokio::task::JoinHandle<()>,
}

impl EphemeralServer {
    /// Gracefully stops the ephemeral server.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.server_handle.await;
    }
}

/// Starts an ephemeral proxy server on `127.0.0.1:<port>` (pass 0 for OS-assigned port).
pub async fn start_ephemeral_server(
    port: u16,
) -> Result<EphemeralServer, Box<dyn std::error::Error>> {
    guardian_core::init_regexes();

    let upstream_var = std::env::var("UPSTREAM_URL");
    let upstream_url = parse_upstream_url(upstream_var)
        .unwrap_or_else(|_| reqwest::Url::parse("https://api.openai.com").unwrap());

    let (state, telemetry_writer) = build_app_state(upstream_url)?;
    let telemetry_tx = state.telemetry_tx.clone();

    let app = create_app(state.clone());
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_port = listener.local_addr()?.port();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        guardian_proxy::connect::accept_loop(listener, app, state, async move {
            let _ = shutdown_rx.await;
        })
        .await;
        drop(telemetry_tx);
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), telemetry_writer.handle).await;
    });

    Ok(EphemeralServer {
        port: bound_port,
        shutdown_tx: Some(shutdown_tx),
        server_handle,
    })
}

pub async fn run_server_with_trust() {
    init_logging();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let ca_dir = std::path::PathBuf::from(home);
    let cert_dir = ca_dir.join(".llm-firewall-certs");

    let ca = match ca::LocalCA::new(&cert_dir) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to generate CA: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = ca.trust() {
        tracing::error!("Failed to trust CA: {}", e);
        std::process::exit(1);
    }

    tracing::info!("CA certificate trusted.");

    struct OrchestratorGuard {
        ca: ca::LocalCA,
        patcher: patcher::ConfigPatcher,
    }

    impl Drop for OrchestratorGuard {
        fn drop(&mut self) {
            tracing::info!("Untrusting CA...");
            if let Err(e) = self.ca.untrust() {
                tracing::error!("Failed to untrust CA: {}", e);
            } else {
                tracing::info!("CA certificate untrusted.");
            }

            tracing::info!("Restoring IDE configs...");
            if let Err(e) = self.patcher.restore() {
                tracing::error!("Failed to restore IDE configs: {}", e);
            } else {
                tracing::info!("IDE configs restored.");
            }
        }
    }

    let port_var = std::env::var("PORT").ok();
    let port = parse_port(port_var).unwrap_or(3000);

    let mut config_patcher = patcher::ConfigPatcher::new();
    if let Err(e) = config_patcher.patch(port) {
        tracing::error!("Failed to patch IDE configs: {}", e);
        // Fail open or fail closed? Story says "Fail-closed security posture (if patching fails, exit cleanly without running the proxy or inform the user)."
        std::process::exit(1);
    }

    let _guard = OrchestratorGuard {
        ca: ca::LocalCA {
            cert_path: ca.cert_path.clone(),
        },
        patcher: config_patcher,
    };

    run_server_internal().await;
}

/// Main CLI entrypoint that parses command-line arguments and dispatches subcommands.
pub async fn run_cli() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "scan" => {
                let config = scanner::ScannerConfig::default();
                let findings = scanner::run_scan(&config).await;
                scanner::print_report(&findings);
                return;
            }
            "preflight" => {
                let preflight_args =
                    preflight::parse_preflight_args(&args[2..]).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    });
                if let Err(e) = preflight::run_preflight(preflight_args).await {
                    eprintln!("Preflight failed: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "stats" => {
                let stats_args = stats::parse_stats_args(&args[2..]).unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                });
                if let Err(e) = stats::run_stats(stats_args) {
                    eprintln!("Stats error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "report" => {
                let report_args = report::parse_report_args(&args[2..]).unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                });
                if let Err(e) = report::run_report(report_args) {
                    eprintln!("Report error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "on" => {
                run_server_with_trust().await;
                return;
            }
            "exec" => {
                let cmd_args: Vec<String> = if args.len() > 2 && args[2] == "--" {
                    args[3..].to_vec()
                } else {
                    args[2..].to_vec()
                };
                match exec::run_exec(&cmd_args).await {
                    Ok(code) => std::process::exit(code),
                    Err(e) => {
                        eprintln!("Exec error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "--help" | "-h" => {
                println!("LLM Firewall — Security & Compliance Proxy for Local LLMs");
                println!();
                println!("USAGE:");
                println!("    llm-firewall [COMMAND] [OPTIONS]");
                println!();
                println!("COMMANDS:");
                println!("    scan                  Scan repository for unprotected secrets and sensitive files");
                println!("    exec -- <cmd>         Run an agent (Claude Code, etc.) supervised with isolated proxy env");
                println!("    on                    Start transparent MITM proxy with automatic CA installation");
                println!("    preflight             Generate or approve an unattended pre-flight security plan");
                println!("    stats                 Display aggregate security metrics and estimated risk avoided");
                println!("    report                Generate SOC 2 / HIPAA / GDPR compliance audit reports");
                println!("    [default]             Start standard proxy server");
                println!();
                println!("OPTIONS:");
                println!("    -h, --help            Print help information");
                return;
            }
            _ => {}
        }
    }

    run_server().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_default() {
        assert_eq!(parse_port(None), Ok(3000));
    }

    #[test]
    fn test_parse_port_valid() {
        assert_eq!(parse_port(Some("4000".to_string())), Ok(4000));
    }

    #[test]
    fn test_parse_port_invalid() {
        assert!(parse_port(Some("invalid".to_string())).is_err());
        assert!(parse_port(Some("-1".to_string())).is_err());
        assert!(parse_port(Some("65536".to_string())).is_err());
    }

    #[test]
    fn test_parse_port_empty() {
        assert_eq!(parse_port(Some("".to_string())), Ok(3000));
        assert_eq!(parse_port(Some("   ".to_string())), Ok(3000));
    }

    #[test]
    fn test_parse_upstream_url_default() {
        let url = parse_upstream_url(Err(std::env::VarError::NotPresent)).unwrap();
        assert_eq!(url.as_str(), "https://api.openai.com/");
    }

    #[test]
    fn test_parse_upstream_url_empty() {
        let url = parse_upstream_url(Ok("".to_string())).unwrap();
        assert_eq!(url.as_str(), "https://api.openai.com/");

        let url = parse_upstream_url(Ok("   ".to_string())).unwrap();
        assert_eq!(url.as_str(), "https://api.openai.com/");
    }

    #[test]
    fn test_parse_upstream_url_valid() {
        let url = parse_upstream_url(Ok("http://localhost:8080".to_string())).unwrap();
        assert_eq!(url.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn test_parse_upstream_url_invalid() {
        assert!(parse_upstream_url(Ok("not_a_url".to_string())).is_err());
        assert!(parse_upstream_url(Ok("ftp://example.com".to_string())).is_err());
        assert!(parse_upstream_url(Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::new()
        )))
        .is_err());
    }
}
