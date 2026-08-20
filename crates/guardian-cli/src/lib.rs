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
pub mod patcher;
pub mod scanner;
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

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(300))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap_or_else(|e| {
            tracing::error!("Fatal: Failed to initialize reqwest client: {}", e);
            std::process::exit(1);
        });

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

    let state = AppState {
        client,
        upstream_url,
        model: shared_model,
    };

    let app = create_app(state);

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

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("Server error: {}", e);
    }
}

pub async fn run_server_with_trust() {
    init_logging();
    let ca_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
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
