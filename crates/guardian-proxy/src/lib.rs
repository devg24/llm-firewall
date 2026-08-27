//! `guardian-proxy` — Axum MITM proxy handlers, ProxyError, and AppState for LLM Firewall.
//!
//! This crate provides:
//! - [`AppState`]: shared application state (HTTP client, upstream URL, ML model)
//! - [`create_app`]: builds the Axum router with all proxy routes
//! - [`proxy::proxy_handler`]: generic passthrough handler
//! - [`proxy::chat_completions_handler`]: PII-intercepting chat completions handler
//! - [`proxy::ProxyError`]: proxy error type with HTTP response mapping

pub mod proxy;

use axum::{routing::get, Router};
use guardian_core::domain::DomainProfile;
use guardian_core::ml::SharedModel;
use std::sync::Arc;

pub use guardian_core::telemetry::{spawn_telemetry_writer, TelemetryWriter};
pub use proxy::{chat_completions_handler, proxy_handler, ProxyError};

/// Shared application state injected into every Axum handler via `State<AppState>`.
///
/// # Clone
/// All fields are cheaply cloneable (`Arc`-wrapped or `Clone`).
#[derive(Clone)]
pub struct AppState {
    /// Reqwest HTTP client for upstream requests.
    pub client: reqwest::Client,
    /// Base URL of the upstream LLM API (e.g., `https://api.openai.com`).
    pub upstream_url: reqwest::Url,
    /// Optional shared BERT ML model for NER-based inference.
    pub model: Option<Arc<SharedModel>>,
    /// Active domain profile auto-detected from project manifests or config.
    pub domain: DomainProfile,
    /// Optional power-user configuration loaded from .guardian.toml.
    pub guardian_config: Option<guardian_core::manifest::GuardianConfig>,
    /// Optional pre-approved pre-flight security plan for unattended sessions.
    pub preflight_plan: Option<Arc<guardian_core::plan::PreflightPlan>>,
    /// Optional non-blocking channel sender for audit telemetry event logging.
    pub telemetry_tx:
        Option<tokio::sync::mpsc::UnboundedSender<guardian_core::telemetry::TelemetryEvent>>,
}

/// Builds the Axum [`Router`] with all proxy routes attached to `state`.
///
/// Routes:
/// - `GET /health` — liveness check, returns `"OK"`
/// - `POST /v1/chat/completions` — PII-intercepting completions handler
/// - All other methods on `/v1/chat/completions` — generic passthrough
/// - `ANY /{*path}` — generic passthrough for all other paths
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/v1/chat/completions",
            axum::routing::post(proxy::chat_completions_handler).fallback(proxy::proxy_handler),
        )
        .route(
            "/v1/chat/completions/",
            axum::routing::post(proxy::chat_completions_handler).fallback(proxy::proxy_handler),
        )
        .route("/{*path}", axum::routing::any(proxy::proxy_handler))
        .with_state(state)
}
