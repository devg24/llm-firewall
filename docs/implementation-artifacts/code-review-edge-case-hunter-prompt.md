# Edge Case Hunter Code Review Prompt

You are an adversarial code reviewer operating in "Edge Case Hunter" mode. Your goal is to identify unhandled boundary conditions, edge cases, race conditions, resource leaks, or error states in the code below.

## Instructions
1. Review the files below for unhandled edge cases (e.g. timeout handling, connection pool exhaustion, memory growth, extreme input sizes, unexpected empty strings, invalid characters, header formatting quirks).
2. Detail each edge case and explain the potential exploit/failure mode.
3. List your findings in a clear, bulleted list. Categorize each finding by severity (High/Medium/Low).

---

## Files Under Review

### File: `src/main.rs`
```rust
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod proxy;

#[derive(Clone)]
pub struct AppState {
    pub client: reqwest::Client,
    pub upstream_url: reqwest::Url,
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .try_init();
}

fn parse_port(port_env: Option<String>) -> Result<u16, String> {
    match port_env {
        Some(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                Ok(3000)
            } else {
                trimmed.parse::<u16>().map_err(|e| format!("Invalid port '{}': {}", trimmed, e))
            }
        }
        None => Ok(3000),
    }
}

fn parse_upstream_url(url_env: Result<String, std::env::VarError>) -> Result<reqwest::Url, String> {
    match url_env {
        Ok(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                reqwest::Url::parse("https://api.openai.com").map_err(|e| e.to_string())
            } else {
                let parsed = reqwest::Url::parse(trimmed)
                    .map_err(|e| format!("Invalid UPSTREAM_URL '{}': {}", trimmed, e))?;
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    return Err(format!("Invalid UPSTREAM_URL '{}': Scheme must be http or https", trimmed));
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

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/v1/chat/completions",
            axum::routing::post(|| async { axum::http::StatusCode::NOT_IMPLEMENTED }),
        )
        .route("/{*path}", axum::routing::any(proxy::proxy_handler))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    init_logging();
    
    let port_var = match std::env::var("PORT") {
        Ok(val) => Some(val),
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::error!("Fatal: PORT environment variable is not valid unicode");
            std::process::exit(1);
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
        .read_timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| {
            tracing::error!("Fatal: Failed to initialize reqwest client: {}", e);
            std::process::exit(1);
        });

    let state = AppState {
        client,
        upstream_url,
    };
    
    let app = create_app(state);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to port {}: {}", port, e);
            std::process::exit(1);
        }
    };
    
    let bound_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!("Server started successfully and listening on {}", bound_addr);
    
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
    }
}
```

### File: `src/proxy.rs`
```rust
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Uri, StatusCode},
    response::Response,
};
use crate::AppState;
use std::time::Instant;

pub async fn proxy_handler(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let start_time = Instant::now();

    // 1. Reconstruct the target URL
    let path = uri.path();
    let query = uri.query();

    let mut target_url = state.upstream_url.clone();
    target_url.set_path(path);
    target_url.set_query(query);

    // 2. Read the request body to Bytes
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            let duration = start_time.elapsed().as_millis();
            tracing::error!(
                method = method.as_str(),
                path = path,
                duration_ms = duration,
                error = %e,
                "Failed to read request body"
            );
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Failed to read request body"))
                .unwrap();
        }
    };

    // 3. Create the reqwest request
    let mut req_builder = state.client.request(method.clone(), target_url.clone());

    // Copy request headers, excluding hop-by-hop headers, and rewrite Host
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            req_headers.insert(name.clone(), value.clone());
        }
    }

    // Set the Host header
    let host_val = if let Some(port) = state.upstream_url.port() {
        format!("{}:{}", state.upstream_url.host_str().unwrap_or(""), port)
    } else {
        state.upstream_url.host_str().unwrap_or("").to_string()
    };
    if let Ok(host_header_val) = reqwest::header::HeaderValue::from_str(&host_val) {
        req_headers.insert(reqwest::header::HOST, host_header_val);
    }

    req_builder = req_builder.headers(req_headers).body(reqwest::Body::from(body_bytes));

    // 4. Send the request
    let response = match req_builder.send().await {
        Ok(res) => res,
        Err(e) => {
            let duration = start_time.elapsed().as_millis();
            tracing::info!(
                method = method.as_str(),
                path = path,
                duration_ms = duration,
                error = %e,
                "Upstream request failed"
            );
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Bad Gateway: {}", e)))
                .unwrap();
        }
    };

    let status = response.status();
    let status_code = status.as_u16();

    // Copy response headers, excluding hop-by-hop headers
    let mut res_headers = HeaderMap::new();
    for (name, value) in response.headers().iter() {
        if !is_hop_by_hop(name) {
            res_headers.insert(name.clone(), value.clone());
        }
    }

    // 5. Read response body
    let res_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            let duration = start_time.elapsed().as_millis();
            tracing::info!(
                method = method.as_str(),
                path = path,
                duration_ms = duration,
                status_code = status_code,
                error = %e,
                "Failed to read response body"
            );
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Failed to read upstream response body"))
                .unwrap();
        }
    };

    let duration = start_time.elapsed().as_millis();

    // 6. Log response
    tracing::info!(
        method = method.as_str(),
        path = path,
        duration_ms = duration,
        status_code = status_code,
        "Request proxied successfully"
    );

    // 7. Reconstruct Axum Response
    let mut axum_res_builder = Response::builder().status(status);
    
    if let Some(headers_mut) = axum_res_builder.headers_mut() {
        *headers_mut = res_headers;
    }

    axum_res_builder.body(Body::from(res_bytes)).unwrap()
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &axum::http::HeaderName) -> bool {
    let name_str = name.as_str();
    HOP_BY_HOP_HEADERS.iter().any(|h| name_str.eq_ignore_ascii_case(h))
}
```
