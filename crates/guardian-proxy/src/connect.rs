//! Forward proxy CONNECT tunneling with TCP-peeking multiplexer.
//!
//! This module implements single-port multiplexing: a raw TCP accept loop peeks the first 7 bytes
//! of every connection to distinguish `CONNECT` requests (forward proxy) from regular HTTP traffic
//! (reverse proxy). Both share the same port without configuration change.
//!
//! ## MITM TLS Strategy
//!
//! For LLM domains listed in [`LLM_MITM_DOMAINS`], the proxy terminates TLS with a dynamically
//! generated leaf certificate signed by the local CA. The decrypted HTTP stream is then routed
//! through the existing Axum PII detection pipeline.
//!
//! For all other domains (auth, telemetry, etc.), the proxy performs a blind byte-pump via
//! `tokio::io::copy_bidirectional` without inspecting the payload.
//!
//! ## Firewall Block Responses
//!
//! When PII is blocked inside a CONNECT tunnel, the proxy returns a mocked SSE streaming response
//! instead of a hard HTTP error. This ensures IDE chat UIs render the block message natively.

use crate::AppState;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::Service;
use tracing;

/// LLM API domains for which the proxy performs TLS MITM and PII inspection.
pub const LLM_MITM_DOMAINS: &[&str] = &["api.anthropic.com", "api.openai.com", "cursor.sh"];

/// Domains where TLS is blindly passed through without inspection (auth/telemetry).
pub const SNI_BYPASS_DOMAINS: &[&str] = &[
    "authenticate.cursor.sh",
    "metrics.cursor.sh",
    "marketplace.cursorapi.com",
    "workoscdn.com",
];

/// Number of bytes to peek in order to detect a `CONNECT` request (7 = "CONNECT").
const PEEK_SIZE: usize = 7;

/// Maximum bytes to read for the full CONNECT request line before giving up.
const CONNECT_HEADER_MAX: usize = 4096;

/// Main accept loop: peeks each incoming TCP connection and dispatches to forward or reverse proxy.
///
/// # Arguments
///
/// * `listener` - Bound TCP listener (typically port 3000).
/// * `axum_app` - The Axum [`Router`] that handles reverse proxy traffic.
/// * `state` - Shared application state, including optional CA key material.
/// * `shutdown` - Future that resolves when a graceful shutdown signal is received.
pub async fn accept_loop(
    listener: TcpListener,
    axum_app: Router,
    state: AppState,
    shutdown: impl std::future::Future<Output = ()>,
) {
    // Wrap the Axum app as a hyper-compatible service factory.
    let axum_service = axum_app.into_make_service();

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("Accept loop shutting down.");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _peer_addr)) => {
                        let state_clone = state.clone();
                        let svc_factory = axum_service.clone();
                        tokio::spawn(async move {
                            dispatch_connection(stream, state_clone, svc_factory).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TCP accept error");
                    }
                }
            }
        }
    }
}

/// Dispatches a single TCP connection to either the CONNECT handler or the Axum reverse proxy.
async fn dispatch_connection(
    stream: TcpStream,
    state: AppState,
    mut axum_make_svc: axum::routing::IntoMakeService<Router>,
) {
    // Peek up to PEEK_SIZE bytes to decide routing. Use a timeout to prevent Slowloris.
    let mut peek_buf = [0u8; PEEK_SIZE];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = stream.peek(&mut peek_buf).await?;
            if n >= 7 || n > 0 && peek_buf[..n] != b"CONNECT"[..n] {
                return Ok::<usize, std::io::Error>(n);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    {
        Ok(Ok(n)) => n,
        _ => {
            tracing::debug!("Peek timeout or error, closing connection");
            return;
        }
    };

    if n >= 7 && &peek_buf[..7] == b"CONNECT" {
        // Forward proxy branch: handle the CONNECT tunnel.
        handle_connect(stream, state).await;
    } else {
        // Reverse proxy branch: hand the socket to the Axum app via hyper.
        let svc = match tower::ServiceExt::<()>::ready(&mut axum_make_svc).await {
            Ok(s) => s,
            Err(_e) => {
                tracing::error!("Failed to get ready Axum service");
                return;
            }
        };
        let conn_svc = match svc.call(()).await {
            Ok(s) => s,
            Err(_e) => {
                tracing::error!("Failed to instantiate Axum connection service");
                return;
            }
        };

        let io = TokioIo::new(stream);
        let hyper_svc = TowerToHyperService::new(conn_svc);
        if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(io, hyper_svc)
            .await
        {
            // Log disconnect-type errors at debug level to avoid noise.
            let msg = e.to_string();
            if msg.contains("connection closed")
                || msg.contains("broken pipe")
                || msg.contains("connection reset")
            {
                tracing::debug!(error = %e, "Client disconnected");
            } else {
                tracing::error!(error = %e, "Hyper connection error");
            }
        }
    }
}

/// Processes a forward proxy `CONNECT` request.
///
/// Reads the full CONNECT header line, sends `200 Connection Established`, then routes
/// the tunnel to either MITM TLS inspection or blind passthrough based on the target host.
async fn handle_connect(mut stream: TcpStream, state: AppState) {
    // Read until \r\n\r\n to capture the CONNECT request line and headers.
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];

    let bad_req = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

    loop {
        if buf.len() > CONNECT_HEADER_MAX {
            let _ = stream.write_all(bad_req).await;
            return;
        }
        let read_future = stream.read(&mut tmp);
        let n = match tokio::time::timeout(std::time::Duration::from_secs(10), read_future).await {
            Ok(Ok(0)) => {
                tracing::debug!("Client disconnected before CONNECT headers complete");
                return;
            }
            Ok(Ok(n)) => n,
            _ => {
                tracing::debug!("Read timeout or error during CONNECT header");
                return;
            }
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Parse the first line: "CONNECT host:port HTTP/1.1"
    let header_str = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.write_all(bad_req).await;
            return;
        }
    };

    let (target_host, target_port) = match parse_connect_target(header_str) {
        Some(pair) => pair,
        None => {
            tracing::warn!("Malformed CONNECT request");
            let _ = stream.write_all(bad_req).await;
            return;
        }
    };

    let target_host = target_host.to_lowercase();

    tracing::debug!(target_host = %target_host, target_port = %target_port, "CONNECT request");

    // Route: bypass domains → blind tunnel; LLM domains → MITM.
    let is_bypass = SNI_BYPASS_DOMAINS
        .iter()
        .any(|d| target_host == *d || target_host.ends_with(&format!(".{}", d)));
    let is_llm = LLM_MITM_DOMAINS
        .iter()
        .any(|d| target_host == *d || target_host.ends_with(&format!(".{}", d)));

    if is_bypass {
        if let Err(e) = stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            tracing::debug!(error = %e, "Failed to write 200 to client");
            return;
        }
        tracing::info!(host = %target_host, "SNI bypass: blind tunnel");
        blind_tunnel(stream, &target_host, target_port).await;
    } else if is_llm {
        if state.ca_key_pair.is_none() || state.ca_cert_der.is_none() {
            tracing::error!(host = %target_host, "CA not available; denying MITM tunnel with 502");
            let _ = stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            return;
        }
        if let Err(e) = stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            tracing::debug!(error = %e, "Failed to write 200 to client");
            return;
        }
        tracing::debug!(host = %target_host, "LLM domain: MITM TLS tunnel");
        mitm_tunnel(stream, target_host, target_port, state).await;
    } else {
        // Unknown domain: fail-open with blind tunnel.
        if let Err(e) = stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            tracing::debug!(error = %e, "Failed to write 200 to client");
            return;
        }
        tracing::info!(host = %target_host, "Unknown domain: blind tunnel (fail-open)");
        blind_tunnel(stream, &target_host, target_port).await;
    }
}

/// Parses `host:port` from a `CONNECT host:port HTTP/1.1\r\n...` header.
///
/// Returns `None` if the request is malformed.
fn parse_connect_target(header: &str) -> Option<(String, u16)> {
    let first_line = header.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
        return None;
    }
    let host_port = parts[1];
    // IPv6 bracket notation: [::1]:443
    if host_port.starts_with('[') {
        let end = host_port.rfind(']')?;
        let host = &host_port[1..end];
        let port_str = host_port.get(end + 2..)?; // skip ]:
        let port = port_str.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    // Standard host:port
    let (host, port_str) = host_port.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

async fn blind_tunnel(mut client_stream: TcpStream, host: &str, port: u16) {
    let upstream_addr = format!("{}:{}", host, port);
    let upstream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&upstream_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            tracing::warn!(
                upstream = %upstream_addr,
                "Blind tunnel: upstream connect timeout or failed"
            );
            return;
        }
    };
    let mut upstream_stream = upstream;
    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await;
}

/// MITM TLS tunnel: terminates TLS on the client side using a dynamically signed leaf cert,
/// then connects to the upstream over real TLS and routes the decrypted HTTP stream through
/// the PII detection pipeline.
async fn mitm_tunnel(client_stream: TcpStream, host: String, _port: u16, state: AppState) {
    let ca_key_pair = Arc::clone(state.ca_key_pair.as_ref().unwrap());
    let ca_cert_der_bytes = Arc::clone(state.ca_cert_der.as_ref().unwrap());

    // Build a dynamic leaf cert for the target hostname, signed by our local CA.
    let host_clone = host.clone();
    let tls_acceptor = match tokio::task::spawn_blocking(move || {
        build_leaf_tls_acceptor(&host_clone, &ca_key_pair, &ca_cert_der_bytes)
    })
    .await
    {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => {
            tracing::error!(error = %e, host = %host, "Failed to build leaf TLS acceptor");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "Task panic in build_leaf_tls_acceptor");
            return;
        }
    };

    // Wrap the client TCP stream with TLS.
    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls_acceptor.accept(client_stream),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            tracing::debug!(
                host = %host,
                "TLS handshake with client timeout or failed (client may not trust CA)"
            );
            return;
        }
    };

    // Build the Axum app for this connection — it serves as the HTTP pipeline.
    let axum_router = crate::create_app(state.clone());
    let mut axum_make_svc = axum_router.into_make_service();

    let conn_svc = match tower::ServiceExt::<()>::ready(&mut axum_make_svc).await {
        Ok(s) => match s.call(()).await {
            Ok(svc) => svc,
            Err(_) => {
                tracing::error!("Failed to instantiate Axum connection service for MITM");
                return;
            }
        },
        Err(_) => {
            tracing::error!("Axum service not ready for MITM");
            return;
        }
    };

    // Inject X-Firewall-Mitm header into all incoming requests.
    let header_injector =
        tower::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            let mut inner_svc = conn_svc.clone();
            async move {
                req.headers_mut().insert(
                    "X-Firewall-Mitm",
                    axum::http::HeaderValue::from_static("true"),
                );
                inner_svc.call(req).await
            }
        });

    let io = TokioIo::new(tls_stream);
    let hyper_svc = TowerToHyperService::new(header_injector);
    if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, hyper_svc)
        .await
    {
        let msg = e.to_string();
        if !msg.contains("connection closed")
            && !msg.contains("broken pipe")
            && !msg.contains("connection reset")
            && !msg.contains("connection error")
        {
            tracing::error!(error = %e, host = %host, "MITM tunnel connection error");
        }
    }
}

/// Builds a `tokio_rustls::TlsAcceptor` with an ephemeral leaf certificate for `hostname`,
/// signed by the local CA key pair.
fn build_leaf_tls_acceptor(
    hostname: &str,
    ca_key_pair: &KeyPair,
    ca_cert_der_bytes: &[u8],
) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    // Generate a new ephemeral key pair for the leaf cert.
    let leaf_key_pair = KeyPair::generate()?;

    // Build the CA issuer from the stored DER cert + CA key pair.
    let ca_cert_der = CertificateDer::from(ca_cert_der_bytes.to_vec());
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der, ca_key_pair)?;

    // Build the leaf cert params.
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, hostname);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()?)];
    params.is_ca = rcgen::IsCa::NoCa;

    // Sign the leaf cert with the CA issuer.
    let leaf_cert = params.signed_by(&leaf_key_pair, &issuer)?;

    // Build rustls ServerConfig.
    let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
    let leaf_key_der = PrivateKeyDer::try_from(leaf_key_pair.serialize_der())
        .map_err(|e| format!("Invalid private key DER: {}", e))?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert_der], leaf_key_der)?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_target_standard() {
        let header =
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        let result = parse_connect_target(header).unwrap();
        assert_eq!(result.0, "api.anthropic.com");
        assert_eq!(result.1, 443);
    }

    #[test]
    fn parse_connect_target_missing_port() {
        let header = "CONNECT api.anthropic.com HTTP/1.1\r\n\r\n";
        assert!(parse_connect_target(header).is_none());
    }

    #[test]
    fn parse_connect_target_malformed() {
        let header = "GET / HTTP/1.1\r\n\r\n";
        assert!(parse_connect_target(header).is_none());
    }

    #[test]
    fn parse_connect_target_ipv4_port() {
        let header = "CONNECT 192.168.1.1:8080 HTTP/1.1\r\n\r\n";
        let result = parse_connect_target(header).unwrap();
        assert_eq!(result.0, "192.168.1.1");
        assert_eq!(result.1, 8080);
    }

    #[test]
    fn llm_mitm_domains_non_empty() {
        assert!(!LLM_MITM_DOMAINS.is_empty());
        assert!(LLM_MITM_DOMAINS.contains(&"api.anthropic.com"));
        assert!(LLM_MITM_DOMAINS.contains(&"api.openai.com"));
    }

    #[test]
    fn sni_bypass_domains_contains_cursor_auth() {
        assert!(SNI_BYPASS_DOMAINS.contains(&"authenticate.cursor.sh"));
    }
}
