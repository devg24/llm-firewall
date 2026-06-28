use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Uri, StatusCode},
    response::Response,
};
use crate::AppState;
use std::time::Instant;

pub struct SyncStream<S>(std::sync::Mutex<S>);

unsafe impl<S> Sync for SyncStream<S> {}

impl<S, T, E> futures_core::Stream for SyncStream<S>
where
    S: futures_core::Stream<Item = Result<T, E>> + Unpin,
{
    type Item = Result<T, E>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut lock = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *lock).poll_next(cx)
    }
}

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
    
    // Joint path logic to preserve configured base path prefix
    let base_path = target_url.path().trim_end_matches('/');
    let incoming_path = path.trim_start_matches('/');
    let joined_path = if base_path.is_empty() {
        format!("/{}", incoming_path)
    } else {
        format!("{}/{}", base_path, incoming_path)
    };
    target_url.set_path(&joined_path);
    target_url.set_query(query);

    // 2. Wrap the request body stream to be thread-safe (Sync) for reqwest
    let stream = body.into_data_stream();
    let sync_stream = SyncStream(std::sync::Mutex::new(stream));
    let reqwest_body = reqwest::Body::wrap_stream(sync_stream);

    // 3. Create the reqwest request
    let mut req_builder = state.client.request(method.clone(), target_url.clone());

    // Copy request headers, excluding hop-by-hop headers, and rewrite Host
    let mut req_headers = reqwest::header::HeaderMap::new();

    // Parse the Connection header to extract client-specified hop-by-hop headers
    let mut custom_hop_headers = Vec::new();
    if let Some(conn_val) = headers.get(axum::http::header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for part in conn_str.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    custom_hop_headers.push(trimmed.to_lowercase());
                }
            }
        }
    }

    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if !is_hop_by_hop(name) && !custom_hop_headers.contains(&name_str) {
            req_headers.append(name.clone(), value.clone());
        }
    }

    // Set the Host header (using authority to handle IPv6 bracket formatting)
    let host_val = state.upstream_url.authority().to_string();
    if let Ok(host_header_val) = reqwest::header::HeaderValue::from_str(&host_val) {
        req_headers.insert(reqwest::header::HOST, host_header_val);
    }

    req_builder = req_builder.headers(req_headers).body(reqwest_body);

    // 4. Send the request
    let response = match req_builder.send().await {
        Ok(res) => res,
        Err(e) => {
            let duration = start_time.elapsed().as_millis();
            tracing::error!(
                method = method.as_str(),
                path = path,
                duration_ms = duration,
                error = %e,
                "Upstream request failed"
            );
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Bad Gateway"))
                .unwrap();
        }
    };

    let status = response.status();
    let status_code = status.as_u16();

    // Copy response headers, excluding hop-by-hop headers
    let mut res_headers = HeaderMap::new();

    // Parse the Connection header in the upstream response
    let mut custom_res_hop_headers = Vec::new();
    if let Some(conn_val) = response.headers().get(reqwest::header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for part in conn_str.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    custom_res_hop_headers.push(trimmed.to_lowercase());
                }
            }
        }
    }

    for (name, value) in response.headers().iter() {
        let name_str = name.as_str().to_lowercase();
        if !is_hop_by_hop(name) && !custom_res_hop_headers.contains(&name_str) {
            res_headers.append(name.clone(), value.clone());
        }
    }

    let duration = start_time.elapsed().as_millis();

    // 6. Log response
    tracing::info!(
        method = method.as_str(),
        path = path,
        duration_ms = duration,
        status_code = status_code,
        "Request proxied successfully"
    );

    // 7. Reconstruct Axum Response by streaming response bytes directly
    let res_stream = response.bytes_stream();
    let axum_body = Body::from_stream(res_stream);

    let mut axum_res_builder = Response::builder().status(status);
    
    if let Some(headers_mut) = axum_res_builder.headers_mut() {
        *headers_mut = res_headers;
    }

    axum_res_builder.body(axum_body).unwrap()
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
