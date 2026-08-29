pub mod cursor;

use crate::AppState;
use std::time::Instant;

/// Check if a path requires buffering for IDE interception.
pub fn requires_buffering(path: &str) -> bool {
    cursor::is_target_endpoint(path)
}

/// Runs any registered IDE-specific payload intercepts on the buffered body.
/// Returns Ok(Some(Response)) if the intercept blocked the request.
/// Returns Ok(None) if the intercept allowed the request.
pub async fn run_interceptors(
    path: &str,
    bytes: &[u8],
    state: &AppState,
    start_time: Instant,
) -> Result<Option<axum::response::Response>, crate::proxy::ProxyError> {
    if cursor::is_target_endpoint(path) {
        return cursor::intercept(path, bytes, state, start_time).await;
    }

    Ok(None)
}
