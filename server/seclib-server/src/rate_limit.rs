#![allow(dead_code)]

use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use seclib_core::store::RateLimitStore;

#[derive(Debug, Clone)]
pub struct RateLimiter<S> {
    store: S,
    pub limit: u64,
    pub window_secs: u64,
}

impl<S: RateLimitStore> RateLimiter<S> {
    pub fn new(store: S, limit: u64, window_secs: u64) -> Self {
        Self {
            store,
            limit,
            window_secs,
        }
    }

    pub async fn check_limit(&self, key: &str) -> Result<u64, String> {
        self.store
            .increment(key, self.window_secs)
            .await
            .map_err(|e| e.to_string())
    }
}

pub async fn rate_limit_middleware<S, F>(
    limiter: RateLimiter<S>,
    key_extractor: F,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response
where
    S: RateLimitStore,
    F: Fn(&Request<axum::body::Body>) -> String,
{
    let key = key_extractor(&request);
    match limiter.check_limit(&key).await {
        Ok(count) => {
            if count > limiter.limit {
                return (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").into_response();
            }
            next.run(request).await
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Security rate limit error: {e}"),
        )
            .into_response(),
    }
}
