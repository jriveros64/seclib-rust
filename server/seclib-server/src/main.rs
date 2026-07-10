#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::dbg_macro
)]

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
    routing::post,
    Router,
};
use base64::Engine;
use rand::RngCore;
use serde::Serialize;
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use seclib_core::auth::{Claims, SessionManager, TokenVerifier};
use seclib_core::config::SecuritySettings;

mod rate_limit;

#[derive(Serialize)]
struct ErrorResponse {
    error_id: String,
    message: String,
}

#[derive(Clone, Copy)]
struct AuthContext {
    auth_via_cookie: bool,
}

#[derive(Clone, Copy)]
struct AuthenticatedMarker;

#[derive(Debug, Clone, PartialEq)]
pub enum RoutePolicy {
    Public,
    Requires(String),
}

pub struct SecureRouter {
    pub router: Router<AppState>,
    pub routes: Vec<(String, Option<RoutePolicy>)>,
}

impl Default for SecureRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureRouter {
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            routes: Vec::new(),
        }
    }

    pub fn route(
        mut self,
        path: &str,
        method_router: axum::routing::MethodRouter<AppState>,
        policy: Option<RoutePolicy>,
    ) -> Self {
        self.routes.push((path.to_string(), policy.clone()));

        let router = if let Some(p) = policy {
            self.router
                .route(path, method_router.layer(axum::Extension(p)))
        } else {
            self.router.route(path, method_router)
        };

        Self {
            router,
            routes: self.routes,
        }
    }

    pub fn into_router(self) -> Router<AppState> {
        self.router
    }
}

pub fn verify_app_routes(router: &SecureRouter) -> Result<(), String> {
    for (path, policy) in &router.routes {
        if policy.is_none() {
            return Err(format!(
                "SECURITY VIOLATION: Route '{path}' has no security requirement."
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    verifier: std::sync::Arc<TokenVerifier>,
    session_manager: std::sync::Arc<SessionManager>,
    _settings: SecuritySettings,
    policies: std::collections::HashMap<String, RoutePolicy>,
}

// Global error handler middleware
async fn error_handler_middleware(request: axum::extract::Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();

    if status.is_server_error() {
        let error_id = Uuid::new_v4().to_string();
        tracing::error!("[AUDIT] Server error occurred. Error ID: {error_id}");

        let error_body = ErrorResponse {
            error_id,
            message: "Ha ocurrido un error interno de seguridad.".to_string(),
        };

        let body_str = serde_json::to_string(&error_body).unwrap_or_default();
        // justificado: building a response from static/known components cannot fail
        #[allow(clippy::unwrap_used)]
        let mut error_response = Response::builder()
            .status(status)
            .body(axum::body::Body::from(body_str))
            .unwrap();

        error_response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return error_response;
    }

    response
}

// Security Headers middleware (R-7)
async fn security_headers_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);

    let mut response = next.run(request).await;
    let is_authenticated = response.extensions().get::<AuthenticatedMarker>().is_some();
    let headers = response.headers_mut();

    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    let csp_str = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none';"
    );
    if let Ok(csp_val) = HeaderValue::from_str(&csp_str) {
        headers.insert("Content-Security-Policy", csp_val);
    }

    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );

    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );

    if is_authenticated {
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
        );
    }

    response
}

// Authentication & Authorization middleware (R-2)
async fn auth_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let matched_path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str())
        .unwrap_or("");

    let policy = state.policies.get(matched_path).cloned();

    let policy = match policy {
        Some(p) => p,
        None => {
            // justificado: building a fallback response with static string cannot fail
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Route security policy missing"))
                .unwrap();
        }
    };

    let mut claims_opt = None;
    let mut auth_via_cookie = false;

    // 1. Authorization header (Bearer)
    if let Some(auth_header) = request.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match state.verifier.verify_token(token).await {
                    Ok(claims) => {
                        claims_opt = Some(claims);
                    }
                    Err(seclib_core::auth::AuthError::IdpUnavailable(msg)) => {
                        // justificado: building a 503 response with dynamic string cannot fail
                        #[allow(clippy::unwrap_used)]
                        return Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .body(axum::body::Body::from(format!("IdP Unavailable: {msg}")))
                            .unwrap();
                    }
                    Err(_) => {}
                }
            }
        }
    }

    // 2. Cookie session (__Host-Session)
    if claims_opt.is_none() {
        if let Some(cookie_header) = request.headers().get(axum::http::header::COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for part in cookie_str.split(';') {
                    let mut kv = part.splitn(2, '=');
                    if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                        if k.trim() == "__Host-Session" {
                            let session_id = v.trim();
                            if let Ok(Some(session_val)) =
                                state.session_manager.get_session(session_id)
                            {
                                if let Ok(claims) = serde_json::from_value::<Claims>(session_val) {
                                    claims_opt = Some(claims);
                                    auth_via_cookie = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    match policy {
        RoutePolicy::Requires(ref permission) => {
            let claims = match claims_opt.clone() {
                Some(c) => c,
                None => {
                    // justificado: building a 401 response with static string cannot fail
                    #[allow(clippy::unwrap_used)]
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(axum::body::Body::from("Unauthorized"))
                        .unwrap();
                }
            };

            let roles = claims
                .extra
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| r.as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();

            let required_perm = match permission.as_str() {
                "users:read" => seclib_core::authz::Permission::UsersRead,
                "users:manage" => seclib_core::authz::Permission::UsersManage,
                "files:upload" => seclib_core::authz::Permission::FilesUpload,
                "finance:read" => seclib_core::authz::Permission::FinanceRead,
                "finance:export" => seclib_core::authz::Permission::FinanceExport,
                "admin:*" => seclib_core::authz::Permission::Admin,
                _ => {
                    // justificado: building a 403 response with static string cannot fail
                    #[allow(clippy::unwrap_used)]
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(axum::body::Body::from("Invalid permission required"))
                        .unwrap();
                }
            };

            if seclib_core::authz::check_permission(&roles, required_perm).is_err() {
                // justificado: building a 403 response with static string cannot fail
                #[allow(clippy::unwrap_used)]
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("Forbidden"))
                    .unwrap();
            }

            request.extensions_mut().insert(claims);
            request
                .extensions_mut()
                .insert(AuthContext { auth_via_cookie });
        }
        RoutePolicy::Public => {
            if let Some(claims) = claims_opt.clone() {
                request.extensions_mut().insert(claims);
                request
                    .extensions_mut()
                    .insert(AuthContext { auth_via_cookie });
            }
        }
    }

    let mut response = next.run(request).await;

    if claims_opt.is_some() {
        response.extensions_mut().insert(AuthenticatedMarker);
    }

    response
}

// CSRF Protection using Double-Submit Cookie (R-2)
async fn csrf_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let is_mutating = matches!(
        method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );

    if !is_mutating {
        let has_csrf_cookie = request
            .headers()
            .get(axum::http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.contains("__Host-CSRF-Token"))
            .unwrap_or(false);

        let mut response = next.run(request).await;

        if method == Method::GET && !has_csrf_cookie {
            let mut token_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let csrf_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);

            let cookie_val =
                format!("__Host-CSRF-Token={csrf_token}; Secure; SameSite=Lax; Path=/");
            if let Ok(header_val) = HeaderValue::from_str(&cookie_val) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, header_val);
            }
        }
        return response;
    }

    let auth_ctx = request.extensions().get::<AuthContext>().copied();
    let authenticated_via_cookie = auth_ctx.map(|ctx| ctx.auth_via_cookie).unwrap_or(false);

    if authenticated_via_cookie {
        let mut cookie_token = None;
        if let Some(cookie_header) = request.headers().get(axum::http::header::COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for part in cookie_str.split(';') {
                    let mut kv = part.splitn(2, '=');
                    if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                        if k.trim() == "__Host-CSRF-Token" {
                            cookie_token = Some(v.trim().to_string());
                        }
                    }
                }
            }
        }

        let header_token = request
            .headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let verified = match (cookie_token, header_token) {
            (Some(c), Some(h)) => c.as_bytes().ct_eq(h.as_bytes()).into(),
            _ => false,
        };

        if !verified {
            let error_body = ErrorResponse {
                error_id: Uuid::new_v4().to_string(),
                message: "CSRF verification failed".to_string(),
            };
            let body_str = serde_json::to_string(&error_body).unwrap_or_default();
            // justificado: building a 403 response with JSON body cannot fail
            #[allow(clippy::unwrap_used)]
            let mut response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(body_str))
                .unwrap();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return response;
        }
    }

    next.run(request).await
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn admin_audit_handler() -> &'static str {
    "AUDIT SUCCESS"
}

// justificado: startup initialization path must panic/expect and abort if invalid config or server binding fails
#[tokio::main]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
async fn main() {
    let settings = seclib_core::config::load_security_settings()
        .expect("Fallo al cargar la configuración de seguridad");

    // R-1 CORS Wildcard validation
    if settings.cors_allow_credentials && settings.cors_allowed_origins.contains(&"*".to_string()) {
        panic!("SECURITY MISCONFIGURATION: Wildcard '*' in CORS origins with credentials is forbidden.");
    }

    let verifier = TokenVerifier::new(
        settings.oidc_jwks_url.clone(),
        settings.oidc_issuer.clone(),
        settings.oidc_client_id.clone(),
    );
    use secrecy::ExposeSecret;
    let session_manager = SessionManager::new(
        Some(settings.redis_url.expose_secret().as_str()),
        "__Host-Session",
    )
    .expect("Fallo al iniciar SessionManager");

    let state = AppState {
        verifier: std::sync::Arc::new(verifier),
        session_manager: std::sync::Arc::new(session_manager),
        _settings: settings.clone(),
        policies: std::collections::HashMap::new(),
    };

    let app = build_router(state, &settings);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("seclib-server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    // justificado: serving the application cannot fail under normal operation
    axum::serve(listener, app).await.unwrap();
}

pub fn build_router(mut state: AppState, settings: &SecuritySettings) -> Router {
    // CORS configuration from settings.
    // M-9: defense-in-depth. main() fails fast on wildcard+credentials, but build_router
    // is `pub` and may be used by embedders that bypass main(); enforce fail-closed here so
    // an insecure CorsLayer (wildcard origin '*' with credentials) can never be emitted.
    let wildcard_with_credentials =
        settings.cors_allow_credentials && settings.cors_allowed_origins.contains(&"*".to_string());
    if wildcard_with_credentials {
        tracing::error!(
            "SECURITY: CORS wildcard '*' combined with credentials is forbidden; disabling credentials (fail-closed)."
        );
    }
    let allow_credentials = settings.cors_allow_credentials && !wildcard_with_credentials;

    let mut cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-csrf-token"),
            axum::http::HeaderName::from_static("x-request-id"),
        ])
        .allow_credentials(allow_credentials);

    if settings.cors_allowed_origins.is_empty() {
        // Safe default
        cors = cors.allow_origin(Vec::<HeaderValue>::new());
    } else {
        let mut origins = Vec::new();
        for origin in &settings.cors_allowed_origins {
            if let Ok(val) = origin.parse::<HeaderValue>() {
                origins.push(val);
            }
        }
        cors = cors.allow_origin(origins);
    }

    let secure_router = SecureRouter::new()
        .route(
            "/health",
            axum::routing::get(health_handler).post(health_handler),
            Some(RoutePolicy::Public),
        )
        .route(
            "/admin/audit",
            post(admin_audit_handler),
            Some(RoutePolicy::Requires("admin:*".to_string())),
        );

    // R-2 Verify app routes
    // justificado: route verify is critical for secure operation, boot must fail if verify fails
    #[allow(clippy::expect_used)]
    verify_app_routes(&secure_router).expect("Failed boot security verification");

    let mut policies = std::collections::HashMap::new();
    for (path, policy) in &secure_router.routes {
        if let Some(p) = policy {
            policies.insert(path.clone(), p.clone());
        }
    }
    state.policies = policies;

    secure_router
        .into_router()
        .route_layer(axum::middleware::from_fn(csrf_middleware))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(cors)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            10 * 1024 * 1024,
        ))
        .layer(axum::middleware::from_fn(error_handler_middleware))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

// justificado: clippy denies do not apply inside test modules
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt;

    fn test_setup() -> (AppState, SecuritySettings) {
        let settings = SecuritySettings {
            oidc_client_id: "test-client".to_string(),
            oidc_client_secret: secrecy::SecretString::new("test-client-secret".to_string()),
            oidc_issuer: "http://localhost:9999".to_string(),
            oidc_jwks_url: "http://localhost:9999/jwks".to_string(),
            master_key: secrecy::SecretString::new("01234567890123456789012345678901".to_string()),
            redis_url: secrecy::SecretString::new("redis://127.0.0.1".to_string()),
            database_url: secrecy::SecretString::new("postgresql://localhost".to_string()),
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            cors_allow_credentials: true,
        };

        let verifier = TokenVerifier::new(
            settings.oidc_jwks_url.clone(),
            settings.oidc_issuer.clone(),
            settings.oidc_client_id.clone(),
        );

        let session_manager = SessionManager::new(None, "__Host-Session").unwrap();

        let state = AppState {
            verifier: std::sync::Arc::new(verifier),
            session_manager: std::sync::Arc::new(session_manager),
            _settings: settings.clone(),
            policies: std::collections::HashMap::new(),
        };

        (state, settings)
    }

    #[tokio::test]
    async fn test_csrf_middleware_behavior() {
        let (state, settings) = test_setup();
        let app = build_router(state.clone(), &settings);

        // 1. GET requests: Should set __Host-CSRF-Token cookie
        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let cookie_header = res.headers().get(axum::http::header::SET_COOKIE);
        assert!(cookie_header.is_some());
        let cookie_str = cookie_header.unwrap().to_str().unwrap();
        assert!(cookie_str.contains("__Host-CSRF-Token="));

        // Extract token
        let token = cookie_str
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_string();

        // 2. Mutating request WITH Bearer (exemption): Should pass without CSRF headers
        let req = Request::builder()
            .method("POST")
            .uri("/health")
            .header("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk5OTkiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6OTk5OTk5OTk5OSwic3ViIjoidGVzdC11c2VyIn0.abc")
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert!(
            res.status() == StatusCode::SERVICE_UNAVAILABLE
                || res.status() == StatusCode::UNAUTHORIZED
        );

        // 3. Mutating request with cookie auth but NO CSRF token: Should return 403 Forbidden
        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "http://localhost:9999".to_string(),
            aud: "test-client".to_string(),
            exp: 9999999999,
            nbf: 0,
            iat: 0,
            extra: json!({ "roles": ["admin"] }).as_object().unwrap().clone(),
        };
        let session_id = state
            .session_manager
            .create_session(serde_json::to_value(&claims).unwrap(), 3600)
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/admin/audit")
            .header("Cookie", format!("__Host-Session={session_id}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN); // Blocked by CSRF

        // 4. Mutating request with cookie auth AND matching CSRF token: Should pass
        let req = Request::builder()
            .method("POST")
            .uri("/admin/audit")
            .header(
                "Cookie",
                format!("__Host-Session={session_id}; __Host-CSRF-Token={token}"),
            )
            .header("X-CSRF-Token", &token)
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_idp_unavailable_returns_503() {
        let (state, settings) = test_setup();
        let app = build_router(state.clone(), &settings);

        let req = Request::builder()
            .method("POST")
            .uri("/admin/audit")
            .header("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk5OTkiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6OTk5OTk5OTk5OSwic3ViIjoidGVzdC11c2VyIn0.abc")
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_error_response_carries_security_headers() {
        let (state, settings) = test_setup();
        let app = build_router(state.clone(), &settings);

        let req = Request::builder()
            .method("POST")
            .uri("/admin/audit")
            .header("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojk5OTkiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6OTk5OTk5OTk5OSwic3ViIjoidGVzdC11c2VyIn0.abc")
            .body(axum::body::Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(res.headers().contains_key("Content-Security-Policy"));
        assert!(res.headers().contains_key("Strict-Transport-Security"));
        assert_eq!(
            res.headers()
                .get("X-Content-Type-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }
}
