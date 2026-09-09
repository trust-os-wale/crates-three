use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

fn json_response(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::empty())
                .unwrap()
        })
}

pub async fn trace_layer(req: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let start = std::time::Instant::now();

    let span = tracing::info_span!(
        "http_request",
        method = %method,
        uri = %uri,
        request_id = %request_id,
        duration_ms = tracing::field::Empty,
    );

    let _guard = span.enter();
    let response = next.run(req).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    span.record("duration_ms", duration_ms);
    info!(status = %response.status().as_u16(), duration_ms = duration_ms, "request completed");

    response
}

pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;
    if let Ok(val) = request_id.parse() {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

#[derive(Clone)]
pub struct RequestId(pub String);

pub async fn timing_middleware(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let start = Utc::now();
    let response = next.run(req).await;
    let duration = Utc::now() - start;

    info!(
        method = %method,
        uri = %uri,
        status = %response.status().as_u16(),
        duration_ms = %duration.num_milliseconds(),
        "request timing"
    );

    response
}

/// JWT Authentication middleware - extracts and validates Bearer tokens.
/// Returns 401 if token is missing, invalid, or expired.
pub async fn jwt_auth_middleware(mut req: Request, next: Next) -> Response {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if let Some(token) = header.strip_prefix("Bearer ") {
                token.to_string()
            } else {
                warn!("Authorization header missing Bearer prefix");
                return json_response(
                    StatusCode::UNAUTHORIZED,
                    r#"{"error":"Invalid authorization header format","code":"INVALID_AUTH_FORMAT"}"#,
                );
            }
        }
        None => {
            warn!("No authorization header present");
            return json_response(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"Missing authorization header","code":"MISSING_AUTH_HEADER"}"#,
            );
        }
    };

    // Extract the TokenManager from request extensions
    let token_manager = req
        .extensions()
        .get::<std::sync::Arc<crate::auth::TokenManager>>()
        .cloned();

    let token_manager = match token_manager {
        Some(tm) => tm,
        None => {
            warn!("TokenManager not found in request extensions");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Authentication service unavailable","code":"AUTH_SERVICE_UNAVAILABLE"}"#,
            );
        }
    };

    match token_manager.verify_token(&token) {
        Ok(claims) => {
            // Insert verified claims into request extensions for downstream handlers
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => {
            warn!(error = %e, "Token verification failed");
            let (status, code) = match &e {
                common::errors::GrcError::TokenExpired => {
                    (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED")
                }
                _ => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN"),
            };
            json_response(
                status,
                &format!(r#"{{"error":"Authentication failed","code":"{}"}}"#, code),
            )
        }
    }
}

/// Tenant context middleware - extracts tenant_id from X-Tenant-ID header
/// and builds a RequestTenantContext for downstream handlers.
/// Returns 400 if tenant_id header is missing.
/// Note: user_id is NOT extracted from JWT here (that requires full verification).
/// Handlers that need user identity should use the auth verification endpoint.
pub async fn tenant_context_middleware(
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    // Extract tenant_id from header
    let tenant_id = request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    if tenant_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Build context with tenant_id only. user_id requires full JWT verification
    // which is handled by the auth middleware, not here.
    let context = tenant::RequestTenantContext::new(tenant_id, String::new());
    request.extensions_mut().insert(context);

    Ok(next.run(request).await)
}
