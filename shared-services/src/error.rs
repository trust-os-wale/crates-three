use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use common::errors::GrcError;
use tracing::error;

pub struct AppError(GrcError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // Log the detailed error server-side only
        error!(error = %self.0, "request error");

        // Return a generic error message to the client to avoid information disclosure
        let message = match &self.0 {
            // Client errors — safe to expose detail
            GrcError::AuthenticationFailed(_)
            | GrcError::AuthorizationFailed
            | GrcError::MfaChallengeRequired
            | GrcError::MfaVerificationFailed
            | GrcError::TenantNotFound(_)
            | GrcError::TenantIsolationViolation
            | GrcError::InvalidTenantContext
            | GrcError::EvidenceNotFound(_)
            | GrcError::EvidenceValidationFailed(_)
            | GrcError::EvidenceDuplicate
            | GrcError::InvalidEvidenceSignature
            | GrcError::ControlNotFound(_)
            | GrcError::InvalidPolicyExpression(_)
            | GrcError::GraphNodeNotFound(_)
            | GrcError::InvalidRequest(_)
            | GrcError::ValidationFailed(_)
            | GrcError::RateLimitExceeded
            | GrcError::UnsupportedOperation(_)
            | GrcError::SignatureVerificationFailed
            | GrcError::WorkflowNotFound(_)
            | GrcError::InvalidWorkflowState(_)
            | GrcError::ResourceConflict(_) => self.0.to_string(),
            GrcError::TokenExpired => self.0.to_string(),
            GrcError::InvalidToken(_) => "Invalid token".to_string(),
            // Server errors — hide internal details
            _ => "Internal server error".to_string(),
        };

        let body = serde_json::json!({
            "error": message,
            "code": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<GrcError> for AppError {
    fn from(err: GrcError) -> Self {
        AppError(err)
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;
