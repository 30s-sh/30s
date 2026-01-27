//! Authentication middleware using Unkey for API key validation.
//!
//! Usage: Add `AuthUser` as an extractor parameter to require authentication.
//! The user's id is extracted from the Unkey key's owner_id field.
//!
//! ```ignore
//! async fn my_handler(user: AuthUser, ...) -> ... {
//!     // user.id is available here
//! }
//! ```

use axum::{
    Json, RequestPartsExt,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use uuid::Uuid;

use crate::state::AppState;

/// Authenticated user extracted from a valid API key.
/// The email comes from Unkey's owner_id field, set during key creation.
pub struct AuthUser {
    pub id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingToken)?;

        let api_key = bearer.token();

        let result = state.unkey.verify_key(api_key).await.map_err(|e| {
            tracing::error!("Unkey verification error: {:?}", e);
            AuthError::InvalidToken
        })?;

        if !result.valid {
            return Err(AuthError::InvalidToken);
        }

        let id = result.identity.ok_or(AuthError::InvalidToken)?.external_id;

        Ok(AuthUser {
            id: Uuid::parse_str(&id).map_err(|_| AuthError::InvalidToken)?,
        })
    }
}

pub enum AuthError {
    MissingToken,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization token"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid or expired token"),
        };

        let body = serde_json::json!({ "error": message });

        (status, Json(body)).into_response()
    }
}
