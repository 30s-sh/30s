//! Email-based passwordless authentication.
//!
//! Flow:
//! 1. User requests a code via POST /auth/code with their email
//! 2. A 6-digit code is generated, hashed (SHA256), and stored in Redis keyed by the hash
//! 3. The plaintext code is emailed to the user
//! 4. User submits email + code to POST /auth/verify
//! 5. Code is hashed and looked up in Redis; if valid and email matches, user is created/verified
//! 6. An Unkey API key is generated and returned to the user
//!
//! Security notes:
//! - Codes are hashed before storage (Redis compromise doesn't leak valid codes)
//! - Codes expire after 15 minutes
//! - Already-verified users get 200 OK (prevents email enumeration)
//! - Code is only deleted after full validation (email mismatch doesn't invalidate legitimate codes)
//! - Rate limiting should be handled by a reverse proxy (Caddy, Kong, etc.)

use axum::{
    Json, Router, debug_handler,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Utc;
use garde::Validate;
use rand::Rng;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::api::{
    MeResponse, RequestCodePayload, RotateVerifyPayload, RotateVerifyResponse, VerifyCodePayload,
    VerifyCodeResponse,
};

use crate::{error::AppError, middleware::auth::AuthUser, models::User, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/code", post(request_code))
        .route("/verify", post(verify_code))
        .route("/me", get(get_me).delete(delete_account))
        .route("/rotate", post(request_rotate))
        .route("/rotate/verify", post(verify_rotate))
}

#[debug_handler]
async fn get_me(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    Ok(Json(MeResponse { email: user.email }))
}

/// Stored in Redis, keyed by the hashed code. The email field lets us verify
/// the code was requested by the same email attempting to use it.
#[derive(Debug, Serialize, Deserialize)]
struct VerifyState {
    email: String,
    code: String,
    created_at: i64,
}

#[debug_handler]
async fn request_code(
    State(state): State<AppState>,
    Json(payload): Json<RequestCodePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Rate limit: 5 code requests per hour per email
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let ratelimit_key = format!("ratelimit:code:{}", payload.email);

    let count: i64 = redis::cmd("INCR")
        .arg(&ratelimit_key)
        .query_async(&mut redis)
        .await?;

    if count == 1 {
        // First request - set 1 hour TTL
        let _: () = redis::cmd("EXPIRE")
            .arg(&ratelimit_key)
            .arg(3600)
            .query_async(&mut redis)
            .await?;
    }

    if count > 5 {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many code requests. Try again later.",
        ));
    }

    let code: String = {
        let mut rng = rand::rng();
        (0..6)
            .map(|_| rng.random_range(0..10).to_string())
            .collect()
    };

    // Hash the code so it can't be stolen from Redis
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // Store keyed by hash so verification is O(1) lookup. TTL of 15 minutes.
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let _: () = redis
        .set_ex(
            format!("verify-{}", hashed),
            serde_json::to_string(&VerifyState {
                email: payload.email.clone(),
                code: hashed.clone(),
                created_at: Utc::now().timestamp(),
            })?,
            15 * 60,
        )
        .await?;

    state
        .email
        .send_verification_code(&payload.email, &code)
        .await?;

    tracing::info!(email = %payload.email, "verification code requested");

    Ok(StatusCode::OK)
}

#[debug_handler]
async fn verify_code(
    State(state): State<AppState>,
    Json(payload): Json<VerifyCodePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Rate limit: 10 verify attempts per 15 minutes per email
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let ratelimit_key = format!("ratelimit:verify:{}", payload.email);

    let count: i64 = redis::cmd("INCR")
        .arg(&ratelimit_key)
        .query_async(&mut redis)
        .await?;

    if count == 1 {
        // First attempt - set 15 minute TTL
        let _: () = redis::cmd("EXPIRE")
            .arg(&ratelimit_key)
            .arg(15 * 60)
            .query_async(&mut redis)
            .await?;
    }

    if count > 10 {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many verification attempts. Try again later.",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(payload.code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // GET first, DEL only after full validation. This way an attacker guessing
    // a valid code with the wrong email doesn't invalidate the legitimate user's code.
    let code_key = format!("verify-{}", hashed);
    let code: Option<String> = redis.get(&code_key).await?;

    let verify_state = match code
        .map(|c| serde_json::from_str::<VerifyState>(&c))
        .transpose()?
    {
        Some(state) => state,
        None => {
            tracing::warn!(email = %payload.email, "verification failed: invalid code");
            return Ok(AppError::External(StatusCode::BAD_REQUEST, "Invalid code").into_response());
        }
    };

    // Prevents using an intercepted code with a different email
    if verify_state.email != payload.email {
        tracing::warn!(email = %payload.email, "verification failed: email mismatch");
        return Ok(AppError::External(StatusCode::BAD_REQUEST, "Invalid code").into_response());
    }

    // Code validated, now safe to delete
    let _: () = redis.del(&code_key).await?;

    // Create user on verify (not on code request) so we don't store unverified emails
    let user = match sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", payload.email)
        .fetch_optional(&state.database)
        .await?
    {
        Some(user) => user,
        None => {
            sqlx::query_as!(
                User,
                "INSERT INTO users (email) VALUES ($1) RETURNING *",
                payload.email
            )
            .fetch_one(&state.database)
            .await?
        }
    };

    // Create API key via Unkey
    let key_response = state
        .unkey
        .create_key(user.id.to_string(), format!("30s-cli-{}", &payload.email))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create API key: {}", e))?;

    // Store key_id for revocation/lookup; return the actual key to the user (shown only once)
    sqlx::query_as!(
        User,
        "UPDATE users SET verified_at = now(), unkey_key_id = $2 WHERE email = $1 RETURNING *",
        user.email,
        key_response.key_id
    )
    .fetch_one(&state.database)
    .await?;

    tracing::info!(user_id = %user.id, email = %payload.email, "user verified");

    Ok(Json(VerifyCodeResponse {
        api_key: key_response.key,
    })
    .into_response())
}

/// Request a verification code for API key rotation.
/// Requires authentication with the current API key.
#[debug_handler]
async fn request_rotate(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Look up user's email
    let db_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    let code: String = {
        let mut rng = rand::rng();
        (0..6)
            .map(|_| rng.random_range(0..10).to_string())
            .collect()
    };

    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // Store with "rotate-" prefix to distinguish from init codes
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let _: () = redis
        .set_ex(
            format!("rotate-{}", hashed),
            serde_json::to_string(&VerifyState {
                email: db_user.email.clone(),
                code: hashed.clone(),
                created_at: Utc::now().timestamp(),
            })?,
            15 * 60,
        )
        .await?;

    state
        .email
        .send_verification_code(&db_user.email, &code)
        .await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "rotation code requested");

    Ok(StatusCode::OK)
}

/// Verify the rotation code and issue a new API key.
/// Revokes the old key and returns a new one.
#[debug_handler]
async fn verify_rotate(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<RotateVerifyPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Look up user
    let db_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    let mut hasher = Sha256::new();
    hasher.update(payload.code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let code_key = format!("rotate-{}", hashed);
    let code: Option<String> = redis.get(&code_key).await?;

    let verify_state = match code
        .map(|c| serde_json::from_str::<VerifyState>(&c))
        .transpose()?
    {
        Some(state) => state,
        None => {
            tracing::warn!(user_id = %user.id, "rotation failed: invalid code");
            return Err(AppError::External(StatusCode::BAD_REQUEST, "Invalid code"));
        }
    };

    // Verify the code was requested for this user's email
    if verify_state.email != db_user.email {
        tracing::warn!(user_id = %user.id, "rotation failed: email mismatch");
        return Err(AppError::External(StatusCode::BAD_REQUEST, "Invalid code"));
    }

    // Code validated, delete it
    let _: () = redis.del(&code_key).await?;

    // Revoke old key if it exists
    if let Some(old_key_id) = &db_user.unkey_key_id {
        state
            .unkey
            .delete_key(old_key_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to revoke old API key: {}", e))?;
    }

    // Create new API key
    let key_response = state
        .unkey
        .create_key(
            db_user.id.to_string(),
            format!("30s-cli-{}", &db_user.email),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create API key: {}", e))?;

    // Update stored key_id
    sqlx::query!(
        "UPDATE users SET unkey_key_id = $2 WHERE id = $1",
        db_user.id,
        key_response.key_id
    )
    .execute(&state.database)
    .await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "API key rotated");

    Ok(Json(RotateVerifyResponse {
        api_key: key_response.key,
    }))
}

/// Delete user account and all associated data.
/// Removes: user record, all devices, all drops (sent and received).
#[debug_handler]
async fn delete_account(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let db_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    // Revoke Unkey API key
    if let Some(key_id) = &db_user.unkey_key_id
        && let Err(e) = state.unkey.delete_key(key_id).await
    {
        tracing::warn!(user_id = %user.id, "Failed to revoke Unkey key during account deletion: {}", e);
    }

    // Delete devices (cascade will handle this if FK is set, but be explicit)
    sqlx::query!("DELETE FROM devices WHERE user_id = $1", user.id)
        .execute(&state.database)
        .await?;

    // Delete user (this is the source of truth)
    sqlx::query!("DELETE FROM users WHERE id = $1", user.id)
        .execute(&state.database)
        .await?;

    // Clean up any drops from Redis inbox
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let inbox_key = format!("inbox:{}", user.id);
    let _: () = redis.del(&inbox_key).await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "account deleted");

    Ok(StatusCode::OK)
}
