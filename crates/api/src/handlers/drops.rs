//! Drop creation and retrieval endpoints.
//!
//! Drops are ephemeral encrypted secrets designed for one-time secret sharing
//! (e.g., sharing a database password instead of pasting it in Slack).
//!
//! ## Storage
//!
//! - Drops are stored in Redis with automatic expiration via TTL
//! - Each drop is encrypted client-side before upload (end-to-end encryption)
//! - Server only stores ciphertext, never sees plaintext
//!
//! ## Redis Structure
//!
//! ```text
//! drop:{uuid} → StoredDrop JSON (auto-expires via TTL)
//! inbox:{user_id} → sorted set of drop IDs (score = expiration timestamp)
//! ratelimit:drops:{user_id}:{YYYY-MM} → monthly drop count (free tier, auto-expires)
//! ratelimit:drops:external:{user_id}:{YYYY-MM} → monthly external drop count (paid tier, auto-expires)
//! ```
//!
//! ## Rate Limiting
//!
//! - **Free tier**: 50 sends/month total
//! - **Paid workspace**: Unlimited internal sends, 50/month external sends
//!
//! ## Endpoints
//!
//! - POST /drops/create - Store an encrypted drop
//! - GET /drops/inbox - List all drops for the authenticated user
//! - GET /drops/{id} - Retrieve a specific drop (verifies recipient access)
//! - DELETE /drops/{id} - Delete a drop (sender only)

use axum::{
    Json, Router, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{Datelike, Months, TimeZone, Utc};
use garde::Validate;
use redis::AsyncCommands;
use shared::api::{CreateDropPayload, CreateDropResponse, Drop, InboxItem};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{StoredDrop, User, Workspace},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/create", post(create_drop))
        .route("/inbox", get(get_inbox))
        .route("/{id}", get(get_drop).delete(delete_drop))
}

/// Check and increment a rate limit counter.
/// Returns an error if the limit is exceeded.
async fn check_rate_limit(
    redis: &mut redis::aio::MultiplexedConnection,
    key: &str,
    limit: i64,
    error_msg: &'static str,
    now: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let count: i64 = redis::cmd("INCR")
        .arg(key)
        .query_async(redis)
        .await?;

    if count == 1 {
        // First request this month - set TTL to expire at start of next month
        let start_of_month = Utc
            .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
            .single()
            .ok_or_else(|| anyhow::anyhow!("failed to calculate start of month"))?;
        let next_month = start_of_month + Months::new(1);
        let ttl = (next_month - now).num_seconds();

        let _: () = redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl)
            .query_async(redis)
            .await?;
    }

    if count > limit {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            error_msg,
        ));
    }

    Ok(())
}

#[debug_handler]
async fn create_drop(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<CreateDropPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate_with(&Utc::now())
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let now = Utc::now();

    // Get sender's email for metadata and rate limiting
    let sender = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    // Extract sender's email domain
    let sender_domain = sender
        .email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid sender email format")))?
        .to_string();

    // Check if sender belongs to a paid workspace
    let paid_workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT w.*
        FROM workspaces w
        JOIN workspace_domains wd ON wd.workspace_id = w.id
        WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
        AND (w.subscription_status = 'active' OR w.subscription_status = 'past_due')
        "#,
        &sender_domain
    )
    .fetch_optional(&state.database)
    .await?;

    // Collect recipient emails
    let recipient_emails: Vec<String> = payload
        .wrapped_keys
        .iter()
        .map(|wk| wk.recipient_email.clone())
        .collect();

    if let Some(workspace) = paid_workspace {
        // Paid workspace: unlimited internal, 50/month external
        // Get all verified domains for this workspace
        let workspace_domains: Vec<String> = sqlx::query_scalar!(
            r#"
            SELECT domain FROM workspace_domains
            WHERE workspace_id = $1 AND verified_at IS NOT NULL
            "#,
            workspace.id
        )
        .fetch_all(&state.database)
        .await?;

        // Count external recipients (domains not in workspace)
        let external_count = recipient_emails
            .iter()
            .filter(|email| {
                let recipient_domain = email.split('@').nth(1).unwrap_or("");
                !workspace_domains.iter().any(|d| d == recipient_domain)
            })
            .count();

        if external_count > 0 {
            // Apply external rate limit
            check_rate_limit(
                &mut redis,
                &format!("ratelimit:drops:external:{}:{}", user.id, now.format("%Y-%m")),
                50,
                "Monthly external recipient limit exceeded (50/month). Internal sends are unlimited.",
                now,
            )
            .await?;
        }
        // If all recipients are internal, no rate limit applies
    } else {
        // Free tier: 50 sends/month total
        check_rate_limit(
            &mut redis,
            &format!("ratelimit:drops:{}:{}", user.id, now.format("%Y-%m")),
            50,
            "Monthly limit exceeded (50 drops/month)",
            now,
        )
        .await?;
    }

    // Verify all recipients exist and are verified, and collect their user IDs.
    // This catches typos early and prevents sending secrets to non-existent users.
    let mut recipient_user_ids: Vec<Uuid> = Vec::with_capacity(recipient_emails.len());
    for email in &recipient_emails {
        let recipient = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1 AND verified_at IS NOT NULL",
            email
        )
        .fetch_optional(&state.database)
        .await?;

        match recipient {
            Some(user) => recipient_user_ids.push(user.id),
            None => {
                return Err(AppError::External(
                    StatusCode::BAD_REQUEST,
                    "One or more recipients not found",
                ));
            }
        }
    }

    let drop_id = Uuid::new_v4();
    let created_at = Utc::now();

    // Calculate TTL in seconds
    let ttl = (payload.expires_at - created_at).num_seconds().max(0) as u64;

    // Store drop in Redis as JSON
    let stored_drop = StoredDrop {
        id: drop_id.to_string(),
        sender_email: sender.email.clone(),
        sender_public_key: payload.sender_public_key,
        ciphertext: payload.ciphertext,
        aes_nonce: payload.aes_nonce,
        wrapped_keys: payload.wrapped_keys,
        created_at,
        once: payload.once,
    };

    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let drop_key = format!("drop:{}", drop_id);

    // Store the drop with TTL
    let _: () = redis
        .set(&drop_key, serde_json::to_string(&stored_drop)?)
        .await?;
    let _: () = redis.expire(&drop_key, ttl as i64).await?;

    // Add drop ID to each recipient's inbox. Using a sorted set with expiration
    // timestamp as the score allows efficient querying of non-expired drops.
    let expiration_score = payload.expires_at.timestamp() as f64;
    for user_id in &recipient_user_ids {
        let inbox_key = format!("inbox:{}", user_id);
        let _: () = redis
            .zadd(&inbox_key, drop_id.to_string(), expiration_score)
            .await?;
    }

    tracing::info!(
        drop_id = %drop_id,
        sender_id = %user.id,
        recipient_count = recipient_emails.len(),
        "drop created"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateDropResponse {
            id: drop_id.to_string(),
        }),
    ))
}

#[debug_handler]
async fn get_inbox(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let inbox_key = format!("inbox:{}", user.id);

    // Query inbox sorted set for drops with expiration >= now. Using ZRANGEBYSCORE
    // with the current timestamp filters out expired drops efficiently.
    let now = Utc::now().timestamp() as f64;
    let drop_ids: Vec<String> = redis
        .zrangebyscore(&inbox_key, now, f64::MAX)
        .await
        .unwrap_or_default();

    let mut items = Vec::new();

    // Fetch full drop data for each ID. Drops that expired (TTL hit) will return None
    // and are silently skipped (lazy cleanup - inbox entries are stale but harmless).
    for drop_id in drop_ids {
        let drop_key = format!("drop:{}", drop_id);
        let drop_json: Option<String> = redis.get(&drop_key).await?;

        if let Some(json) = drop_json
            && let Ok(drop) = serde_json::from_str::<StoredDrop>(&json)
        {
            items.push(InboxItem {
                id: drop_id,
                sender_email: drop.sender_email,
                created_at: drop.created_at,
            });
        }
    }

    Ok(Json(items))
}

#[debug_handler]
async fn get_drop(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let recipient = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let drop_key = format!("drop:{}", id);

    let drop_json: Option<String> = redis.get(&drop_key).await?;

    let drop_json =
        drop_json.ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "Drop not found"))?;

    let stored_drop: StoredDrop = serde_json::from_str(&drop_json)?;

    // Verify this user is a recipient. Prevents unauthorized access even if
    // someone guesses or intercepts a drop ID.
    let is_recipient = stored_drop
        .wrapped_keys
        .iter()
        .any(|wk| wk.recipient_email == recipient.email);

    if !is_recipient {
        return Err(AppError::External(
            StatusCode::FORBIDDEN,
            "Not authorized to view this drop",
        ));
    }

    tracing::info!(drop_id = %id, user_id = %user.id, once = stored_drop.once, "drop accessed");

    // If burn-after-reading is enabled, delete the drop after retrieval
    if stored_drop.once {
        // Delete the drop from Redis
        let _: () = redis.del(&drop_key).await?;

        // Remove from all recipients' inboxes
        for wk in &stored_drop.wrapped_keys {
            if let Some(recipient_user) = sqlx::query_as!(
                User,
                "SELECT * FROM users WHERE email = $1",
                wk.recipient_email
            )
            .fetch_optional(&state.database)
            .await?
            {
                let inbox_key = format!("inbox:{}", recipient_user.id);
                let _: () = redis.zrem(&inbox_key, id.to_string()).await?;
            }
        }

        tracing::info!(drop_id = %id, "drop burned after reading");
    }

    // Convert to response format
    let drop = Drop {
        id: stored_drop.id,
        sender_email: stored_drop.sender_email,
        sender_public_key: stored_drop.sender_public_key,
        ciphertext: stored_drop.ciphertext,
        aes_nonce: stored_drop.aes_nonce,
        wrapped_keys: stored_drop.wrapped_keys,
        created_at: stored_drop.created_at,
        once: stored_drop.once,
    };

    Ok(Json(drop))
}

/// Deletes a drop. Only the sender can delete their own drops.
/// Returns 200 OK even if the drop already expired or doesn't exist (idempotent).
#[debug_handler]
async fn delete_drop(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let sender = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user.id)
        .fetch_one(&state.database)
        .await?;

    let mut redis = state.redis.get_multiplexed_async_connection().await?;
    let drop_key = format!("drop:{}", id);

    // Check if drop exists and verify ownership before deleting
    let drop_json: Option<String> = redis.get(&drop_key).await?;

    if let Some(json) = drop_json {
        let stored_drop: StoredDrop = serde_json::from_str(&json)?;

        // Only the sender can delete their own drops
        if stored_drop.sender_email != sender.email {
            return Err(AppError::External(
                StatusCode::FORBIDDEN,
                "Not authorized to delete this drop",
            ));
        }

        // Delete the drop
        let _: () = redis.del(&drop_key).await?;

        // Remove from all recipients' inboxes (look up user IDs from emails)
        for wk in &stored_drop.wrapped_keys {
            if let Some(recipient) = sqlx::query_as!(
                User,
                "SELECT * FROM users WHERE email = $1",
                wk.recipient_email
            )
            .fetch_optional(&state.database)
            .await?
            {
                let inbox_key = format!("inbox:{}", recipient.id);
                let _: () = redis.zrem(&inbox_key, id.to_string()).await?;
            }
        }

        tracing::info!(drop_id = %id, user_id = %user.id, "drop deleted");
    }

    // Return success even if drop didn't exist (idempotent)
    Ok(StatusCode::OK)
}
