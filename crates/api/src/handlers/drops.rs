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
use chrono::Utc;
use garde::Validate;
use shared::api::{AppliedPolicies, CreateDropPayload, CreateDropResponse, Drop, InboxItem};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::StoredDrop,
    repos::{events, is_internal_send},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/create", post(create_drop))
        .route("/inbox", get(get_inbox))
        .route("/{id}", get(get_drop).delete(delete_drop))
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

    let now = Utc::now();

    // Get sender's email for metadata and rate limiting
    let sender = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    // Extract sender's email domain
    let sender_domain = sender
        .email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid sender email format")))?
        .to_string();

    // Check if sender belongs to a paid workspace
    let paid_workspace = state.repos.workspaces.find_paid_by_domain(&sender_domain).await?;

    // Collect recipient emails
    let recipient_emails: Vec<String> = payload
        .wrapped_keys
        .iter()
        .map(|wk| wk.recipient_email.clone())
        .collect();

    // Track applied policies for response
    let mut applied_policies: Option<AppliedPolicies> = None;

    // Calculate requested TTL in seconds
    let requested_ttl = (payload.expires_at - now).num_seconds();

    // Mutable copies for policy modifications
    let mut effective_expires_at = payload.expires_at;
    let mut effective_once = payload.once;

    // Store workspace domains for reuse in activity logging
    let mut workspace_domains: Option<Vec<String>> = None;

    if let Some(ref workspace) = paid_workspace {
        // Paid workspace: unlimited internal, 50/month external
        // Get all verified domains for this workspace
        let domains = state.repos.workspaces.get_verified_domains(workspace.id).await?;
        workspace_domains = Some(domains);
        // Use the stored domains - safe because we just set it
        let domains = workspace_domains.as_ref().unwrap();

        // Fetch workspace policies
        let policy = state.repos.workspaces.get_policy(workspace.id).await?;

        // Apply policy validations and defaults
        if let Some(ref p) = policy {
            // Validate TTL against min/max
            if let Some(min_ttl) = p.min_ttl_seconds
                && requested_ttl < min_ttl as i64
            {
                state
                    .repos
                    .activity
                    .log(
                        workspace.id,
                        events::DROP_FAILED,
                        user.id,
                        None,
                        serde_json::json!({
                            "reason": "ttl_below_minimum",
                            "requested_ttl": requested_ttl,
                            "min_ttl": min_ttl,
                        }),
                    )
                    .await;
                return Err(AppError::External(
                    StatusCode::BAD_REQUEST,
                    "TTL below workspace minimum",
                ));
            }
            if let Some(max_ttl) = p.max_ttl_seconds
                && requested_ttl > max_ttl as i64
            {
                state
                    .repos
                    .activity
                    .log(
                        workspace.id,
                        events::DROP_FAILED,
                        user.id,
                        None,
                        serde_json::json!({
                            "reason": "ttl_exceeds_maximum",
                            "requested_ttl": requested_ttl,
                            "max_ttl": max_ttl,
                        }),
                    )
                    .await;
                return Err(AppError::External(
                    StatusCode::BAD_REQUEST,
                    "TTL exceeds workspace maximum",
                ));
            }

            // Check allow_external policy
            if p.allow_external == Some(false) {
                for email in &recipient_emails {
                    let recipient_domain = email.split('@').nth(1).ok_or_else(|| {
                        AppError::Validation(format!("Invalid email format: {}", email))
                    })?;
                    if !domains.iter().any(|d| d == recipient_domain) {
                        state
                            .repos
                            .activity
                            .log(
                                workspace.id,
                                events::DROP_FAILED,
                                user.id,
                                None,
                                serde_json::json!({
                                    "reason": "external_recipients_blocked",
                                    "recipient_count": recipient_emails.len(),
                                }),
                            )
                            .await;
                        return Err(AppError::External(
                            StatusCode::FORBIDDEN,
                            "Workspace policy prohibits sending to external recipients",
                        ));
                    }
                }
            }

            // Apply default TTL if user used the 30s default
            if requested_ttl == 30
                && let Some(default_ttl) = p.default_ttl_seconds
            {
                effective_expires_at = now + chrono::Duration::seconds(default_ttl as i64);
                applied_policies = Some(AppliedPolicies {
                    default_ttl_applied: Some(default_ttl),
                    once_enforced: None,
                });
            }

            // Apply require_once or default_once
            if p.require_once == Some(true) && !payload.once {
                effective_once = true;
                applied_policies = Some(AppliedPolicies {
                    default_ttl_applied: applied_policies
                        .as_ref()
                        .and_then(|a| a.default_ttl_applied),
                    once_enforced: Some(true),
                });
            } else if p.default_once == Some(true) && !payload.once {
                effective_once = true;
                applied_policies = Some(AppliedPolicies {
                    default_ttl_applied: applied_policies
                        .as_ref()
                        .and_then(|a| a.default_ttl_applied),
                    once_enforced: Some(true),
                });
            }
        }

        // Count external recipients (domains not in workspace)
        // Note: Email format already validated above in allow_external check,
        // but we still handle the case gracefully for non-policy paths
        let external_count = recipient_emails
            .iter()
            .filter(|email| {
                let recipient_domain = match email.split('@').nth(1) {
                    Some(domain) => domain,
                    None => return true, // Treat invalid emails as external (will fail recipient lookup anyway)
                };
                !domains.iter().any(|d| d == recipient_domain)
            })
            .count();

        if external_count > 0 {
            // Apply external rate limit
            let result = state
                .stores
                .rate_limiter
                .check_monthly("ratelimit:drops:external", &user.id.to_string(), 50, now)
                .await?;
            if !result.is_allowed() {
                state
                    .repos
                    .activity
                    .log(
                        workspace.id,
                        events::DROP_FAILED,
                        user.id,
                        None,
                        serde_json::json!({
                            "reason": "external_rate_limit_exceeded",
                            "external_count": external_count,
                        }),
                    )
                    .await;
                return Err(AppError::External(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Monthly external recipient limit exceeded (50/month). Internal sends are unlimited.",
                ));
            }
        }
        // If all recipients are internal, no rate limit applies
    } else {
        // Free tier: 50 sends/month total (no workspace to log to)
        let result = state
            .stores
            .rate_limiter
            .check_monthly("ratelimit:drops", &user.id.to_string(), 50, now)
            .await?;
        if !result.is_allowed() {
            return Err(AppError::External(
                StatusCode::TOO_MANY_REQUESTS,
                "Monthly limit exceeded (50 drops/month)",
            ));
        }
    }

    // Verify all recipients exist and are verified, and collect their user IDs.
    // This catches typos early and prevents sending secrets to non-existent users.
    let mut recipient_user_ids: Vec<Uuid> = Vec::with_capacity(recipient_emails.len());
    for email in &recipient_emails {
        let recipient = state.repos.users.find_verified_by_email(email).await?;

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

    // Calculate TTL in seconds (using effective expiration which may be adjusted by policy)
    let ttl = (effective_expires_at - created_at).num_seconds().max(0) as u64;

    // Store drop in Redis as JSON
    let stored_drop = StoredDrop {
        id: drop_id.to_string(),
        sender_email: sender.email.clone(),
        sender_public_key: payload.sender_public_key,
        ciphertext: payload.ciphertext,
        aes_nonce: payload.aes_nonce,
        wrapped_keys: payload.wrapped_keys,
        created_at,
        once: effective_once,
    };

    // Store the drop with TTL
    state.stores.drops.store(&stored_drop, ttl).await?;

    // Add drop ID to each recipient's inbox. Using a sorted set with expiration
    // timestamp as the score allows efficient querying of non-expired drops.
    let expiration_score = effective_expires_at.timestamp() as f64;
    for user_id in &recipient_user_ids {
        state
            .stores
            .inbox
            .add(*user_id, &drop_id.to_string(), expiration_score)
            .await?;
    }

    tracing::info!(
        drop_id = %drop_id,
        sender_id = %user.id,
        recipient_count = recipient_emails.len(),
        "drop created"
    );

    // Log activity if sender belongs to a paid workspace
    if let Some(ref workspace) = paid_workspace {
        // Use workspace_domains we fetched earlier (safe unwrap, always set for paid workspaces)
        let domains = workspace_domains.as_ref().unwrap();
        let is_internal = is_internal_send(&recipient_emails, domains);

        state
            .repos
            .activity
            .log(
                workspace.id,
                events::DROP_SENT,
                user.id,
                Some(drop_id),
                serde_json::json!({
                    "recipient_count": recipient_emails.len(),
                    "internal": is_internal,
                    "once": effective_once,
                }),
            )
            .await;
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateDropResponse {
            id: drop_id.to_string(),
            applied_policies,
        }),
    ))
}

#[debug_handler]
async fn get_inbox(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let now = Utc::now().timestamp() as f64;

    // Clean up expired entries (score < now) on each inbox access.
    // This prevents unbounded growth of stale entries over time.
    state.stores.inbox.cleanup_expired(user.id, now).await?;

    // Query inbox sorted set for drops with expiration >= now.
    let drop_ids = state.stores.inbox.get_active(user.id, now).await?;

    let mut items = Vec::new();

    // Fetch full drop data for each ID. Drops that expired (TTL hit) will return None
    // and are silently skipped (lazy cleanup - inbox entries are stale but harmless).
    for drop_id in drop_ids {
        if let Some(drop) = state.stores.drops.get(&drop_id).await? {
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
    let recipient = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let stored_drop = state
        .stores
        .drops
        .get(&id.to_string())
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "Drop not found"))?;

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

    // Log activity if either sender or recipient belongs to a paid workspace
    // We log to the sender's workspace (they own the drop)
    let sender_domain = stored_drop
        .sender_email
        .split('@')
        .nth(1)
        .unwrap_or_default();

    if let Ok(Some(sender_workspace)) = state
        .repos
        .workspaces
        .find_paid_by_domain(sender_domain)
        .await
    {
        state
            .repos
            .activity
            .log(
                sender_workspace.id,
                events::DROP_OPENED,
                user.id,
                Some(id),
                serde_json::json!({
                    "sender_email": stored_drop.sender_email,
                }),
            )
            .await;
    }

    // If burn-after-reading is enabled, delete the drop after retrieval
    if stored_drop.once {
        // Delete the drop from Redis
        state.stores.drops.delete(&id.to_string()).await?;

        // Remove from all recipients' inboxes
        for wk in &stored_drop.wrapped_keys {
            if let Some(recipient_user) = state.repos.users.find_by_email(&wk.recipient_email).await?
            {
                state
                    .stores
                    .inbox
                    .remove(recipient_user.id, &id.to_string())
                    .await?;
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
    let sender = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    // Check if drop exists and verify ownership before deleting
    let stored_drop = state.stores.drops.get(&id.to_string()).await?;

    if let Some(stored_drop) = stored_drop {
        // Only the sender can delete their own drops
        if stored_drop.sender_email != sender.email {
            return Err(AppError::External(
                StatusCode::FORBIDDEN,
                "Not authorized to delete this drop",
            ));
        }

        // Delete the drop
        state.stores.drops.delete(&id.to_string()).await?;

        // Remove from all recipients' inboxes (look up user IDs from emails)
        for wk in &stored_drop.wrapped_keys {
            if let Some(recipient) = state.repos.users.find_by_email(&wk.recipient_email).await? {
                state
                    .stores
                    .inbox
                    .remove(recipient.id, &id.to_string())
                    .await?;
            }
        }

        tracing::info!(drop_id = %id, user_id = %user.id, "drop deleted");

        // Log activity if sender belongs to a paid workspace
        let sender_domain = stored_drop
            .sender_email
            .split('@')
            .nth(1)
            .unwrap_or_default();

        if let Ok(Some(workspace)) = state
            .repos
            .workspaces
            .find_paid_by_domain(sender_domain)
            .await
        {
            let recipient_count = stored_drop.wrapped_keys.len();
            state
                .repos
                .activity
                .log(
                    workspace.id,
                    events::DROP_DELETED,
                    user.id,
                    Some(id),
                    serde_json::json!({
                        "recipient_count": recipient_count,
                    }),
                )
                .await;
        }
    }

    // Return success even if drop didn't exist (idempotent)
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{MockActivityRepo, MockUserRepo, MockWorkspaceRepo};
    use crate::stores::{MockDropStore, MockInboxStore, MockRateLimiter, RateLimitResult};
    use crate::test_utils::{
        mock_policy, mock_stored_drop, mock_user, mock_workspace, TestStateBuilder,
    };
    use axum::http::StatusCode;
    use shared::api::WrappedKeyPayload;

    #[tokio::test]
    async fn get_inbox_returns_empty_when_no_drops() {
        let user_id = Uuid::new_v4();

        let mut inbox_store = MockInboxStore::new();
        inbox_store
            .expect_cleanup_expired()
            .returning(|_, _| Ok(()));
        inbox_store
            .expect_get_active()
            .returning(|_, _| Ok(vec![]));

        let state = TestStateBuilder::new()
            .with_inbox_store(inbox_store)
            .build();

        let result = get_inbox(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_inbox_returns_drops_for_user() {
        let user_id = Uuid::new_v4();
        let drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        let drop_id = drop.id.clone();

        let mut inbox_store = MockInboxStore::new();
        inbox_store
            .expect_cleanup_expired()
            .returning(|_, _| Ok(()));
        inbox_store
            .expect_get_active()
            .returning(move |_, _| Ok(vec![drop_id.clone()]));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));

        let state = TestStateBuilder::new()
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .build();

        let result = get_inbox(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_drop_returns_drop_for_recipient() {
        let recipient = mock_user("recipient@example.com");
        let recipient_id = recipient.id;
        let drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        let drop_id: Uuid = drop.id.parse().unwrap();

        let mut user_repo = MockUserRepo::new();
        let recipient_clone = recipient.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(recipient_clone.clone())));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_workspace_repo(workspace_repo)
            .build();

        let result = get_drop(AuthUser { id: recipient_id }, State(state), Path(drop_id))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_drop_returns_forbidden_for_non_recipient() {
        let non_recipient = mock_user("other@example.com");
        let non_recipient_id = non_recipient.id;
        let drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        let drop_id: Uuid = drop.id.parse().unwrap();

        let mut user_repo = MockUserRepo::new();
        let user_clone = non_recipient.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .build();

        let result = get_drop(
            AuthUser {
                id: non_recipient_id,
            },
            State(state),
            Path(drop_id),
        )
        .await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn get_drop_returns_not_found_for_missing_drop() {
        let user = mock_user("recipient@example.com");
        let user_id = user.id;
        let drop_id = Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut drop_store = MockDropStore::new();
        drop_store.expect_get().returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .build();

        let result = get_drop(AuthUser { id: user_id }, State(state), Path(drop_id)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn delete_drop_returns_ok_for_sender() {
        let sender = mock_user("sender@example.com");
        let sender_id = sender.id;
        let drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        let drop_id: Uuid = drop.id.parse().unwrap();

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));
        user_repo.expect_find_by_email().returning(|_| Ok(None));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));
        drop_store.expect_delete().returning(|_| Ok(true));

        let mut inbox_store = MockInboxStore::new();
        inbox_store.expect_remove().returning(|_, _| Ok(()));

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .with_workspace_repo(workspace_repo)
            .build();

        let result = delete_drop(AuthUser { id: sender_id }, State(state), Path(drop_id))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_drop_returns_forbidden_for_non_sender() {
        let non_sender = mock_user("other@example.com");
        let non_sender_id = non_sender.id;
        let drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        let drop_id: Uuid = drop.id.parse().unwrap();

        let mut user_repo = MockUserRepo::new();
        let user_clone = non_sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .build();

        let result = delete_drop(
            AuthUser {
                id: non_sender_id,
            },
            State(state),
            Path(drop_id),
        )
        .await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn delete_drop_returns_ok_even_when_not_found() {
        let user = mock_user("sender@example.com");
        let user_id = user.id;
        let drop_id = Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut drop_store = MockDropStore::new();
        drop_store.expect_get().returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .build();

        let result = delete_drop(AuthUser { id: user_id }, State(state), Path(drop_id))
            .await
            .unwrap();

        // Idempotent - returns OK even when drop doesn't exist
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_drop_with_once_flag_deletes_after_read() {
        let recipient = mock_user("recipient@example.com");
        let recipient_id = recipient.id;
        let mut drop = mock_stored_drop("sender@example.com", "recipient@example.com");
        drop.once = true; // Burn-after-reading
        let drop_id: Uuid = drop.id.parse().unwrap();

        let mut user_repo = MockUserRepo::new();
        let recipient_clone = recipient.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(recipient_clone.clone())));
        user_repo.expect_find_by_email().returning(|_| Ok(None));

        let mut drop_store = MockDropStore::new();
        let drop_clone = drop.clone();
        drop_store
            .expect_get()
            .returning(move |_| Ok(Some(drop_clone.clone())));
        drop_store
            .expect_delete()
            .times(1)
            .returning(|_| Ok(true));

        let mut inbox_store = MockInboxStore::new();
        inbox_store.expect_remove().returning(|_, _| Ok(()));

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .with_workspace_repo(workspace_repo)
            .build();

        let result = get_drop(AuthUser { id: recipient_id }, State(state), Path(drop_id))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // create_drop tests

    fn mock_create_drop_payload(recipient_email: &str) -> CreateDropPayload {
        CreateDropPayload {
            sender_public_key: "sender-pubkey-base64".to_string(),
            ciphertext: "encrypted-data-base64".to_string(),
            aes_nonce: "nonce-base64".to_string(),
            wrapped_keys: vec![WrappedKeyPayload {
                recipient_email: recipient_email.to_string(),
                nonce: "wrap-nonce".to_string(),
                wrapped_key: "wrapped-aes-key".to_string(),
            }],
            expires_at: Utc::now() + chrono::Duration::seconds(30),
            once: false,
        }
    }

    #[tokio::test]
    async fn create_drop_returns_rate_limited_for_free_tier() {
        let sender = mock_user("sender@example.com");
        let sender_id = sender.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None)); // Free tier

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_monthly()
            .returning(|_, _, _, _| Ok(RateLimitResult::Exceeded(51)));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_workspace_repo(workspace_repo)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = mock_create_drop_payload("recipient@example.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert!(msg.contains("50 drops/month"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_returns_bad_request_for_missing_recipient() {
        let sender = mock_user("sender@example.com");
        let sender_id = sender.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));
        user_repo
            .expect_find_verified_by_email()
            .returning(|_| Ok(None)); // Recipient not found

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_monthly()
            .returning(|_, _, _, _| Ok(RateLimitResult::Allowed(1)));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_workspace_repo(workspace_repo)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = mock_create_drop_payload("nonexistent@example.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert!(msg.contains("recipients not found"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_succeeds_for_free_tier() {
        let sender = mock_user("sender@example.com");
        let sender_id = sender.id;
        let recipient = mock_user("recipient@example.com");

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));
        let recipient_clone = recipient.clone();
        user_repo
            .expect_find_verified_by_email()
            .returning(move |_| Ok(Some(recipient_clone.clone())));

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_monthly()
            .returning(|_, _, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut drop_store = MockDropStore::new();
        drop_store.expect_store().returning(|_, _| Ok(()));

        let mut inbox_store = MockInboxStore::new();
        inbox_store.expect_add().returning(|_, _, _| Ok(()));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .with_rate_limiter(rate_limiter)
            .with_workspace_repo(workspace_repo)
            .build();

        let payload = mock_create_drop_payload("recipient@example.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_drop_returns_validation_error_for_expired_timestamp() {
        let sender = mock_user("sender@example.com");
        let sender_id = sender.id;

        let state = TestStateBuilder::new().build();

        let mut payload = mock_create_drop_payload("recipient@example.com");
        payload.expires_at = Utc::now() - chrono::Duration::seconds(60); // Past timestamp

        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::Validation(msg) => {
                assert!(msg.contains("expires_at"));
            }
            _ => panic!("Expected Validation error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_returns_not_found_when_sender_missing() {
        let sender_id = Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_id().returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .build();

        let payload = mock_create_drop_payload("recipient@example.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    // Workspace policy tests

    #[tokio::test]
    async fn create_drop_rejects_ttl_below_minimum() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));

        // Policy with min_ttl of 60 seconds
        let mut policy = mock_policy(workspace_id);
        policy.min_ttl_seconds = Some(60);
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(policy.clone())));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Payload with 30s TTL (below 60s minimum)
        let payload = mock_create_drop_payload("recipient@acme.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert!(msg.contains("below workspace minimum"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_rejects_ttl_above_maximum() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));

        // Policy with max_ttl of 60 seconds
        let mut policy = mock_policy(workspace_id);
        policy.max_ttl_seconds = Some(60);
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(policy.clone())));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Payload with 2 hour TTL (above 60s maximum)
        let mut payload = mock_create_drop_payload("recipient@acme.com");
        payload.expires_at = Utc::now() + chrono::Duration::hours(2);
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert!(msg.contains("exceeds workspace maximum"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_blocks_external_recipients_when_policy_forbids() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));

        // Policy forbids external recipients
        let mut policy = mock_policy(workspace_id);
        policy.allow_external = Some(false);
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(policy.clone())));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Try to send to external recipient (different domain)
        let payload = mock_create_drop_payload("recipient@external.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(msg.contains("external recipients"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_enforces_require_once_policy() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let recipient = mock_user("recipient@acme.com");
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));
        let recipient_clone = recipient.clone();
        user_repo
            .expect_find_verified_by_email()
            .returning(move |_| Ok(Some(recipient_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));

        // Policy requires once (burn-after-reading)
        let mut policy = mock_policy(workspace_id);
        policy.require_once = Some(true);
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(policy.clone())));

        let mut drop_store = MockDropStore::new();
        // Verify that the drop is stored with once=true
        drop_store
            .expect_store()
            .withf(|drop, _| drop.once)
            .returning(|_, _| Ok(()));

        let mut inbox_store = MockInboxStore::new();
        inbox_store.expect_add().returning(|_, _, _| Ok(()));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Payload explicitly sets once=false, but policy should override
        let mut payload = mock_create_drop_payload("recipient@acme.com");
        payload.once = false;
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_drop_rate_limits_external_recipients_for_paid_workspace() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(mock_policy(workspace_id))));

        // External rate limit exceeded (50/month for external)
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_monthly()
            .returning(|_, _, _, _| Ok(RateLimitResult::Exceeded(51)));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_rate_limiter(rate_limiter)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Send to external recipient
        let payload = mock_create_drop_payload("recipient@external.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, msg) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert!(msg.contains("external recipient limit"));
            }
            _ => panic!("Expected External error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn create_drop_allows_unlimited_internal_for_paid_workspace() {
        let sender = mock_user("sender@acme.com");
        let sender_id = sender.id;
        let recipient = mock_user("recipient@acme.com");
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut user_repo = MockUserRepo::new();
        let sender_clone = sender.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(sender_clone.clone())));
        let recipient_clone = recipient.clone();
        user_repo
            .expect_find_verified_by_email()
            .returning(move |_| Ok(Some(recipient_clone.clone())));

        let workspace_clone = workspace.clone();
        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));
        workspace_repo
            .expect_get_verified_domains()
            .returning(|_| Ok(vec!["acme.com".to_string()]));
        workspace_repo
            .expect_get_policy()
            .returning(move |_| Ok(Some(mock_policy(workspace_id))));

        // No rate limiter expectations - internal sends should NOT check rate limit
        let rate_limiter = MockRateLimiter::new();

        let mut drop_store = MockDropStore::new();
        drop_store.expect_store().returning(|_, _| Ok(()));

        let mut inbox_store = MockInboxStore::new();
        inbox_store.expect_add().returning(|_, _, _| Ok(()));

        let mut activity_repo = MockActivityRepo::new();
        activity_repo.expect_log().returning(|_, _, _, _, _| ());

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_drop_store(drop_store)
            .with_inbox_store(inbox_store)
            .with_rate_limiter(rate_limiter)
            .with_workspace_repo(workspace_repo)
            .with_activity_repo(activity_repo)
            .build();

        // Send to internal recipient (same domain)
        let payload = mock_create_drop_payload("recipient@acme.com");
        let result = create_drop(AuthUser { id: sender_id }, State(state), Json(payload))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
