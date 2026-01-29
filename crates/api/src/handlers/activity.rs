//! Workspace activity log endpoint.
//!
//! Provides access to workspace activity events.
//! - Admins can see all workspace activity
//! - Members can only see their own activity

use axum::{
    Json, Router, debug_handler,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use shared::api::{ActivityLogEntry, ActivityLogQuery, ActivityLogResponse};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    repos::ActivityQuery,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/activity", get(get_activity))
}

/// Get the user's workspace ID via admin membership or domain.
/// Returns (workspace_id, is_admin).
async fn get_user_workspace(state: &AppState, user_id: Uuid) -> Result<(Uuid, bool), AppError> {
    // Check if user is an admin
    let admin = state.repos.workspaces.find_admin_by_user(user_id).await?;

    if let Some(a) = admin {
        return Ok((a.workspace_id, true));
    }

    // Find workspace via email domain
    let user = state
        .repos
        .users
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let email_domain = user
        .email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid email format")))?;

    // Use find_paid_by_domain since activity log is only for paid workspaces
    let workspace = state.repos.workspaces.find_paid_by_domain(email_domain).await?;

    match workspace {
        Some(w) => Ok((w.id, false)),
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "No workspace found for your email domain",
        )),
    }
}

#[debug_handler]
async fn get_activity(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<ActivityLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    let (workspace_id, is_admin) = get_user_workspace(&state, user.id).await?;

    // Limit: None = unlimited, Some(n) = n entries (max 10000)
    let limit = match query.limit {
        None => i64::MAX,
        Some(n) => (n as i64).clamp(0, 10000),
    };

    // Convert Unix timestamp to DateTime
    let since = query
        .since
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    // Non-admins can only see their own activity
    let actor_filter = if is_admin { None } else { Some(user.id) };

    let entries = state
        .repos
        .activity
        .query(ActivityQuery {
            workspace_id,
            actor_id: actor_filter,
            since,
            event_type: query.event_type.clone(),
            limit,
        })
        .await?;

    // Look up actor emails in bulk
    let actor_ids: Vec<Uuid> = entries.iter().map(|e| e.actor_id).collect();
    let actors = state.repos.activity.find_users_by_ids(&actor_ids).await?;

    let actor_map: std::collections::HashMap<Uuid, String> =
        actors.into_iter().map(|u| (u.id, u.email)).collect();

    let response_entries: Vec<ActivityLogEntry> = entries
        .into_iter()
        .map(|e| ActivityLogEntry {
            id: e.id,
            event_type: e.event_type,
            actor_email: actor_map
                .get(&e.actor_id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            drop_id: e.drop_id,
            metadata: e.metadata,
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(ActivityLogResponse {
        entries: response_entries,
    }))
}
