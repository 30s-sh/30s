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
use chrono::{DateTime, Utc};
use shared::api::{ActivityLogEntry, ActivityLogQuery, ActivityLogResponse};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{User, Workspace, WorkspaceActivityLog, WorkspaceAdmin},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/activity", get(get_activity))
}

/// Get the user's workspace ID via admin membership or domain.
/// Returns (workspace_id, is_admin).
async fn get_user_workspace(state: &AppState, user_id: Uuid) -> Result<(Uuid, bool), AppError> {
    // Check if user is an admin
    let admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.database)
    .await?;

    if let Some(a) = admin {
        return Ok((a.workspace_id, true));
    }

    // Find workspace via email domain
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(&state.database)
        .await?;

    let email_domain = user
        .email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid email format")))?;

    let workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT w.*
        FROM workspaces w
        JOIN workspace_domains wd ON wd.workspace_id = w.id
        WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
        "#,
        email_domain
    )
    .fetch_optional(&state.database)
    .await?;

    match workspace {
        Some(w) => Ok((w.id, false)),
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "No workspace found for your email domain",
        )),
    }
}

/// Query activity logs with optional filters.
async fn query_activity_logs(
    state: &AppState,
    workspace_id: Uuid,
    actor_id: Option<Uuid>,
    since: Option<DateTime<Utc>>,
    event_type: Option<&str>,
    limit: i64,
) -> Result<Vec<WorkspaceActivityLog>, AppError> {
    // Build dynamic WHERE clauses
    let mut conditions = vec!["workspace_id = $1".to_string()];
    let mut param_idx = 2;

    let use_actor = actor_id.is_some();
    let use_since = since.is_some();
    let use_event_type = event_type.is_some();

    if use_actor {
        conditions.push(format!("actor_id = ${}", param_idx));
        param_idx += 1;
    }

    if use_since {
        conditions.push(format!("created_at >= ${}", param_idx));
        param_idx += 1;
    }

    if use_event_type {
        conditions.push(format!("event_type = ${}", param_idx));
        param_idx += 1;
    }

    let where_clause = conditions.join(" AND ");
    let query = format!(
        r#"
        SELECT id, workspace_id, event_type, actor_id, drop_id, metadata, created_at
        FROM workspace_activity_log
        WHERE {}
        ORDER BY created_at DESC, id DESC
        LIMIT ${}
        "#,
        where_clause, param_idx
    );

    let mut q = sqlx::query_as::<_, WorkspaceActivityLog>(&query).bind(workspace_id);

    if let Some(actor) = actor_id {
        q = q.bind(actor);
    }
    if let Some(s) = since {
        q = q.bind(s);
    }
    if let Some(et) = event_type {
        q = q.bind(et);
    }
    q = q.bind(limit);

    Ok(q.fetch_all(&state.database).await?)
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

    let entries = query_activity_logs(
        &state,
        workspace_id,
        actor_filter,
        since,
        query.event_type.as_deref(),
        limit,
    )
    .await?;

    // Look up actor emails in bulk
    let actor_ids: Vec<Uuid> = entries.iter().map(|e| e.actor_id).collect();
    let actors: Vec<User> = if actor_ids.is_empty() {
        vec![]
    } else {
        sqlx::query_as!(User, "SELECT * FROM users WHERE id = ANY($1)", &actor_ids)
            .fetch_all(&state.database)
            .await?
    };

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
