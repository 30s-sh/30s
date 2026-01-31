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

#[debug_handler]
async fn get_activity(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<ActivityLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    let membership = state
        .repos
        .membership
        .get_paid_membership(user.id)
        .await?
        .ok_or_else(|| {
            AppError::External(
                StatusCode::NOT_FOUND,
                "No paid workspace found for your account",
            )
        })?;

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
    let actor_filter = if membership.is_admin {
        None
    } else {
        Some(user.id)
    };

    let entries = state
        .repos
        .activity
        .query(ActivityQuery {
            workspace_id: membership.workspace.id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use crate::models::WorkspaceActivityLog;
    use crate::repos::{ActivityQuery, MembershipInfo, MockActivityRepo, MockWorkspaceMembership};
    use crate::test_utils::{mock_user, mock_workspace, TestStateBuilder};

    #[tokio::test]
    async fn get_activity_returns_events_for_admin() {
        // Admin can view all workspace activity
        let admin = mock_user("admin@acme.com");
        let admin_id = admin.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        // Membership service returns admin membership
        let workspace_clone = workspace.clone();
        let mut membership_service = MockWorkspaceMembership::new();
        membership_service
            .expect_get_paid_membership()
            .returning(move |_| {
                Ok(Some(MembershipInfo {
                    workspace: workspace_clone.clone(),
                    is_admin: true,
                }))
            });

        // Mock activity entries
        let entry = WorkspaceActivityLog {
            id: Uuid::new_v4(),
            workspace_id,
            event_type: "drop.sent".to_string(),
            actor_id: admin_id,
            drop_id: Some(Uuid::new_v4()),
            metadata: serde_json::json!({"recipient_count": 1}),
            created_at: chrono::Utc::now(),
        };
        let entry_clone = entry.clone();
        let mut activity_repo = MockActivityRepo::new();
        activity_repo
            .expect_query()
            .withf(move |q: &ActivityQuery| {
                // Admin should see all activity (no actor_id filter)
                q.workspace_id == workspace_id && q.actor_id.is_none()
            })
            .returning(move |_| Ok(vec![entry_clone.clone()]));
        activity_repo
            .expect_find_users_by_ids()
            .returning(move |_| Ok(vec![mock_user("admin@acme.com")]));

        let state = TestStateBuilder::new()
            .with_membership_service(membership_service)
            .with_activity_repo(activity_repo)
            .build();

        let query = ActivityLogQuery {
            since: None,
            event_type: None,
            limit: Some(50),
        };

        let result = get_activity(AuthUser { id: admin_id }, State(state), Query(query))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_activity_returns_own_events_for_domain_member() {
        // Non-admin can only view their own activity
        let member = mock_user("member@acme.com");
        let member_id = member.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        // Membership service returns domain membership (not admin)
        let workspace_clone = workspace.clone();
        let mut membership_service = MockWorkspaceMembership::new();
        membership_service
            .expect_get_paid_membership()
            .returning(move |_| {
                Ok(Some(MembershipInfo {
                    workspace: workspace_clone.clone(),
                    is_admin: false,
                }))
            });

        // Mock activity entries
        let entry = WorkspaceActivityLog {
            id: Uuid::new_v4(),
            workspace_id,
            event_type: "drop.sent".to_string(),
            actor_id: member_id,
            drop_id: Some(Uuid::new_v4()),
            metadata: serde_json::json!({"recipient_count": 1}),
            created_at: chrono::Utc::now(),
        };
        let entry_clone = entry.clone();
        let mut activity_repo = MockActivityRepo::new();
        activity_repo
            .expect_query()
            .withf(move |q: &ActivityQuery| {
                // Non-admin should only see their own activity
                q.workspace_id == workspace_id && q.actor_id == Some(member_id)
            })
            .returning(move |_| Ok(vec![entry_clone.clone()]));
        activity_repo
            .expect_find_users_by_ids()
            .returning(move |_| Ok(vec![mock_user("member@acme.com")]));

        let state = TestStateBuilder::new()
            .with_membership_service(membership_service)
            .with_activity_repo(activity_repo)
            .build();

        let query = ActivityLogQuery {
            since: None,
            event_type: None,
            limit: Some(50),
        };

        let result = get_activity(AuthUser { id: member_id }, State(state), Query(query))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_activity_returns_not_found_for_non_member() {
        // User not in any workspace should get 404
        let user = mock_user("outsider@gmail.com");
        let user_id = user.id;

        // Membership service returns None (no workspace)
        let mut membership_service = MockWorkspaceMembership::new();
        membership_service
            .expect_get_paid_membership()
            .returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_membership_service(membership_service)
            .build();

        let query = ActivityLogQuery {
            since: None,
            event_type: None,
            limit: Some(50),
        };

        let result = get_activity(AuthUser { id: user_id }, State(state), Query(query)).await;

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

    #[tokio::test]
    async fn get_activity_works_for_admin_without_verified_domain() {
        // Admin whose domain is NOT verified should still access activity
        let admin = mock_user("admin@unverified.com");
        let admin_id = admin.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        // Membership service returns admin membership (even without verified domain)
        let workspace_clone = workspace.clone();
        let mut membership_service = MockWorkspaceMembership::new();
        membership_service
            .expect_get_paid_membership()
            .returning(move |_| {
                Ok(Some(MembershipInfo {
                    workspace: workspace_clone.clone(),
                    is_admin: true,
                }))
            });

        let mut activity_repo = MockActivityRepo::new();
        activity_repo
            .expect_query()
            .withf(move |q: &ActivityQuery| {
                q.workspace_id == workspace_id && q.actor_id.is_none()
            })
            .returning(|_| Ok(vec![]));
        activity_repo
            .expect_find_users_by_ids()
            .returning(|_| Ok(vec![]));

        let state = TestStateBuilder::new()
            .with_membership_service(membership_service)
            .with_activity_repo(activity_repo)
            .build();

        let query = ActivityLogQuery {
            since: None,
            event_type: None,
            limit: Some(50),
        };

        let result = get_activity(AuthUser { id: admin_id }, State(state), Query(query))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
