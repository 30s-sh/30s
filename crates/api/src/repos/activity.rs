//! Activity log repository for PostgreSQL.
//!
//! Provides fire-and-forget logging of drop events and querying for the activity log endpoint.
//! Errors during logging are recorded but never block drop operations.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{User, WorkspaceActivityLog};

/// Event types for activity logging.
pub mod events {
    pub const DROP_SENT: &str = "drop.sent";
    pub const DROP_OPENED: &str = "drop.opened";
    pub const DROP_DELETED: &str = "drop.deleted";
    pub const DROP_FAILED: &str = "drop.failed";
}

/// Check if a send is internal (all recipients share the sender's workspace domains).
pub fn is_internal_send(recipient_emails: &[String], workspace_domains: &[String]) -> bool {
    recipient_emails.iter().all(|email| {
        email
            .split('@')
            .nth(1)
            .is_some_and(|domain| workspace_domains.iter().any(|d| d == domain))
    })
}

/// Query parameters for activity log filtering.
#[derive(Debug, Default)]
pub struct ActivityQuery {
    pub workspace_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub limit: i64,
}

/// Repository for activity log operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait ActivityRepo: Send + Sync {
    /// Log an activity event (fire-and-forget, errors are logged but not propagated).
    async fn log(
        &self,
        workspace_id: Uuid,
        event_type: &str,
        actor_id: Uuid,
        drop_id: Option<Uuid>,
        metadata: serde_json::Value,
    );

    /// Query activity logs with filters.
    async fn query(&self, params: ActivityQuery) -> Result<Vec<WorkspaceActivityLog>>;

    /// Find users by IDs (bulk lookup for actor emails).
    async fn find_users_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>>;
}

/// PostgreSQL implementation of ActivityRepo.
#[derive(Clone)]
pub struct PgActivityRepo {
    pool: Pool<Postgres>,
}

impl PgActivityRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ActivityRepo for PgActivityRepo {
    async fn log(
        &self,
        workspace_id: Uuid,
        event_type: &str,
        actor_id: Uuid,
        drop_id: Option<Uuid>,
        metadata: serde_json::Value,
    ) {
        let result = sqlx::query!(
            r#"
            INSERT INTO workspace_activity_log (workspace_id, event_type, actor_id, drop_id, metadata)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            workspace_id,
            event_type,
            actor_id,
            drop_id,
            metadata
        )
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            tracing::error!(
                workspace_id = %workspace_id,
                event_type = %event_type,
                actor_id = %actor_id,
                drop_id = ?drop_id,
                error = %e,
                "Failed to log activity event"
            );
        }
    }

    async fn query(&self, params: ActivityQuery) -> Result<Vec<WorkspaceActivityLog>> {
        // Build dynamic WHERE clauses
        let mut conditions = vec!["workspace_id = $1".to_string()];
        let mut param_idx = 2;

        let use_actor = params.actor_id.is_some();
        let use_since = params.since.is_some();
        let use_event_type = params.event_type.is_some();

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

        let mut q = sqlx::query_as::<_, WorkspaceActivityLog>(&query).bind(params.workspace_id);

        if let Some(actor) = params.actor_id {
            q = q.bind(actor);
        }
        if let Some(s) = params.since {
            q = q.bind(s);
        }
        if let Some(et) = params.event_type {
            q = q.bind(et);
        }
        q = q.bind(params.limit);

        Ok(q.fetch_all(&self.pool).await?)
    }

    async fn find_users_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }

        let users = sqlx::query_as!(User, "SELECT * FROM users WHERE id = ANY($1)", ids)
            .fetch_all(&self.pool)
            .await?;
        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_internal_send_tests {
        use super::*;

        #[test]
        fn all_internal_returns_true() {
            let recipients = vec!["alice@acme.com".to_string(), "bob@acme.com".to_string()];
            let domains = vec!["acme.com".to_string()];

            assert!(is_internal_send(&recipients, &domains));
        }

        #[test]
        fn one_external_returns_false() {
            let recipients = vec![
                "alice@acme.com".to_string(),
                "external@gmail.com".to_string(),
            ];
            let domains = vec!["acme.com".to_string()];

            assert!(!is_internal_send(&recipients, &domains));
        }

        #[test]
        fn multiple_workspace_domains() {
            let recipients = vec!["alice@acme.com".to_string(), "bob@acme.io".to_string()];
            let domains = vec!["acme.com".to_string(), "acme.io".to_string()];

            assert!(is_internal_send(&recipients, &domains));
        }

        #[test]
        fn empty_recipients_returns_true() {
            let recipients: Vec<String> = vec![];
            let domains = vec!["acme.com".to_string()];

            assert!(is_internal_send(&recipients, &domains));
        }

        #[test]
        fn invalid_email_returns_false() {
            let recipients = vec!["not-an-email".to_string()];
            let domains = vec!["acme.com".to_string()];

            assert!(!is_internal_send(&recipients, &domains));
        }
    }
}
