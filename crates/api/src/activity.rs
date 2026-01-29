//! Workspace activity logging for audit purposes.
//!
//! Provides fire-and-forget logging of drop events to PostgreSQL.
//! Errors are logged but never block drop operations.

use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Event types for activity logging.
pub mod events {
    pub const DROP_SENT: &str = "drop.sent";
    pub const DROP_OPENED: &str = "drop.opened";
    pub const DROP_DELETED: &str = "drop.deleted";
    pub const DROP_FAILED: &str = "drop.failed";
}

/// Log an activity event to the workspace activity log.
///
/// This is fire-and-forget: errors are logged but never returned.
/// Drop operations should never fail due to activity logging failures.
pub async fn log_activity(
    db: &Pool<Postgres>,
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
    .execute(db)
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

/// Check if a send is internal (all recipients share the sender's workspace domains).
pub fn is_internal_send(recipient_emails: &[String], workspace_domains: &[String]) -> bool {
    recipient_emails.iter().all(|email| {
        email
            .split('@')
            .nth(1)
            .is_some_and(|domain| workspace_domains.iter().any(|d| d == domain))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_internal_send {
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
