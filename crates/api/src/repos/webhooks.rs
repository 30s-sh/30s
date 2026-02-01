//! Webhook repository for PostgreSQL.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::Webhook;

/// Repository for webhook operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WebhookRepo: Send + Sync {
    /// Get webhook for a user (returns None if not configured).
    async fn get_by_user(&self, user_id: Uuid) -> Result<Option<Webhook>>;

    /// Set/replace webhook for a user.
    async fn upsert_for_user(&self, user_id: Uuid, url: &str, secret: &str) -> Result<Webhook>;

    /// Delete webhook for a user (returns true if a webhook was deleted).
    async fn delete_for_user(&self, user_id: Uuid) -> Result<bool>;
}

/// PostgreSQL implementation of WebhookRepo.
#[derive(Clone)]
pub struct PgWebhookRepo {
    pool: Pool<Postgres>,
}

impl PgWebhookRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WebhookRepo for PgWebhookRepo {
    async fn get_by_user(&self, user_id: Uuid) -> Result<Option<Webhook>> {
        let webhook = sqlx::query_as::<_, Webhook>(
            "SELECT id, user_id, url, secret, created_at FROM webhooks WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(webhook)
    }

    async fn upsert_for_user(&self, user_id: Uuid, url: &str, secret: &str) -> Result<Webhook> {
        let webhook = sqlx::query_as::<_, Webhook>(
            r#"
            INSERT INTO webhooks (user_id, url, secret)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id)
            DO UPDATE SET url = EXCLUDED.url, secret = EXCLUDED.secret, created_at = now()
            RETURNING id, user_id, url, secret, created_at
            "#,
        )
        .bind(user_id)
        .bind(url)
        .bind(secret)
        .fetch_one(&self.pool)
        .await?;
        Ok(webhook)
    }

    async fn delete_for_user(&self, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM webhooks WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
