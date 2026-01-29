//! Inbox storage for Redis (sorted sets).

use anyhow::Result;
use async_trait::async_trait;
use redis::AsyncCommands;
use uuid::Uuid;

/// Store for inbox operations (sorted sets of drop IDs per user).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait InboxStore: Send + Sync {
    /// Add a drop ID to a user's inbox with expiration score.
    async fn add(&self, user_id: Uuid, drop_id: &str, expiration_timestamp: f64) -> Result<()>;

    /// Remove a drop ID from a user's inbox.
    async fn remove(&self, user_id: Uuid, drop_id: &str) -> Result<()>;

    /// Get all non-expired drop IDs for a user (score >= now).
    async fn get_active(&self, user_id: Uuid, now_timestamp: f64) -> Result<Vec<String>>;

    /// Remove expired entries from a user's inbox (score < now).
    async fn cleanup_expired(&self, user_id: Uuid, now_timestamp: f64) -> Result<()>;

    /// Delete entire inbox for a user.
    async fn delete_all(&self, user_id: Uuid) -> Result<()>;
}

/// Redis implementation of InboxStore.
#[derive(Clone)]
pub struct RedisInboxStore {
    client: redis::Client,
}

impl RedisInboxStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    fn inbox_key(user_id: Uuid) -> String {
        format!("inbox:{}", user_id)
    }
}

#[async_trait]
impl InboxStore for RedisInboxStore {
    async fn add(&self, user_id: Uuid, drop_id: &str, expiration_timestamp: f64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::inbox_key(user_id);

        let _: () = conn.zadd(&key, drop_id, expiration_timestamp).await?;
        Ok(())
    }

    async fn remove(&self, user_id: Uuid, drop_id: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::inbox_key(user_id);

        let _: () = conn.zrem(&key, drop_id).await?;
        Ok(())
    }

    async fn get_active(&self, user_id: Uuid, now_timestamp: f64) -> Result<Vec<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::inbox_key(user_id);

        let drop_ids: Vec<String> = conn.zrangebyscore(&key, now_timestamp, f64::MAX).await?;
        Ok(drop_ids)
    }

    async fn cleanup_expired(&self, user_id: Uuid, now_timestamp: f64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::inbox_key(user_id);

        let _: () = conn
            .zrembyscore(&key, f64::NEG_INFINITY, now_timestamp)
            .await?;
        Ok(())
    }

    async fn delete_all(&self, user_id: Uuid) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::inbox_key(user_id);

        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
