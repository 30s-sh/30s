//! Drop storage for Redis.

use anyhow::Result;
use async_trait::async_trait;
use redis::AsyncCommands;

use crate::models::StoredDrop;

/// Store for drop operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DropStore: Send + Sync {
    /// Health check - verify Redis connectivity.
    async fn health_check(&self) -> Result<bool>;

    /// Store a drop with TTL.
    async fn store(&self, drop: &StoredDrop, ttl_secs: u64) -> Result<()>;

    /// Get a drop by ID.
    async fn get(&self, id: &str) -> Result<Option<StoredDrop>>;

    /// Delete a drop by ID (returns true if it existed).
    async fn delete(&self, id: &str) -> Result<bool>;
}

/// Redis implementation of DropStore.
#[derive(Clone)]
pub struct RedisDropStore {
    client: redis::Client,
}

impl RedisDropStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    fn drop_key(id: &str) -> String {
        format!("drop:{}", id)
    }
}

#[async_trait]
impl DropStore for RedisDropStore {
    async fn health_check(&self) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let result: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(result == "PONG")
    }

    async fn store(&self, drop: &StoredDrop, ttl_secs: u64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::drop_key(&drop.id);
        let json = serde_json::to_string(drop)?;

        let _: () = conn.set(&key, &json).await?;
        let _: () = conn.expire(&key, ttl_secs as i64).await?;

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<StoredDrop>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::drop_key(id);

        let json: Option<String> = conn.get(&key).await?;

        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::drop_key(id);

        let deleted: i64 = conn.del(&key).await?;
        Ok(deleted > 0)
    }
}
