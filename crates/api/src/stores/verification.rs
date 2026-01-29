//! Verification code storage for Redis.

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

/// State stored for verification codes.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyState {
    pub email: String,
    pub code: String,
    pub created_at: i64,
}

/// Store for verification code operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait VerificationStore: Send + Sync {
    /// Store a verification code (hashed) with TTL.
    async fn store_verify_code(&self, hashed_code: &str, email: &str, ttl_secs: u64) -> Result<()>;

    /// Get verification state by hashed code.
    async fn get_verify_code(&self, hashed_code: &str) -> Result<Option<VerifyState>>;

    /// Delete a verification code.
    async fn delete_verify_code(&self, hashed_code: &str) -> Result<()>;

    /// Store a rotation code (hashed) with TTL.
    async fn store_rotate_code(&self, hashed_code: &str, email: &str, ttl_secs: u64) -> Result<()>;

    /// Get rotation state by hashed code.
    async fn get_rotate_code(&self, hashed_code: &str) -> Result<Option<VerifyState>>;

    /// Delete a rotation code.
    async fn delete_rotate_code(&self, hashed_code: &str) -> Result<()>;
}

/// Redis implementation of VerificationStore.
#[derive(Clone)]
pub struct RedisVerificationStore {
    client: redis::Client,
}

impl RedisVerificationStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    fn verify_key(hashed_code: &str) -> String {
        format!("verify-{}", hashed_code)
    }

    fn rotate_key(hashed_code: &str) -> String {
        format!("rotate-{}", hashed_code)
    }
}

#[async_trait]
impl VerificationStore for RedisVerificationStore {
    async fn store_verify_code(&self, hashed_code: &str, email: &str, ttl_secs: u64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::verify_key(hashed_code);

        let state = VerifyState {
            email: email.to_string(),
            code: hashed_code.to_string(),
            created_at: Utc::now().timestamp(),
        };

        let _: () = conn.set_ex(&key, serde_json::to_string(&state)?, ttl_secs).await?;
        Ok(())
    }

    async fn get_verify_code(&self, hashed_code: &str) -> Result<Option<VerifyState>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::verify_key(hashed_code);

        let json: Option<String> = conn.get(&key).await?;

        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    async fn delete_verify_code(&self, hashed_code: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::verify_key(hashed_code);

        let _: () = conn.del(&key).await?;
        Ok(())
    }

    async fn store_rotate_code(&self, hashed_code: &str, email: &str, ttl_secs: u64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::rotate_key(hashed_code);

        let state = VerifyState {
            email: email.to_string(),
            code: hashed_code.to_string(),
            created_at: Utc::now().timestamp(),
        };

        let _: () = conn.set_ex(&key, serde_json::to_string(&state)?, ttl_secs).await?;
        Ok(())
    }

    async fn get_rotate_code(&self, hashed_code: &str) -> Result<Option<VerifyState>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::rotate_key(hashed_code);

        let json: Option<String> = conn.get(&key).await?;

        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    async fn delete_rotate_code(&self, hashed_code: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::rotate_key(hashed_code);

        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
