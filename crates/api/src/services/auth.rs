//! Authentication service abstraction wrapping Unkey.

use anyhow::Result;
use async_trait::async_trait;

use super::unkey;

/// Response from key verification.
#[derive(Debug, Clone)]
pub struct VerifyKeyResult {
    pub valid: bool,
    pub user_id: Option<String>,
}

/// Response from key creation.
#[derive(Debug, Clone)]
pub struct CreateKeyResult {
    pub key: String,
    pub key_id: String,
}

/// Authentication service trait for API key operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AuthService: Send + Sync {
    /// Verify an API key.
    async fn verify_key(&self, key: &str) -> Result<VerifyKeyResult>;

    /// Create a new API key for a user.
    async fn create_key(&self, user_id: &str, name: &str) -> Result<CreateKeyResult>;

    /// Delete/revoke an API key.
    async fn delete_key(&self, key_id: &str) -> Result<()>;
}

/// Unkey implementation of AuthService.
pub struct UnkeyAuthService {
    client: unkey::Client,
}

impl UnkeyAuthService {
    pub fn new(client: unkey::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AuthService for UnkeyAuthService {
    async fn verify_key(&self, key: &str) -> Result<VerifyKeyResult> {
        let response = self
            .client
            .verify_key(key)
            .await
            .map_err(|e| anyhow::anyhow!("Unkey verification failed: {}", e))?;

        Ok(VerifyKeyResult {
            valid: response.valid,
            user_id: response.identity.map(|i| i.external_id),
        })
    }

    async fn create_key(&self, user_id: &str, name: &str) -> Result<CreateKeyResult> {
        let response = self
            .client
            .create_key(user_id, name)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create API key: {}", e))?;

        Ok(CreateKeyResult {
            key: response.key,
            key_id: response.key_id,
        })
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.client
            .delete_key(key_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to delete API key: {}", e))?;

        Ok(())
    }
}
