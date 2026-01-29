//! Device repository for PostgreSQL.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::Device;

/// Repository for device operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DeviceRepo: Send + Sync {
    /// Find a device by ID.
    #[allow(dead_code)]
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Device>>;

    /// Find a device by ID that belongs to a specific user.
    async fn find_by_id_and_user(&self, id: Uuid, user_id: Uuid) -> Result<Option<Device>>;

    /// List all devices for a user.
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Device>>;

    /// Create a new device.
    async fn create(&self, user_id: Uuid, public_key: &str) -> Result<Device>;

    /// Update a device's public key.
    async fn update_public_key(&self, id: Uuid, user_id: Uuid, public_key: &str) -> Result<bool>;

    /// Delete a device (returns true if a device was deleted).
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool>;

    /// Delete all devices for a user.
    async fn delete_all_by_user(&self, user_id: Uuid) -> Result<()>;
}

/// PostgreSQL implementation of DeviceRepo.
#[derive(Clone)]
pub struct PgDeviceRepo {
    pool: Pool<Postgres>,
}

impl PgDeviceRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceRepo for PgDeviceRepo {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Device>> {
        let device = sqlx::query_as!(Device, "SELECT * FROM devices WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(device)
    }

    async fn find_by_id_and_user(&self, id: Uuid, user_id: Uuid) -> Result<Option<Device>> {
        let device = sqlx::query_as!(
            Device,
            "SELECT * FROM devices WHERE id = $1 AND user_id = $2",
            id,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(device)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Device>> {
        let devices = sqlx::query_as!(
            Device,
            "SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC",
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(devices)
    }

    async fn create(&self, user_id: Uuid, public_key: &str) -> Result<Device> {
        let device = sqlx::query_as!(
            Device,
            "INSERT INTO devices (user_id, public_key) VALUES ($1, $2) RETURNING *",
            user_id,
            public_key,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(device)
    }

    async fn update_public_key(&self, id: Uuid, user_id: Uuid, public_key: &str) -> Result<bool> {
        let result = sqlx::query!(
            "UPDATE devices SET public_key = $1 WHERE id = $2 AND user_id = $3",
            public_key,
            id,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            "DELETE FROM devices WHERE id = $1 AND user_id = $2",
            id,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_all_by_user(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!("DELETE FROM devices WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
