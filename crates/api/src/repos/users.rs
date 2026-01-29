//! User repository for PostgreSQL.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::User;

/// Repository for user operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UserRepo: Send + Sync {
    /// Find a user by ID.
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;

    /// Find a user by email.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;

    /// Find a verified user by email.
    async fn find_verified_by_email(&self, email: &str) -> Result<Option<User>>;

    /// Create a new user with the given email.
    async fn create(&self, email: &str) -> Result<User>;

    /// Update a user's verified_at and unkey_key_id after verification.
    async fn set_verified(&self, email: &str, unkey_key_id: &str) -> Result<User>;

    /// Update a user's unkey_key_id.
    async fn update_key_id(&self, id: Uuid, unkey_key_id: &str) -> Result<()>;

    /// Delete a user by ID.
    async fn delete(&self, id: Uuid) -> Result<()>;
}

/// PostgreSQL implementation of UserRepo.
#[derive(Clone)]
pub struct PgUserRepo {
    pool: Pool<Postgres>,
}

impl PgUserRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepo for PgUserRepo {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_verified_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1 AND verified_at IS NOT NULL",
            email
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    async fn create(&self, email: &str) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (email) VALUES ($1) RETURNING *",
            email
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn set_verified(&self, email: &str, unkey_key_id: &str) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users SET verified_at = now(), unkey_key_id = $2 WHERE email = $1 RETURNING *",
            email,
            unkey_key_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn update_key_id(&self, id: Uuid, unkey_key_id: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET unkey_key_id = $2 WHERE id = $1",
            id,
            unkey_key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
