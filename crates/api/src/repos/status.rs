//! Status repository for health checks.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

/// Repository for database health checks.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait StatusRepo: Send + Sync {
    /// Health check - verify database connectivity.
    async fn health_check(&self) -> Result<bool>;
}

/// PostgreSQL implementation of StatusRepo.
#[derive(Clone)]
pub struct PgStatusRepo {
    pool: Pool<Postgres>,
}

impl PgStatusRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl StatusRepo for PgStatusRepo {
    async fn health_check(&self) -> Result<bool> {
        let result: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&self.pool).await?;
        Ok(result == 1)
    }
}
