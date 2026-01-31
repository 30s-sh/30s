//! Workspace repository for PostgreSQL.

use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{Workspace, WorkspaceAdmin, WorkspaceDomain, WorkspacePolicy};

/// Repository for workspace operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WorkspaceRepo: Send + Sync {
    /// Find a workspace by ID.
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Workspace>>;

    /// Find a paid workspace by ID (active or past_due subscription).
    async fn find_paid_by_id(&self, id: Uuid) -> Result<Option<Workspace>>;

    /// Find a paid workspace by domain (active or past_due subscription).
    async fn find_paid_by_domain(&self, domain: &str) -> Result<Option<Workspace>>;

    /// Find a workspace by verified domain (any subscription status).
    async fn find_by_verified_domain(&self, domain: &str) -> Result<Option<Workspace>>;

    /// Find a workspace by stripe customer ID.
    #[allow(dead_code)]
    async fn find_by_stripe_customer(&self, customer_id: &str) -> Result<Option<Workspace>>;

    /// Get all verified domains for a workspace.
    async fn get_verified_domains(&self, workspace_id: Uuid) -> Result<Vec<String>>;

    /// Get workspace policy.
    async fn get_policy(&self, workspace_id: Uuid) -> Result<Option<WorkspacePolicy>>;

    /// Find workspace admin by user ID.
    async fn find_admin_by_user(&self, user_id: Uuid) -> Result<Option<WorkspaceAdmin>>;

    /// Update workspace stripe customer ID.
    async fn set_stripe_customer(&self, workspace_id: Uuid, customer_id: &str) -> Result<()>;

    /// Update subscription after checkout.
    async fn set_subscription_active(
        &self,
        workspace_id: Uuid,
        subscription_id: &str,
    ) -> Result<()>;

    /// Update subscription status by customer ID.
    async fn update_subscription_status(
        &self,
        customer_id: &str,
        subscription_id: &str,
        status: &str,
    ) -> Result<bool>;

    /// Clear subscription by customer ID.
    async fn clear_subscription(&self, customer_id: &str) -> Result<bool>;

    /// Create a new workspace and add the user as admin.
    async fn create_with_admin(&self, name: &str, admin_user_id: Uuid) -> Result<Workspace>;

    /// Find a domain by name.
    async fn find_domain(&self, domain: &str) -> Result<Option<WorkspaceDomain>>;

    /// Add a domain for verification.
    async fn add_domain(&self, workspace_id: Uuid, domain: &str, token: &str) -> Result<()>;

    /// Mark a domain as verified.
    async fn verify_domain(&self, domain: &str) -> Result<()>;

    /// List all domains for a workspace.
    async fn list_domains(&self, workspace_id: Uuid) -> Result<Vec<WorkspaceDomain>>;

    /// Upsert workspace policies.
    async fn upsert_policy(&self, workspace_id: Uuid, policy: &WorkspacePolicy) -> Result<()>;
}

/// PostgreSQL implementation of WorkspaceRepo.
#[derive(Clone)]
pub struct PgWorkspaceRepo {
    pool: Pool<Postgres>,
}

impl PgWorkspaceRepo {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepo for PgWorkspaceRepo {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"
            SELECT id, name, created_at, stripe_customer_id, stripe_subscription_id, subscription_status
            FROM workspaces WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(workspace)
    }

    async fn find_paid_by_id(&self, id: Uuid) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"
            SELECT id, name, created_at, stripe_customer_id, stripe_subscription_id, subscription_status
            FROM workspaces
            WHERE id = $1
            AND (subscription_status = 'active' OR subscription_status = 'past_due')
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(workspace)
    }

    async fn find_paid_by_domain(&self, domain: &str) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"
            SELECT w.id, w.name, w.created_at, w.stripe_customer_id, w.stripe_subscription_id, w.subscription_status
            FROM workspaces w
            JOIN workspace_domains wd ON wd.workspace_id = w.id
            WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
            AND (w.subscription_status = 'active' OR w.subscription_status = 'past_due')
            "#,
            domain
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(workspace)
    }

    async fn find_by_stripe_customer(&self, customer_id: &str) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"
            SELECT id, name, created_at, stripe_customer_id, stripe_subscription_id, subscription_status
            FROM workspaces WHERE stripe_customer_id = $1
            "#,
            customer_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(workspace)
    }

    async fn get_verified_domains(&self, workspace_id: Uuid) -> Result<Vec<String>> {
        let domains: Vec<String> = sqlx::query_scalar!(
            r#"
            SELECT domain FROM workspace_domains
            WHERE workspace_id = $1 AND verified_at IS NOT NULL
            "#,
            workspace_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(domains)
    }

    async fn get_policy(&self, workspace_id: Uuid) -> Result<Option<WorkspacePolicy>> {
        let policy = sqlx::query_as!(
            WorkspacePolicy,
            "SELECT * FROM workspace_policies WHERE workspace_id = $1",
            workspace_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(policy)
    }

    async fn find_admin_by_user(&self, user_id: Uuid) -> Result<Option<WorkspaceAdmin>> {
        let admin = sqlx::query_as!(
            WorkspaceAdmin,
            "SELECT * FROM workspace_admins WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(admin)
    }

    async fn set_stripe_customer(&self, workspace_id: Uuid, customer_id: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE workspaces SET stripe_customer_id = $1 WHERE id = $2",
            customer_id,
            workspace_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_subscription_active(
        &self,
        workspace_id: Uuid,
        subscription_id: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE workspaces
            SET stripe_subscription_id = $1, subscription_status = 'active'
            WHERE id = $2
            "#,
            subscription_id,
            workspace_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_subscription_status(
        &self,
        customer_id: &str,
        subscription_id: &str,
        status: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE workspaces
            SET stripe_subscription_id = $1, subscription_status = $2
            WHERE stripe_customer_id = $3
            "#,
        )
        .bind(subscription_id)
        .bind(status)
        .bind(customer_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn clear_subscription(&self, customer_id: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE workspaces
            SET stripe_subscription_id = NULL, subscription_status = 'none'
            WHERE stripe_customer_id = $1
            "#,
        )
        .bind(customer_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn find_by_verified_domain(&self, domain: &str) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            r#"
            SELECT w.id, w.name, w.created_at, w.stripe_customer_id, w.stripe_subscription_id, w.subscription_status
            FROM workspaces w
            JOIN workspace_domains wd ON wd.workspace_id = w.id
            WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
            "#,
            domain
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(workspace)
    }

    async fn create_with_admin(&self, name: &str, admin_user_id: Uuid) -> Result<Workspace> {
        let mut tx = self.pool.begin().await?;

        let workspace = sqlx::query_as!(
            Workspace,
            "INSERT INTO workspaces (name) VALUES ($1) RETURNING *",
            name
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query!(
            "INSERT INTO workspace_admins (workspace_id, user_id) VALUES ($1, $2)",
            workspace.id,
            admin_user_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(workspace)
    }

    async fn find_domain(&self, domain: &str) -> Result<Option<WorkspaceDomain>> {
        let domain = sqlx::query_as!(
            WorkspaceDomain,
            "SELECT * FROM workspace_domains WHERE domain = $1",
            domain
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(domain)
    }

    async fn add_domain(&self, workspace_id: Uuid, domain: &str, token: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO workspace_domains (workspace_id, domain, verification_token)
            VALUES ($1, $2, $3)
            "#,
            workspace_id,
            domain,
            token
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn verify_domain(&self, domain: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE workspace_domains SET verified_at = NOW() WHERE domain = $1",
            domain
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_domains(&self, workspace_id: Uuid) -> Result<Vec<WorkspaceDomain>> {
        let domains = sqlx::query_as!(
            WorkspaceDomain,
            "SELECT * FROM workspace_domains WHERE workspace_id = $1 ORDER BY created_at DESC",
            workspace_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(domains)
    }

    async fn upsert_policy(&self, workspace_id: Uuid, policy: &WorkspacePolicy) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO workspace_policies (
                workspace_id, max_ttl_seconds, min_ttl_seconds, default_ttl_seconds,
                require_once, default_once, allow_external, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (workspace_id) DO UPDATE SET
                max_ttl_seconds = $2,
                min_ttl_seconds = $3,
                default_ttl_seconds = $4,
                require_once = $5,
                default_once = $6,
                allow_external = $7,
                updated_at = NOW()
            "#,
            workspace_id,
            policy.max_ttl_seconds,
            policy.min_ttl_seconds,
            policy.default_ttl_seconds,
            policy.require_once,
            policy.default_once,
            policy.allow_external
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
