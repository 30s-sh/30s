//! Workspace membership service.
//!
//! Centralizes logic for determining workspace membership and permissions.
//! A user belongs to a workspace if they are:
//! - An admin (explicit, in workspace_admins table)
//! - A domain member (automatic, email domain matches verified workspace domain)

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use super::{UserRepo, WorkspaceRepo};
use crate::models::Workspace;

/// Result of a membership lookup.
#[derive(Debug, Clone)]
pub struct MembershipInfo {
    pub workspace: Workspace,
    pub is_admin: bool,
}

/// Service for determining workspace membership.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WorkspaceMembership: Send + Sync {
    /// Get user's paid workspace membership (for features requiring subscription).
    /// Returns None if user is not a member of any paid workspace.
    async fn get_paid_membership(&self, user_id: Uuid) -> Result<Option<MembershipInfo>>;

    /// Get user's workspace membership (any subscription status).
    /// Returns None if user is not a member of any workspace.
    async fn get_membership(&self, user_id: Uuid) -> Result<Option<MembershipInfo>>;

    /// Get paid workspace by email address (for sender lookups).
    /// Returns None if email owner is not a member of any paid workspace.
    async fn get_paid_membership_by_email(&self, email: &str) -> Result<Option<MembershipInfo>>;

    /// Check if user is admin of any workspace.
    /// Returns None if user is not admin of any workspace.
    async fn get_admin_workspace(&self, user_id: Uuid) -> Result<Option<Workspace>>;
}

/// PostgreSQL implementation of WorkspaceMembership.
pub struct PgWorkspaceMembership {
    users: Arc<dyn UserRepo>,
    workspaces: Arc<dyn WorkspaceRepo>,
}

impl PgWorkspaceMembership {
    pub fn new(users: Arc<dyn UserRepo>, workspaces: Arc<dyn WorkspaceRepo>) -> Self {
        Self { users, workspaces }
    }

    /// Core logic: check admin first, then domain fallback.
    async fn resolve_membership(
        &self,
        user_id: Uuid,
        require_paid: bool,
    ) -> Result<Option<MembershipInfo>> {
        // 1. Check admin path
        if let Some(admin) = self.workspaces.find_admin_by_user(user_id).await? {
            let workspace = if require_paid {
                self.workspaces.find_paid_by_id(admin.workspace_id).await?
            } else {
                self.workspaces.find_by_id(admin.workspace_id).await?
            };
            if let Some(ws) = workspace {
                return Ok(Some(MembershipInfo {
                    workspace: ws,
                    is_admin: true,
                }));
            }
        }

        // 2. Domain fallback
        let user = self.users.find_by_id(user_id).await?;
        if let Some(user) = user
            && let Some(domain) = user.email.split('@').nth(1)
        {
            let workspace = if require_paid {
                self.workspaces.find_paid_by_domain(domain).await?
            } else {
                self.workspaces.find_by_verified_domain(domain).await?
            };
            if let Some(ws) = workspace {
                return Ok(Some(MembershipInfo {
                    workspace: ws,
                    is_admin: false,
                }));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl WorkspaceMembership for PgWorkspaceMembership {
    async fn get_paid_membership(&self, user_id: Uuid) -> Result<Option<MembershipInfo>> {
        self.resolve_membership(user_id, true).await
    }

    async fn get_membership(&self, user_id: Uuid) -> Result<Option<MembershipInfo>> {
        self.resolve_membership(user_id, false).await
    }

    async fn get_paid_membership_by_email(&self, email: &str) -> Result<Option<MembershipInfo>> {
        // Look up user by email to check admin status
        if let Some(user) = self.users.find_by_email(email).await? {
            return self.resolve_membership(user.id, true).await;
        }

        // User not found, fall back to domain lookup only
        if let Some(domain) = email.split('@').nth(1)
            && let Some(workspace) = self.workspaces.find_paid_by_domain(domain).await?
        {
            return Ok(Some(MembershipInfo {
                workspace,
                is_admin: false,
            }));
        }
        Ok(None)
    }

    async fn get_admin_workspace(&self, user_id: Uuid) -> Result<Option<Workspace>> {
        let admin = self.workspaces.find_admin_by_user(user_id).await?;
        match admin {
            Some(a) => self.workspaces.find_by_id(a.workspace_id).await,
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::WorkspaceAdmin;
    use crate::repos::{MockUserRepo, MockWorkspaceRepo};
    use chrono::Utc;

    fn mock_user(email: &str) -> crate::models::User {
        crate::models::User {
            id: Uuid::new_v4(),
            email: email.to_string(),
            unkey_key_id: Some("key_123".to_string()),
            created_at: Utc::now(),
            verified_at: Some(Utc::now()),
        }
    }

    fn mock_workspace() -> Workspace {
        Workspace {
            id: Uuid::new_v4(),
            name: "Test Workspace".to_string(),
            created_at: Utc::now(),
            stripe_customer_id: Some("cus_test".to_string()),
            stripe_subscription_id: Some("sub_test".to_string()),
            subscription_status: "active".to_string(),
        }
    }

    fn mock_workspace_admin(workspace_id: Uuid, user_id: Uuid) -> WorkspaceAdmin {
        WorkspaceAdmin {
            workspace_id,
            user_id,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn get_paid_membership_returns_admin_workspace() {
        let user = mock_user("admin@acme.com");
        let user_id = user.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;
        let admin = mock_workspace_admin(workspace_id, user_id);

        let mut workspace_repo = MockWorkspaceRepo::new();
        let admin_clone = admin.clone();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(move |_| Ok(Some(admin_clone.clone())));
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_paid_by_id()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let user_repo = MockUserRepo::new();

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_paid_membership(user_id).await.unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.is_admin);
        assert_eq!(info.workspace.id, workspace_id);
    }

    #[tokio::test]
    async fn get_paid_membership_returns_domain_workspace_for_non_admin() {
        let user = mock_user("member@acme.com");
        let user_id = user.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(|_| Ok(None));
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_paid_membership(user_id).await.unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(!info.is_admin);
        assert_eq!(info.workspace.id, workspace_id);
    }

    #[tokio::test]
    async fn get_paid_membership_returns_none_for_non_member() {
        let user = mock_user("outsider@gmail.com");
        let user_id = user.id;

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(|_| Ok(None));
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(|_| Ok(None));

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_paid_membership(user_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_membership_returns_unpaid_workspace() {
        let user = mock_user("member@acme.com");
        let user_id = user.id;
        let mut workspace = mock_workspace();
        workspace.subscription_status = "none".to_string();
        let workspace_id = workspace.id;

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(|_| Ok(None));
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_by_verified_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_membership(user_id).await.unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.workspace.id, workspace_id);
    }

    #[tokio::test]
    async fn get_paid_membership_by_email_finds_admin() {
        let user = mock_user("admin@acme.com");
        let user_id = user.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;
        let admin = mock_workspace_admin(workspace_id, user_id);

        let mut workspace_repo = MockWorkspaceRepo::new();
        let admin_clone = admin.clone();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(move |_| Ok(Some(admin_clone.clone())));
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_paid_by_id()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_email()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service
            .get_paid_membership_by_email("admin@acme.com")
            .await
            .unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.is_admin);
        assert_eq!(info.workspace.id, workspace_id);
    }

    #[tokio::test]
    async fn get_paid_membership_by_email_falls_back_to_domain() {
        let workspace = mock_workspace();
        let workspace_id = workspace.id;

        let mut workspace_repo = MockWorkspaceRepo::new();
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_paid_by_domain()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let mut user_repo = MockUserRepo::new();
        user_repo
            .expect_find_by_email()
            .returning(|_| Ok(None)); // User not found

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service
            .get_paid_membership_by_email("unknown@acme.com")
            .await
            .unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(!info.is_admin);
        assert_eq!(info.workspace.id, workspace_id);
    }

    #[tokio::test]
    async fn get_admin_workspace_returns_workspace_for_admin() {
        let user = mock_user("admin@acme.com");
        let user_id = user.id;
        let workspace = mock_workspace();
        let workspace_id = workspace.id;
        let admin = mock_workspace_admin(workspace_id, user_id);

        let mut workspace_repo = MockWorkspaceRepo::new();
        let admin_clone = admin.clone();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(move |_| Ok(Some(admin_clone.clone())));
        let workspace_clone = workspace.clone();
        workspace_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(workspace_clone.clone())));

        let user_repo = MockUserRepo::new();

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_admin_workspace(user_id).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, workspace_id);
    }

    #[tokio::test]
    async fn get_admin_workspace_returns_none_for_non_admin() {
        let user_id = Uuid::new_v4();

        let mut workspace_repo = MockWorkspaceRepo::new();
        workspace_repo
            .expect_find_admin_by_user()
            .returning(|_| Ok(None));

        let user_repo = MockUserRepo::new();

        let service =
            PgWorkspaceMembership::new(Arc::new(user_repo), Arc::new(workspace_repo));

        let result = service.get_admin_workspace(user_id).await.unwrap();
        assert!(result.is_none());
    }
}
