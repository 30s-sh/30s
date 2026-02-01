//! Shared test utilities for API handler tests.
//!
//! Provides common mock factories and a flexible `TestStateBuilder` for constructing
//! `AppState` instances with only the mocks needed for each test.
//!
//! ## Usage
//!
//! ```ignore
//! use crate::test_utils::{TestStateBuilder, mock_user, mock_device};
//!
//! let mut user_repo = MockUserRepo::new();
//! user_repo.expect_find_by_id().returning(|_| Ok(Some(mock_user("alice@example.com"))));
//!
//! let state = TestStateBuilder::new()
//!     .with_user_repo(user_repo)
//!     .build();
//! ```

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::config::Config;
use crate::models::{Device, StoredDrop, User, Workspace, WorkspacePolicy};
use crate::repos::{
    MockActivityRepo, MockDeviceRepo, MockStatusRepo, MockUserRepo, MockWebhookRepo,
    MockWorkspaceMembership, MockWorkspaceRepo, Repos,
};
use crate::services::{MockAuthService, MockDnsResolver, MockEmailSender, MockWebhookSender};
use crate::state::AppState;
use crate::stores::{
    MockDropStore, MockInboxStore, MockRateLimiter, MockVerificationStore, Stores,
};
use shared::api::WrappedKeyPayload;

/// Creates a test configuration with dummy values.
pub fn test_config() -> Config {
    Config {
        host: "127.0.0.1".to_string(),
        port: 3000,
        database_url: "postgres://test".to_string(),
        redis_url: "redis://test".to_string(),
        smtp_url: None,
        resend_api_key: None,
        unkey_root_key: "test".to_string(),
        unkey_api_id: "test".to_string(),
        env: "test".to_string(),
        sentry_dsn: None,
        stripe_secret_key: "sk_test_xxx".to_string(),
        stripe_webhook_secret: "whsec_xxx".to_string(),
        stripe_price_id: "price_xxx".to_string(),
    }
}

/// Creates a mock user with the given email.
pub fn mock_user(email: &str) -> User {
    User {
        id: Uuid::new_v4(),
        email: email.to_string(),
        unkey_key_id: Some("key_123".to_string()),
        created_at: Utc::now(),
        verified_at: Some(Utc::now()),
    }
}

/// Creates a mock device for the given user.
pub fn mock_device(user_id: Uuid) -> Device {
    Device {
        id: Uuid::new_v4(),
        user_id,
        public_key: "test-public-key".to_string(),
        created_at: Utc::now(),
    }
}

/// Creates a mock stored drop.
pub fn mock_stored_drop(sender_email: &str, recipient_email: &str) -> StoredDrop {
    StoredDrop {
        id: Uuid::new_v4().to_string(),
        sender_email: sender_email.to_string(),
        sender_public_key: "sender-pubkey".to_string(),
        ciphertext: "encrypted-data".to_string(),
        aes_nonce: "nonce123".to_string(),
        wrapped_keys: vec![WrappedKeyPayload {
            recipient_email: recipient_email.to_string(),
            nonce: "wrap-nonce".to_string(),
            wrapped_key: "wrapped-aes-key".to_string(),
        }],
        created_at: Utc::now(),
        once: false,
    }
}

/// Creates a mock workspace with active subscription.
pub fn mock_workspace() -> Workspace {
    Workspace {
        id: Uuid::new_v4(),
        name: "Test Workspace".to_string(),
        created_at: Utc::now(),
        stripe_customer_id: Some("cus_test".to_string()),
        stripe_subscription_id: Some("sub_test".to_string()),
        subscription_status: "active".to_string(),
    }
}

/// Creates a mock workspace policy with no restrictions.
pub fn mock_policy(workspace_id: Uuid) -> WorkspacePolicy {
    WorkspacePolicy {
        workspace_id,
        max_ttl_seconds: None,
        min_ttl_seconds: None,
        default_ttl_seconds: None,
        require_once: None,
        default_once: None,
        allow_external: None,
        updated_at: Utc::now(),
    }
}

/// Builder for constructing test `AppState` with custom mocks.
///
/// Uses default (empty) mocks for any repo/store/service not explicitly set.
/// This allows tests to only configure the mocks they actually need.
pub struct TestStateBuilder {
    user_repo: Option<MockUserRepo>,
    device_repo: Option<MockDeviceRepo>,
    workspace_repo: Option<MockWorkspaceRepo>,
    activity_repo: Option<MockActivityRepo>,
    status_repo: Option<MockStatusRepo>,
    membership_service: Option<MockWorkspaceMembership>,
    webhook_repo: Option<MockWebhookRepo>,
    drop_store: Option<MockDropStore>,
    inbox_store: Option<MockInboxStore>,
    verification_store: Option<MockVerificationStore>,
    rate_limiter: Option<MockRateLimiter>,
    auth_service: Option<MockAuthService>,
    email_sender: Option<MockEmailSender>,
    dns_resolver: Option<MockDnsResolver>,
    webhook_sender: Option<MockWebhookSender>,
}

impl TestStateBuilder {
    /// Creates a new builder with no mocks configured.
    pub fn new() -> Self {
        Self {
            user_repo: None,
            device_repo: None,
            workspace_repo: None,
            activity_repo: None,
            status_repo: None,
            membership_service: None,
            webhook_repo: None,
            drop_store: None,
            inbox_store: None,
            verification_store: None,
            rate_limiter: None,
            auth_service: None,
            email_sender: None,
            dns_resolver: None,
            webhook_sender: None,
        }
    }

    pub fn with_user_repo(mut self, repo: MockUserRepo) -> Self {
        self.user_repo = Some(repo);
        self
    }

    pub fn with_device_repo(mut self, repo: MockDeviceRepo) -> Self {
        self.device_repo = Some(repo);
        self
    }

    pub fn with_workspace_repo(mut self, repo: MockWorkspaceRepo) -> Self {
        self.workspace_repo = Some(repo);
        self
    }

    pub fn with_activity_repo(mut self, repo: MockActivityRepo) -> Self {
        self.activity_repo = Some(repo);
        self
    }

    #[allow(dead_code)]
    pub fn with_status_repo(mut self, repo: MockStatusRepo) -> Self {
        self.status_repo = Some(repo);
        self
    }

    pub fn with_membership_service(mut self, service: MockWorkspaceMembership) -> Self {
        self.membership_service = Some(service);
        self
    }

    pub fn with_webhook_repo(mut self, repo: MockWebhookRepo) -> Self {
        self.webhook_repo = Some(repo);
        self
    }

    pub fn with_drop_store(mut self, store: MockDropStore) -> Self {
        self.drop_store = Some(store);
        self
    }

    pub fn with_inbox_store(mut self, store: MockInboxStore) -> Self {
        self.inbox_store = Some(store);
        self
    }

    pub fn with_verification_store(mut self, store: MockVerificationStore) -> Self {
        self.verification_store = Some(store);
        self
    }

    pub fn with_rate_limiter(mut self, limiter: MockRateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    pub fn with_auth_service(mut self, service: MockAuthService) -> Self {
        self.auth_service = Some(service);
        self
    }

    pub fn with_email_sender(mut self, sender: MockEmailSender) -> Self {
        self.email_sender = Some(sender);
        self
    }

    #[allow(dead_code)]
    pub fn with_dns_resolver(mut self, resolver: MockDnsResolver) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    pub fn with_webhook_sender(mut self, sender: MockWebhookSender) -> Self {
        self.webhook_sender = Some(sender);
        self
    }

    /// Builds the `AppState` using configured mocks or defaults.
    pub fn build(self) -> AppState {
        let repos = Repos {
            users: Arc::new(self.user_repo.unwrap_or_else(MockUserRepo::new)),
            devices: Arc::new(self.device_repo.unwrap_or_else(MockDeviceRepo::new)),
            workspaces: Arc::new(self.workspace_repo.unwrap_or_else(MockWorkspaceRepo::new)),
            activity: Arc::new(self.activity_repo.unwrap_or_else(MockActivityRepo::new)),
            status: Arc::new(self.status_repo.unwrap_or_else(MockStatusRepo::new)),
            membership: Arc::new(
                self.membership_service
                    .unwrap_or_else(MockWorkspaceMembership::new),
            ),
            webhooks: Arc::new(self.webhook_repo.unwrap_or_else(default_webhook_repo)),
        };

        let stores = Stores {
            drops: Arc::new(self.drop_store.unwrap_or_else(MockDropStore::new)),
            inbox: Arc::new(self.inbox_store.unwrap_or_else(MockInboxStore::new)),
            verification: Arc::new(
                self.verification_store
                    .unwrap_or_else(MockVerificationStore::new),
            ),
            rate_limiter: Arc::new(self.rate_limiter.unwrap_or_else(MockRateLimiter::new)),
        };

        let auth = Arc::new(self.auth_service.unwrap_or_else(MockAuthService::new))
            as Arc<dyn crate::services::AuthService>;
        let email = Arc::new(self.email_sender.unwrap_or_else(MockEmailSender::new))
            as Arc<dyn crate::services::EmailSender>;
        let dns = Arc::new(self.dns_resolver.unwrap_or_else(MockDnsResolver::new))
            as Arc<dyn crate::services::DnsResolver>;
        let webhook = Arc::new(self.webhook_sender.unwrap_or_else(MockWebhookSender::new))
            as Arc<dyn crate::services::WebhookSender>;
        let stripe = stripe::Client::new("sk_test_xxx");

        AppState {
            config: test_config(),
            repos,
            stores,
            auth,
            email,
            dns,
            stripe,
            webhook,
        }
    }
}

impl Default for TestStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a default webhook repo mock that returns None for get_by_user.
fn default_webhook_repo() -> MockWebhookRepo {
    let mut repo = MockWebhookRepo::new();
    repo.expect_get_by_user().returning(|_| Ok(None));
    repo
}
