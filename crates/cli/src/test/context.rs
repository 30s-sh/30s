//! Test context for CLI command tests.
//!
//! Provides a TestContext struct that sets up:
//! - A wiremock MockServer for API mocking
//! - Temporary credential files
//! - Test configuration pointing to the mock server

use std::sync::Arc;

use tempfile::TempDir;
use wiremock::MockServer;

use crate::config::Config;

/// Test context for CLI command tests.
///
/// Sets up a mock API server and temporary credentials storage.
/// The mock server URL is automatically configured as the API URL.
pub struct TestContext {
    /// The wiremock mock server for API mocking.
    pub mock_server: MockServer,
    /// Configuration pointing to the mock server.
    pub config: Config,
    /// Temporary directory for credential storage (keeps it alive).
    pub _temp_dir: Arc<TempDir>,
}

impl TestContext {
    /// Create a new test context with a running mock server.
    ///
    /// Sets XDG_CONFIG_HOME to a temp directory so credentials
    /// are isolated from the real user's config.
    pub async fn new() -> Self {
        let mock_server = MockServer::start().await;
        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // SAFETY: These env vars are set in test context only, where we control
        // that tests don't run in parallel with the same env vars.
        // This is necessary to isolate credential storage for tests.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            std::env::set_var("HOME", temp_dir.path());
        }

        let config = Config {
            api_url: mock_server.uri(),
        };

        Self {
            mock_server,
            config,
            _temp_dir: Arc::new(temp_dir),
        }
    }

    /// Create a test context with pre-configured credentials.
    ///
    /// Writes credentials to the temp config directory so commands
    /// that require authentication will find them.
    pub async fn with_credentials(api_key: &str, private_key_b64: &str) -> Self {
        let ctx = Self::new().await;

        // Write credentials file
        let config_dir = ctx._temp_dir.path().join("30s");
        std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");

        let creds_path = config_dir.join("credentials.json");
        let creds_json = serde_json::json!({
            "api_key": api_key,
            "private_key": private_key_b64
        });
        std::fs::write(&creds_path, creds_json.to_string()).expect("Failed to write credentials");

        ctx
    }

    /// Create a test context with a valid keypair for crypto operations.
    ///
    /// Generates a real X25519 keypair for tests that need to decrypt data.
    pub async fn with_keypair() -> (Self, crypto_box::SecretKey) {
        use aes_gcm::aead::OsRng;
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use crypto_box::SecretKey;

        let secret_key = SecretKey::generate(&mut OsRng);
        let private_key_b64 = BASE64.encode(secret_key.to_bytes());

        let ctx = Self::with_credentials("test-api-key", &private_key_b64).await;

        (ctx, secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_context_creates_mock_server() {
        let ctx = TestContext::new().await;

        // Mock server should be running
        assert!(ctx.mock_server.uri().starts_with("http://"));

        // Config should point to mock server
        assert_eq!(ctx.config.api_url, ctx.mock_server.uri());
    }

    #[tokio::test]
    async fn test_context_with_credentials() {
        let ctx = TestContext::with_credentials("my-key", "cHJpdmF0ZQ==").await;

        // Credentials file should exist
        let creds_path = ctx._temp_dir.path().join("30s").join("credentials.json");
        assert!(creds_path.exists());

        // Read and verify credentials
        let content = std::fs::read_to_string(&creds_path).unwrap();
        let creds: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(creds["api_key"], "my-key");
        assert_eq!(creds["private_key"], "cHJpdmF0ZQ==");
    }

    #[tokio::test]
    async fn test_context_with_keypair() {
        let (ctx, secret_key) = TestContext::with_keypair().await;

        // Should have valid keypair
        assert_eq!(secret_key.to_bytes().len(), 32);

        // Credentials should be written
        let creds_path = ctx._temp_dir.path().join("30s").join("credentials.json");
        assert!(creds_path.exists());
    }
}
