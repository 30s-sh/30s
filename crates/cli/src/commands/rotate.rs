//! Key rotation commands.
//!
//! - `rotate auth`: Rotate API key (requires email verification)
//! - `rotate keys`: Rotate device encryption keys (requires empty inbox)

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crypto_box::{SecretKey, aead::OsRng};
use shared::api::RegisterDevicePayload;

use crate::{api::Api, config::Config, credentials, ui};

/// Rotate API key with email verification.
pub async fn auth(config: &Config) -> Result<()> {
    let api = Api::new(config.api_url.to_string());
    let api_key = credentials::get_api_key().await?;

    ui::spin(
        "Sending verification code...",
        api.request_rotate(api_key.clone()),
    )
    .await?;

    let code = ui::prompt_code()?;

    let response = ui::spin(
        "Verifying and rotating key...",
        api.verify_rotate(api_key, code),
    )
    .await?;

    credentials::set_api_key(response.api_key).await?;

    ui::success("API key rotated");

    Ok(())
}

/// Rotate device encryption keys.
/// Requires inbox to be empty since pending drops are encrypted with current keys.
pub async fn keys(config: &Config) -> Result<()> {
    let api = Api::new(config.api_url.to_string());
    let api_key = credentials::get_api_key().await?;

    // Check inbox is empty
    let inbox = ui::spin("Checking inbox...", api.get_inbox(api_key.clone())).await?;

    if !inbox.is_empty() {
        anyhow::bail!(
            "You have {} pending drop(s). Open or delete them before rotating keys.",
            inbox.len()
        );
    }

    // Generate new keypair
    let keypair = SecretKey::generate(&mut OsRng);

    // Get current device ID
    let devices = ui::spin("Getting device info...", api.list_devices(api_key.clone())).await?;

    // Get the current device's ID (most recent device for this user)
    let current_device = devices
        .first()
        .ok_or_else(|| anyhow::anyhow!("No device registered. Run '30s init' first."))?;

    ui::spin(
        "Rotating keys...",
        api.update_device(
            api_key.clone(),
            &current_device.id,
            RegisterDevicePayload {
                public_key: BASE64.encode(keypair.public_key()),
            },
        ),
    )
    .await?;

    // Store new private key
    credentials::set_private_key(BASE64.encode(keypair.to_bytes())).await?;

    ui::success("Device keys rotated");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use shared::api::RotateVerifyResponse;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn request_rotate_succeeds() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/rotate"))
            .and(header("Authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.request_rotate("test-key".to_string()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn request_rotate_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/rotate"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({"error": "Too many requests"})),
            )
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.request_rotate("test-key".to_string()).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many requests"));
    }

    #[tokio::test]
    async fn verify_rotate_returns_new_key() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/rotate/verify"))
            .and(header("Authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(RotateVerifyResponse {
                api_key: "new-api-key".to_string(),
            }))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api
            .verify_rotate("test-key".to_string(), "123456".to_string())
            .await
            .unwrap();

        assert_eq!(result.api_key, "new-api-key");
    }

    #[tokio::test]
    async fn verify_rotate_invalid_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/rotate/verify"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "Invalid code"})),
            )
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api
            .verify_rotate("test-key".to_string(), "wrong".to_string())
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid code"));
    }
}
