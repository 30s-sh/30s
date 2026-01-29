//! Show the email address and key fingerprint of the currently signed-in user.
//!
//! Fetches user info from the API using the stored credentials.
//! Useful for verifying which account is active when managing multiple identities.

use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crypto_box::SecretKey;

use crate::{api::Api, config::Config, credentials, crypto, ui};

pub async fn run(config: &Config) -> anyhow::Result<()> {
    let api_key = credentials::get_api_key().await?;

    let api = Api::new(config.api_url.clone());
    let me = ui::spin("Fetching...", api.get_me(api_key)).await?;

    // Load private key and derive public key for fingerprint
    let private_key_b64 = credentials::get_private_key().await?;
    let private_key_bytes = BASE64.decode(private_key_b64)?;
    let secret_key = SecretKey::from(
        <[u8; 32]>::try_from(private_key_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid private key length"))?,
    );
    let public_key = secret_key.public_key();
    let fingerprint = crypto::fingerprint(&public_key);

    println!("{}", ui::bold(&me.email));
    println!("Key: {}", ui::fingerprint(&fingerprint));

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use shared::api::MeResponse;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn get_me_api_call_returns_email() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .and(header("Authorization", "Bearer test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(MeResponse {
                email: "alice@example.com".to_string(),
            }))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.get_me("test-api-key".to_string()).await.unwrap();

        assert_eq!(result.email, "alice@example.com");
    }

    #[tokio::test]
    async fn get_me_api_call_with_invalid_key_fails() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.get_me("bad-key".to_string()).await;

        assert!(result.is_err());
    }
}
