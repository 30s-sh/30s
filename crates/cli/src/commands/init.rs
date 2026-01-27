//! Initialize the CLI with user authentication and device registration.
//!
//! Flow:
//! 1. Request verification code (sent to user's email)
//! 2. User enters code, CLI verifies and receives API key
//! 3. Generate device keypair (crypto_box x25519)
//! 4. Register public key with server (for encrypting secrets to this device)
//! 5. Store API key and private key in system keyring
//!
//! The private key never leaves the device. Only the public key is sent to the server.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crypto_box::{SecretKey, aead::OsRng};
use shared::api::{RegisterDevicePayload, RequestCodePayload, VerifyCodePayload};

use crate::{api::Api, config::Config, credentials, ui};

pub async fn run(config: &Config, email: &str) -> Result<()> {
    let api = Api::new(config.api_url.to_string());

    ui::spin(
        "Sending verification code...",
        api.request_code(RequestCodePayload {
            email: email.into(),
        }),
    )
    .await?;

    let code = ui::prompt_code()?;

    let response = ui::spin(
        "Verifying...",
        api.verify_code(VerifyCodePayload {
            email: email.into(),
            code,
        }),
    )
    .await?;

    let keypair = SecretKey::generate(&mut OsRng);

    // Register device before storing secrets locally - if this fails, we don't
    // want orphaned credentials in the keyring
    ui::spin(
        "Registering device...",
        api.register_device(
            response.api_key.clone(),
            RegisterDevicePayload {
                public_key: BASE64.encode(keypair.public_key()),
            },
        ),
    )
    .await?;

    // Store credentials (keyring with file fallback for headless environments)
    credentials::set_api_key(response.api_key).await?;
    credentials::set_private_key(BASE64.encode(keypair.to_bytes())).await?;

    ui::success("Authenticated");

    Ok(())
}
