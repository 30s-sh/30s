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
