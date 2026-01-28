//! Decrypt and display a drop from your inbox.
//!
//! Flow:
//! 1. Fetch the encrypted drop from the API
//! 2. Load recipient's private key from keyring
//! 3. Find the wrapped key for this user
//! 4. Decrypt using envelope encryption
//! 5. Display the plaintext secret

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crypto_box::{PublicKey, SecretKey};
use dialoguer::{Confirm, theme::ColorfulTheme};
use owo_colors::OwoColorize;
use zeroize::Zeroize;

use crate::{api::Api, config::Config, credentials, crypto, known_keys, ui};

pub async fn run(config: &Config, drop_id: String) -> Result<()> {
    let api = Api::new(config.api_url.to_string());

    // Load credentials from keyring
    let api_key = credentials::get_api_key().await?;

    let private_key_b64 = credentials::get_private_key().await?;
    let mut private_key_bytes = BASE64.decode(private_key_b64)?;
    let recipient_secret_key = SecretKey::from(
        <[u8; 32]>::try_from(private_key_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid private key length"))?,
    );
    private_key_bytes.zeroize();

    // Fetch the drop
    let drop = ui::spin("Fetching drop...", api.get_drop(api_key, &drop_id)).await?;

    // Decode sender's public key
    let sender_public_key_bytes = BASE64.decode(&drop.sender_public_key)?;
    let sender_public_key = PublicKey::from(
        <[u8; 32]>::try_from(sender_public_key_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid sender public key length"))?,
    );

    // TOFU key verification - check sender key against known keys
    let sender_fp = crypto::fingerprint(&sender_public_key);
    let fps = vec![sender_fp.clone()];
    let mut known = known_keys::load();

    match known.check(&drop.sender_email, &fps) {
        known_keys::KeyCheckResult::FirstContact => {
            // Silently pin on first contact
            known.pin_all(&drop.sender_email, &fps);
            known_keys::save(&known)?;
        }
        known_keys::KeyCheckResult::Trusted => {
            // Key matches - nothing to do
        }
        known_keys::KeyCheckResult::NewKeys { new } => {
            // This shouldn't happen when opening (we only have one key from sender)
            // but handle it anyway
            eprintln!();
            ui::warning(&format!("New device key(s) for {}", ui::bold(&drop.sender_email)));
            for fp in &new {
                eprintln!("  New: {}", ui::fingerprint(fp));
            }
            eprintln!();
            ui::hint("They may have added a new device, or this could be a MITM attack.");
            eprintln!();

            let proceed = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Trust new key?")
                .default(false)
                .interact()?;

            if !proceed {
                return Err(anyhow!("Aborted: new key not trusted"));
            }

            known.add_keys(&drop.sender_email, &new);
            known_keys::save(&known)?;
        }
        known_keys::KeyCheckResult::KeysMissing { missing } => {
            // Sender's key changed - warn and prompt
            eprintln!();
            ui::warning(&format!("Missing device key(s) for {}", ui::bold(&drop.sender_email)));
            for fp in &missing {
                eprintln!("  Missing: {}", fp.dimmed());
            }
            eprintln!();
            ui::hint("They may have removed a device, or this could indicate key compromise.");
            eprintln!();

            let proceed = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Continue anyway?")
                .default(false)
                .interact()?;

            if !proceed {
                return Err(anyhow!("Aborted: key mismatch"));
            }

            // Update to current key
            known.pin_all(&drop.sender_email, &fps);
            known_keys::save(&known)?;
        }
    }

    // Decode ciphertext and AES nonce (shared by all recipients)
    let ciphertext = BASE64.decode(&drop.ciphertext)?;
    let aes_nonce_bytes = BASE64.decode(&drop.aes_nonce)?;
    let aes_nonce: [u8; 12] = aes_nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid AES nonce length"))?;

    // Try each wrapped key until one successfully decrypts. The correct one is
    // the one encrypted for our device's public key.
    let mut plaintext = None;
    for wrapped_key in &drop.wrapped_keys {
        let nonce_bytes = BASE64.decode(&wrapped_key.nonce)?;
        let nonce: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid nonce length"))?;

        let wrapped_key_bytes = BASE64.decode(&wrapped_key.wrapped_key)?;

        let encrypted_drop = crypto::EncryptedDrop {
            ciphertext: ciphertext.clone(),
            aes_nonce,
            wrapped_keys: vec![crypto::WrappedKey {
                nonce,
                wrapped_key: wrapped_key_bytes,
            }],
        };

        // Try to decrypt - if this wrapped key wasn't for us, it will fail
        if let Ok(decrypted) = crypto::decrypt_drop(
            &encrypted_drop,
            &sender_public_key,
            &recipient_secret_key,
            &encrypted_drop.wrapped_keys[0],
        ) {
            plaintext = Some(decrypted);
            break;
        }
    }

    let plaintext = plaintext.ok_or_else(|| {
        anyhow!("Could not decrypt this drop. It may have been sent to a different device.")
    })?;

    // Display sender info with fingerprint
    ui::info(&format!("From {}", ui::bold(&drop.sender_email)));
    eprintln!("  Key: {}", ui::fingerprint(&sender_fp));
    eprintln!();

    // Display the secret
    let secret = String::from_utf8(plaintext)?;
    println!("{}", secret);

    // Notify if this was a burn-after-reading drop
    if drop.once {
        ui::info("This secret was deleted after viewing.");
    }

    Ok(())
}
