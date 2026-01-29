//! Send encrypted secrets to recipients.
//!
//! Flow:
//! 1. Parse expiration duration (e.g., "30s", "1h", "7d")
//! 2. Fetch recipient public keys from API
//! 3. Load sender's private key from keyring
//! 4. Encrypt the secret using envelope encryption
//! 5. Send encrypted drop to API

use std::io::{self, Read};
use std::time::Duration;

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use crypto_box::SecretKey;
use dialoguer::{Confirm, theme::ColorfulTheme};
use humantime::{format_duration, parse_duration};
use owo_colors::OwoColorize;
use shared::api::{CreateDropPayload, WrappedKeyPayload};
use zeroize::Zeroize;

use crate::known_keys::KeyCheckResult;
use crate::{api::Api, config::Config, credentials, crypto, known_keys, ui};

pub async fn run(
    config: &Config,
    recipients: &[String],
    expires_in: &str,
    secret: &str,
    once: bool,
) -> Result<()> {
    // Read from stdin if message is "-"
    let secret = if secret == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf.trim_end().to_string()
    } else {
        secret.to_string()
    };

    let api = Api::new(config.api_url.to_string());

    // Load credentials from keyring
    let api_key = credentials::get_api_key().await?;

    let private_key_b64 = credentials::get_private_key().await?;
    let mut private_key_bytes = BASE64.decode(private_key_b64)?;
    let sender_secret_key = SecretKey::from(
        <[u8; 32]>::try_from(private_key_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid private key length"))?,
    );
    private_key_bytes.zeroize();
    let sender_public_key = sender_secret_key.public_key();

    // Parse expiration duration (e.g., "30s", "5m", "1h", "7d")
    let duration = parse_duration(expires_in)?;
    let expires_at = Utc::now() + chrono::Duration::from_std(duration)?;

    // Fetch recipient public keys from API. We need these to wrap the symmetric
    // key so each recipient can decrypt the drop.
    let recipient_keys = ui::spin(
        "Fetching recipient keys...",
        api.get_public_keys(api_key.clone(), recipients.to_owned()),
    )
    .await?;

    // Check that we have at least one device key for each recipient
    let found_emails: std::collections::HashSet<_> =
        recipient_keys.iter().map(|k| k.email.as_str()).collect();
    let missing: Vec<&str> = recipients
        .iter()
        .filter(|r| !found_emails.contains(r.as_str()))
        .map(|s| s.as_str())
        .collect();

    if !missing.is_empty() {
        return Err(anyhow!("Recipient not found: {}", missing.join(", ")));
    }

    // Convert base64 public keys to PublicKey objects
    let recipient_public_keys: Result<Vec<crypto_box::PublicKey>> = recipient_keys
        .iter()
        .map(|rk| {
            let bytes = BASE64.decode(&rk.public_key)?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;
            Ok(crypto_box::PublicKey::from(key_bytes))
        })
        .collect();
    let recipient_public_keys = recipient_public_keys?;

    // Compute fingerprints and group by email
    let mut fingerprints_by_email: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for (rk, pub_key) in recipient_keys.iter().zip(&recipient_public_keys) {
        let fp = crypto::fingerprint(pub_key);
        fingerprints_by_email
            .entry(rk.email.clone())
            .or_default()
            .push(fp);
    }

    // TOFU key verification - check all keys for each recipient
    let mut known = known_keys::load();

    for email in recipients {
        let fps = match fingerprints_by_email.get(email) {
            Some(fps) => fps,
            None => continue,
        };

        match known.check(email, fps) {
            KeyCheckResult::FirstContact => {
                // Silently pin all keys on first contact
                known.pin_all(email, fps);
            }
            KeyCheckResult::Trusted => {
                // All keys match - nothing to do
            }
            KeyCheckResult::NewKeys { new } => {
                // New device keys detected - warn and prompt
                eprintln!();
                ui::warning(&format!("New device key(s) for {}", ui::bold(email)));
                for fp in &new {
                    eprintln!("  New: {}", ui::fingerprint(fp));
                }
                eprintln!();
                ui::hint("They may have added a new device, or this could be a MITM attack.");
                eprintln!();

                let proceed = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Trust new key(s)?")
                    .default(false)
                    .interact()?;

                if !proceed {
                    return Err(anyhow!("Aborted: new keys not trusted"));
                }

                // Add the new keys
                known.add_keys(email, &new);
            }
            KeyCheckResult::KeysMissing { missing } => {
                // Previously pinned keys are missing - warn and prompt
                eprintln!();
                ui::warning(&format!("Missing device key(s) for {}", ui::bold(email)));
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
                    return Err(anyhow!("Aborted: missing keys"));
                }

                // Update to current key set
                known.pin_all(email, fps);
            }
        }
    }

    // Save any new/updated keys
    known_keys::save(&known)?;

    // Encrypt the secret
    let encrypted = crypto::encrypt_drop(
        secret.as_bytes(),
        &sender_secret_key,
        &recipient_public_keys,
    )?;

    // Build wrapped keys payload with recipient email metadata. The order of
    // wrapped_keys matches recipient_public_keys, so we zip them to attach emails.
    let wrapped_keys: Vec<WrappedKeyPayload> = encrypted
        .wrapped_keys
        .iter()
        .zip(&recipient_keys)
        .map(|(wk, rk)| WrappedKeyPayload {
            recipient_email: rk.email.clone(),
            nonce: BASE64.encode(wk.nonce),
            wrapped_key: BASE64.encode(&wk.wrapped_key),
        })
        .collect();

    // Send to API
    let response = ui::spin(
        "Sending...",
        api.create_drop(
            api_key,
            CreateDropPayload {
                sender_public_key: BASE64.encode(sender_public_key.as_bytes()),
                ciphertext: BASE64.encode(&encrypted.ciphertext),
                aes_nonce: BASE64.encode(encrypted.aes_nonce),
                wrapped_keys,
                expires_at,
                once,
            },
        ),
    )
    .await?;

    ui::success(&format!("Sent! Drop ID: {}", ui::bold(&response.id)));

    // Show applied workspace policies
    if let Some(ref applied) = response.applied_policies {
        if let Some(ttl) = applied.default_ttl_applied {
            ui::info(&format!(
                "Workspace default TTL applied: {}",
                format_duration_seconds(ttl)
            ));
        }
        if applied.once_enforced == Some(true) {
            ui::info("Workspace policy: once enabled");
        }
    }

    // Display recipient fingerprints (one per email, show first)
    for email in recipients {
        if let Some(fps) = fingerprints_by_email.get(email)
            && let Some(fp) = fps.first()
        {
            let suffix = if fps.len() > 1 {
                format!(" (+{} devices)", fps.len() - 1)
            } else {
                String::new()
            };
            eprintln!("  {}: {}{}", email, ui::fingerprint(fp), suffix.dimmed());
        }
    }

    Ok(())
}

/// Format seconds as a human-readable duration.
fn format_duration_seconds(seconds: i32) -> String {
    format_duration(Duration::from_secs(seconds as u64)).to_string()
}
