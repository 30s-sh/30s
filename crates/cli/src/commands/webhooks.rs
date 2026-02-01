//! Manage account-level webhooks.
//!
//! Webhooks allow you to receive HTTP notifications when you receive drops.
//! Each webhook is signed with HMAC-SHA256 for verification.

use anyhow::Result;

use crate::{api::Api, config::Config, credentials, ui};

/// Set a webhook URL to receive drop notifications.
pub async fn set(config: &Config, url: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let webhook = ui::spin("Configuring webhook...", api.set_webhook(api_key, url)).await?;

    ui::success("Webhook configured");
    println!();
    println!("URL: {}", webhook.url);
    println!("Secret: {}", webhook.secret);
    println!();
    ui::hint("Store your secret securely. You'll need it to verify webhook signatures.");
    ui::hint("The signature is computed as: sha256=HMAC(secret, \"<timestamp>.<payload>\")");

    Ok(())
}

/// Show the current webhook configuration.
pub async fn show(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    match api.get_webhook(api_key).await {
        Ok(webhook) => {
            println!("URL: {}", webhook.url);
            println!("Secret: {}", webhook.secret);
        }
        Err(e) if e.to_string().contains("Not Found") => {
            println!("No webhook configured");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Clear the webhook configuration.
pub async fn clear(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    ui::spin("Clearing webhook...", api.clear_webhook(api_key)).await?;

    ui::success("Webhook cleared");

    Ok(())
}

/// Send a test webhook event.
pub async fn test(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let response = ui::spin("Sending test webhook...", api.test_webhook(api_key)).await?;

    ui::success(&response.message);
    ui::hint("Check your webhook endpoint for the test event.");

    Ok(())
}
