//! Permanently delete user account and all associated data.

use anyhow::Result;
use dialoguer::{Confirm, theme::ColorfulTheme};

use crate::{api::Api, config::Config, credentials, ui};

pub async fn run(config: &Config) -> Result<()> {
    let api = Api::new(config.api_url.to_string());
    let api_key = credentials::get_api_key().await?;

    // Get user email for confirmation message
    let me = ui::spin("Fetching account info...", api.get_me(api_key.clone())).await?;

    println!();
    println!("This will permanently delete your account and all associated data:");
    println!("  - Your user profile");
    println!("  - All registered devices");
    println!("  - All drops you've sent or received");
    println!();

    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Delete account {}?", me.email))
        .default(false)
        .interact()?;

    if !confirmed {
        println!("Aborted.");
        return Ok(());
    }

    ui::spin("Deleting account...", api.delete_account(api_key)).await?;

    // Clear local credentials
    credentials::delete_all().await?;

    ui::success("Account deleted");

    Ok(())
}
