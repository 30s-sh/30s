//! Manage registered devices.
//!
//! Each device has its own keypair for end-to-end encryption. Users accumulate
//! devices over time (new laptops, reinstalls, etc.) and may need to clean up
//! old ones that are no longer in use.
//!
//! Listing devices helps identify orphaned entries. Deleting a device removes
//! its public key from the server, so secrets can no longer be encrypted to it.

use anyhow::Result;
use chrono_humanize::HumanTime;
use dialoguer::{Confirm, theme::ColorfulTheme};
use tabled::{Table, Tabled, settings::Style};

use crate::{api::Api, config::Config, credentials, ui};

#[derive(Tabled)]
struct DeviceRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Created")]
    created: String,
}

pub async fn list(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;

    let api = Api::new(config.api_url.clone());
    let devices = ui::spin("Fetching devices...", api.list_devices(api_key)).await?;

    if devices.is_empty() {
        println!("No devices");
        return Ok(());
    }

    let rows: Vec<DeviceRow> = devices
        .into_iter()
        .map(|d| DeviceRow {
            id: d.id.to_string(),
            created: HumanTime::from(d.created_at).to_string(),
        })
        .collect();

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}

pub async fn delete(config: &Config, id: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    // Warn if inbox has pending drops - they may become inaccessible
    let inbox = ui::spin("Checking inbox...", api.get_inbox(api_key.clone())).await?;

    if !inbox.is_empty() {
        ui::warning(&format!(
            "You have {} pending drop(s) in your inbox.",
            inbox.len()
        ));
        ui::hint("Deleting this device may make some drops inaccessible.");
        eprintln!();

        let proceed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Continue with deletion?")
            .default(false)
            .interact()?;

        if !proceed {
            anyhow::bail!("Aborted");
        }
    }

    ui::spin("Deleting...", api.delete_device(api_key, id)).await?;

    ui::success("Deleted");

    Ok(())
}
