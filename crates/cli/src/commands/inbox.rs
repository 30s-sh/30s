//! List encrypted drops waiting in your inbox.
//!
//! Shows all non-expired drops sent to you, displaying:
//! - Drop ID (used with `open` command)
//! - Sender's email
//! - When it was created
//!
//! The secrets are still encrypted at this point - use `open <id>` to decrypt.

use anyhow::Result;
use chrono_humanize::HumanTime;
use tabled::{Table, Tabled, settings::Style};

use crate::{api::Api, config::Config, credentials, ui};

#[derive(Tabled)]
struct InboxRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "From")]
    from: String,
    #[tabled(rename = "Received")]
    received: String,
}

pub async fn run(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.to_string());

    let inbox = ui::spin("Fetching inbox...", api.get_inbox(api_key)).await?;

    if inbox.is_empty() {
        println!("No drops in your inbox");
        return Ok(());
    }

    let rows: Vec<InboxRow> = inbox
        .into_iter()
        .map(|item| InboxRow {
            id: item.id,
            from: item.sender_email,
            received: HumanTime::from(item.created_at).to_string(),
        })
        .collect();

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}
