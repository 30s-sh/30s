//! Manage contact aliases.
//!
//! Aliases provide shorthand names for frequently-used email addresses.
//! They are stored locally in `~/.config/30s/contacts.toml` and expanded
//! client-side before API calls.

use anyhow::{Result, anyhow};
use dialoguer::{Confirm, theme::ColorfulTheme};
use tabled::{Table, Tabled, settings::Style};

use crate::{contacts, ui};

#[derive(Tabled)]
struct AliasRow {
    #[tabled(rename = "Alias")]
    name: String,
    #[tabled(rename = "Email")]
    email: String,
}

/// List all aliases.
pub async fn list() -> Result<()> {
    let contacts = contacts::load();

    if contacts.aliases.is_empty() {
        println!("No aliases configured.");
        ui::hint("Add one with: 30s alias <name> <email>");
        return Ok(());
    }

    let mut rows: Vec<AliasRow> = contacts
        .aliases
        .into_iter()
        .map(|(name, email)| AliasRow { name, email })
        .collect();

    // Sort by alias name for consistent output
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}

/// Set an alias (add or update).
pub async fn set(name: &str, email: &str) -> Result<()> {
    // Validate inputs
    contacts::validate_alias_name(name)?;
    contacts::validate_email(email)?;

    let mut contacts = contacts::load();

    // Check if alias already exists
    if let Some(existing) = contacts.aliases.get(name) {
        if existing == email {
            ui::info(&format!("Alias '{}' already points to {}", name, email));
            return Ok(());
        }

        // Prompt to confirm overwrite
        eprintln!();
        ui::warning(&format!(
            "Alias '{}' already exists ({})",
            ui::bold(name),
            existing
        ));
        eprintln!();

        let proceed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Overwrite with {}?", email))
            .default(false)
            .interact()?;

        if !proceed {
            return Err(anyhow!("Aborted"));
        }
    }

    contacts.aliases.insert(name.to_string(), email.to_string());
    contacts::save(&contacts)?;

    ui::success(&format!("Alias '{}' → {}", ui::bold(name), email));

    Ok(())
}

/// Show a specific alias.
pub async fn show(name: &str) -> Result<()> {
    let contacts = contacts::load();

    match contacts.aliases.get(name) {
        Some(email) => {
            println!("{} → {}", ui::bold(name), email);
            Ok(())
        }
        None => Err(anyhow!("Alias '{}' doesn't exist", name)),
    }
}

/// Delete an alias.
pub async fn delete(name: &str) -> Result<()> {
    let mut contacts = contacts::load();

    if contacts.aliases.remove(name).is_none() {
        return Err(anyhow!("Alias '{}' doesn't exist", name));
    }

    contacts::save(&contacts)?;

    ui::success(&format!("Deleted alias '{}'", ui::bold(name)));

    Ok(())
}
