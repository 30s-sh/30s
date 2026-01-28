//! Manage contact groups.
//!
//! Groups provide shorthand names for multiple email addresses at once.
//! They are stored locally in `~/.config/30s/contacts.toml` and expanded
//! client-side before API calls. Use `@groupname` when sending to expand.

use anyhow::{Result, anyhow};
use dialoguer::{Confirm, theme::ColorfulTheme};
use tabled::{Table, Tabled, settings::Style};

use crate::{contacts, ui};

#[derive(Tabled)]
struct GroupRow {
    #[tabled(rename = "Group")]
    name: String,
    #[tabled(rename = "Members")]
    members: String,
}

/// List all groups.
pub async fn list() -> Result<()> {
    let contacts = contacts::load();

    if contacts.groups.is_empty() {
        println!("No groups configured.");
        ui::hint("Add one with: 30s groups <name> <email> [email...]");
        return Ok(());
    }

    let mut rows: Vec<GroupRow> = contacts
        .groups
        .into_iter()
        .map(|(name, members)| GroupRow {
            name,
            members: members.join(", "),
        })
        .collect();

    // Sort by group name for consistent output
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}

/// Set a group (add or update).
pub async fn set(name: &str, emails: &[String]) -> Result<()> {
    // Validate group name
    contacts::validate_group_name(name)?;

    // Validate all emails
    for email in emails {
        contacts::validate_email(email)?;
    }

    let mut contacts = contacts::load();

    // Check if group already exists
    if let Some(existing) = contacts.groups.get(name) {
        // Prompt to confirm overwrite
        eprintln!();
        ui::warning(&format!(
            "Group '{}' already exists with {} member(s)",
            ui::bold(name),
            existing.len()
        ));
        for member in existing {
            eprintln!("  - {}", member);
        }
        eprintln!();

        let proceed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Overwrite with {} new member(s)?", emails.len()))
            .default(false)
            .interact()?;

        if !proceed {
            return Err(anyhow!("Aborted"));
        }
    }

    contacts.groups.insert(name.to_string(), emails.to_vec());
    contacts::save(&contacts)?;

    ui::success(&format!(
        "Group '@{}' set with {} member(s)",
        ui::bold(name),
        emails.len()
    ));
    for email in emails {
        eprintln!("  - {}", email);
    }

    Ok(())
}

/// Show members of a specific group.
pub async fn show(name: &str) -> Result<()> {
    let contacts = contacts::load();

    match contacts.groups.get(name) {
        Some(members) => {
            println!("@{} ({} member(s)):", ui::bold(name), members.len());
            for member in members {
                println!("  {}", member);
            }
            Ok(())
        }
        None => Err(anyhow!("Group '{}' doesn't exist", name)),
    }
}

/// Delete a group.
pub async fn delete(name: &str) -> Result<()> {
    let mut contacts = contacts::load();

    if contacts.groups.remove(name).is_none() {
        return Err(anyhow!("Group '{}' doesn't exist", name));
    }

    contacts::save(&contacts)?;

    ui::success(&format!("Deleted group '@{}'", ui::bold(name)));

    Ok(())
}
