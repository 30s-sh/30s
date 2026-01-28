//! Workspace management commands for domain verification.

use anyhow::Result;

use crate::{api::Api, config::Config, credentials, ui};

/// Show workspace status.
pub async fn status(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    match api.get_workspace(api_key).await {
        Ok(workspace) => {
            println!("Workspace: {}", workspace.name);
            println!("Created:   {}", workspace.created_at.format("%Y-%m-%d"));
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No workspace found") {
                println!("No workspace found for your email domain.");
                println!();
                println!("To create a workspace, verify your domain:");
                println!("  30s workspace domain add yourdomain.com");
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Add a domain for verification.
pub async fn add_domain(config: &Config, domain: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let response = api.add_domain(api_key, domain).await?;

    println!("Domain {} added for verification.", response.domain);
    println!();
    println!("Add the following TXT record to your DNS:");
    println!();
    println!("  Host:  {}", response.txt_host);
    println!("  Value: {}", response.txt_value);
    println!();
    println!("After adding the record, run:");
    println!("  30s workspace domain verify {}", response.domain);

    Ok(())
}

/// Verify a domain via DNS TXT record lookup.
pub async fn verify_domain(config: &Config, domain: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let response = ui::spin("Verifying DNS record...", api.verify_domain(api_key, domain)).await?;

    if response.workspace_created {
        ui::success(&format!(
            "Domain {} verified! Workspace '{}' created.",
            response.domain, response.workspace_name
        ));
        println!();
        println!("You are now an admin of this workspace.");
        println!(
            "Users with @{} email addresses will automatically belong to this workspace.",
            response.domain
        );
    } else {
        ui::success(&format!(
            "Domain {} verified and added to workspace '{}'.",
            response.domain, response.workspace_name
        ));
    }

    Ok(())
}

/// List all domains for the workspace.
pub async fn list_domains(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let domains = api.list_domains(api_key).await?;

    if domains.is_empty() {
        println!("No domains configured.");
        return Ok(());
    }

    println!("Domains:");
    for domain in domains {
        let status = if domain.verified { "verified" } else { "pending" };
        println!("  {} ({})", domain.domain, status);
    }

    Ok(())
}
