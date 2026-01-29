//! Workspace management commands for domain verification.

use anyhow::{Result, anyhow};
use humantime::{format_duration, parse_duration};
use shared::api::UpdatePoliciesPayload;
use std::time::Duration;

use crate::{api::Api, config::Config, credentials, ui};

/// Show workspace status.
pub async fn status(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    match api.get_workspace(api_key).await {
        Ok(workspace) => {
            println!("Workspace:    {}", workspace.name);
            println!("Created:      {}", workspace.created_at.format("%Y-%m-%d"));
            println!("Subscription: {}", format_status(&workspace.subscription_status));
            if workspace.is_paid {
                println!("Benefits:     Unlimited internal sends, 50/month external");
            } else {
                println!();
                println!("Upgrade for unlimited internal sends:");
                println!("  30s billing subscribe");
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No workspace found") {
                println!("No workspace found for your email domain.");
                println!();
                println!("Create a workspace:");
                println!("  30s workspace create <name>");
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Create a new workspace.
pub async fn create(config: &Config, name: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let workspace = api.create_workspace(api_key, name).await?;

    ui::success(&format!("Workspace '{}' created!", workspace.name));
    println!();
    println!("Next steps:");
    println!("  1. Subscribe:     30s billing subscribe");
    println!("  2. Add domain:    30s workspace domain add yourdomain.com");
    println!("  3. Verify domain: 30s workspace domain verify yourdomain.com");

    Ok(())
}

fn format_status(status: &str) -> &str {
    match status {
        "active" => "Active",
        "past_due" => "Past Due (please update payment method)",
        "canceled" => "Canceled",
        "unpaid" => "Unpaid",
        "none" => "Free tier",
        _ => status,
    }
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

/// Display workspace policies.
pub async fn policies(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let policies = api.get_policies(api_key).await?;

    println!("Workspace Policies:");
    println!();

    // TTL policies
    match (policies.min_ttl_seconds, policies.max_ttl_seconds) {
        (Some(min), Some(max)) => {
            println!("  TTL range:      {} - {}", format_seconds(min), format_seconds(max));
        }
        (Some(min), None) => {
            println!("  Minimum TTL:    {}", format_seconds(min));
        }
        (None, Some(max)) => {
            println!("  Maximum TTL:    {}", format_seconds(max));
        }
        (None, None) => {
            println!("  TTL range:      No restriction (global max: 24h)");
        }
    }

    if let Some(default) = policies.default_ttl_seconds {
        println!("  Default TTL:    {}", format_seconds(default));
    } else {
        println!("  Default TTL:    30s (CLI default)");
    }

    println!();

    // Once policies
    if policies.require_once == Some(true) {
        println!("  Once:            Required");
    } else if policies.default_once == Some(true) {
        println!("  Once:            Default on");
    } else {
        println!("  Once:            Optional");
    }

    // External recipients
    if policies.allow_external == Some(false) {
        println!("  External sends:  Blocked");
    } else {
        println!("  External sends:  Allowed");
    }

    Ok(())
}

/// Set a workspace policy.
pub async fn set_policy(config: &Config, key: &str, value: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    // First get current policies so we only update the specified one
    let current = api.get_policies(api_key.clone()).await?;

    let payload = match key {
        "max-ttl" => {
            let seconds = parse_duration_to_seconds(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: Some(seconds),
                min_ttl_seconds: current.min_ttl_seconds,
                default_ttl_seconds: current.default_ttl_seconds,
                require_once: current.require_once,
                default_once: current.default_once,
                allow_external: current.allow_external,
            }
        }
        "min-ttl" => {
            let seconds = parse_duration_to_seconds(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: current.max_ttl_seconds,
                min_ttl_seconds: Some(seconds),
                default_ttl_seconds: current.default_ttl_seconds,
                require_once: current.require_once,
                default_once: current.default_once,
                allow_external: current.allow_external,
            }
        }
        "default-ttl" => {
            let seconds = parse_duration_to_seconds(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: current.max_ttl_seconds,
                min_ttl_seconds: current.min_ttl_seconds,
                default_ttl_seconds: Some(seconds),
                require_once: current.require_once,
                default_once: current.default_once,
                allow_external: current.allow_external,
            }
        }
        "require-once" => {
            let enabled = parse_bool(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: current.max_ttl_seconds,
                min_ttl_seconds: current.min_ttl_seconds,
                default_ttl_seconds: current.default_ttl_seconds,
                require_once: Some(enabled),
                default_once: current.default_once,
                allow_external: current.allow_external,
            }
        }
        "default-once" => {
            let enabled = parse_bool(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: current.max_ttl_seconds,
                min_ttl_seconds: current.min_ttl_seconds,
                default_ttl_seconds: current.default_ttl_seconds,
                require_once: current.require_once,
                default_once: Some(enabled),
                allow_external: current.allow_external,
            }
        }
        "allow-external" => {
            let enabled = parse_bool(value)?;
            UpdatePoliciesPayload {
                max_ttl_seconds: current.max_ttl_seconds,
                min_ttl_seconds: current.min_ttl_seconds,
                default_ttl_seconds: current.default_ttl_seconds,
                require_once: current.require_once,
                default_once: current.default_once,
                allow_external: Some(enabled),
            }
        }
        _ => {
            return Err(anyhow!(
                "Unknown policy key: {}. Valid keys: max-ttl, min-ttl, default-ttl, require-once, default-once, allow-external",
                key
            ));
        }
    };

    api.update_policies(api_key, payload).await?;
    ui::success(&format!("Policy '{}' set to '{}'", key, value));

    Ok(())
}

/// Clear a workspace policy (set to NULL/unrestricted).
pub async fn clear_policy(config: &Config, key: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    // First get current policies so we only clear the specified one
    let current = api.get_policies(api_key.clone()).await?;

    let payload = match key {
        "max-ttl" => UpdatePoliciesPayload {
            max_ttl_seconds: None,
            min_ttl_seconds: current.min_ttl_seconds,
            default_ttl_seconds: current.default_ttl_seconds,
            require_once: current.require_once,
            default_once: current.default_once,
            allow_external: current.allow_external,
        },
        "min-ttl" => UpdatePoliciesPayload {
            max_ttl_seconds: current.max_ttl_seconds,
            min_ttl_seconds: None,
            default_ttl_seconds: current.default_ttl_seconds,
            require_once: current.require_once,
            default_once: current.default_once,
            allow_external: current.allow_external,
        },
        "default-ttl" => UpdatePoliciesPayload {
            max_ttl_seconds: current.max_ttl_seconds,
            min_ttl_seconds: current.min_ttl_seconds,
            default_ttl_seconds: None,
            require_once: current.require_once,
            default_once: current.default_once,
            allow_external: current.allow_external,
        },
        "require-once" => UpdatePoliciesPayload {
            max_ttl_seconds: current.max_ttl_seconds,
            min_ttl_seconds: current.min_ttl_seconds,
            default_ttl_seconds: current.default_ttl_seconds,
            require_once: None,
            default_once: current.default_once,
            allow_external: current.allow_external,
        },
        "default-once" => UpdatePoliciesPayload {
            max_ttl_seconds: current.max_ttl_seconds,
            min_ttl_seconds: current.min_ttl_seconds,
            default_ttl_seconds: current.default_ttl_seconds,
            require_once: current.require_once,
            default_once: None,
            allow_external: current.allow_external,
        },
        "allow-external" => UpdatePoliciesPayload {
            max_ttl_seconds: current.max_ttl_seconds,
            min_ttl_seconds: current.min_ttl_seconds,
            default_ttl_seconds: current.default_ttl_seconds,
            require_once: current.require_once,
            default_once: current.default_once,
            allow_external: None,
        },
        _ => {
            return Err(anyhow!(
                "Unknown policy key: {}. Valid keys: max-ttl, min-ttl, default-ttl, require-once, default-once, allow-external",
                key
            ));
        }
    };

    api.update_policies(api_key, payload).await?;
    ui::success(&format!("Policy '{}' cleared", key));

    Ok(())
}

/// Parse a duration string (e.g., "1h", "30m") to seconds.
fn parse_duration_to_seconds(s: &str) -> Result<i32> {
    let duration = parse_duration(s)?;
    let seconds = duration.as_secs();
    if seconds > i32::MAX as u64 {
        return Err(anyhow!("Duration too large"));
    }
    Ok(seconds as i32)
}

/// Parse a boolean value from string.
fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(anyhow!("Invalid boolean value: {}. Use true/false", s)),
    }
}

/// Format seconds as a human-readable duration.
fn format_seconds(seconds: i32) -> String {
    format_duration(Duration::from_secs(seconds as u64)).to_string()
}
