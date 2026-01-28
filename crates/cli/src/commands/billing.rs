//! Billing management commands for Stripe subscription.

use anyhow::Result;

use crate::{api::Api, config::Config, credentials, ui};

/// Show billing status.
pub async fn status(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    match api.billing_status(api_key).await {
        Ok(status) => {
            println!("Subscription: {}", format_status(&status.subscription_status));
            if status.is_paid {
                println!("Benefits:     Unlimited internal sends, 50/month external");
            } else {
                println!("Limits:       50 sends/month total");
                println!();
                println!("Upgrade to a paid workspace for unlimited internal sends:");
                println!("  30s billing subscribe");
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("must be a workspace admin") {
                println!("No workspace found.");
                println!();
                println!("Create a workspace first:");
                println!("  30s workspace create <name>");
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Open Stripe Checkout to subscribe.
pub async fn subscribe(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let response = ui::spin("Creating checkout session...", api.create_checkout(api_key)).await?;

    ui::success("Opening Stripe Checkout in your browser...");
    println!();

    if let Err(e) = open::that(&response.checkout_url) {
        ui::warning(&format!("Could not open browser: {}", e));
        println!();
        println!("Open this URL manually:");
        println!("  {}", response.checkout_url);
    }

    Ok(())
}

/// Open Stripe Customer Portal to manage subscription.
pub async fn manage(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.clone());

    let response = ui::spin("Creating portal session...", api.create_portal(api_key)).await?;

    ui::success("Opening Stripe Customer Portal in your browser...");
    println!();

    if let Err(e) = open::that(&response.portal_url) {
        ui::warning(&format!("Could not open browser: {}", e));
        println!();
        println!("Open this URL manually:");
        println!("  {}", response.portal_url);
    }

    Ok(())
}

fn format_status(status: &str) -> &str {
    match status {
        "active" => "Active",
        "past_due" => "Past Due (please update payment method)",
        "canceled" => "Canceled",
        "unpaid" => "Unpaid",
        "none" => "None (free tier)",
        _ => status,
    }
}
