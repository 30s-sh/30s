//! View workspace activity log.
//!
//! Shows recent drop activity (sent, opened, deleted) for your workspace.
//! Admins see all workspace activity; members see only their own.

use anyhow::Result;
use chrono::{Duration, Utc};
use chrono_humanize::HumanTime;
use shared::api::ActivityLogQuery;
use tabled::{Table, Tabled, settings::Style};

use crate::{api::Api, config::Config, credentials, ui};

#[derive(Tabled)]
struct ActivityRow {
    #[tabled(rename = "Time")]
    time: String,
    #[tabled(rename = "Event")]
    event: String,
    #[tabled(rename = "User")]
    user: String,
    #[tabled(rename = "Details")]
    details: String,
}

/// Format event type for display.
fn format_event_type(event_type: &str) -> &'static str {
    match event_type {
        "drop.sent" => "Sent",
        "drop.opened" => "Opened",
        "drop.deleted" => "Deleted",
        "drop.expired" => "Expired",
        "drop.failed" => "Failed",
        _ => "Unknown",
    }
}

/// Format event metadata for display.
fn format_details(event_type: &str, metadata: &serde_json::Value) -> String {
    match event_type {
        "drop.sent" => {
            let count = metadata
                .get("recipient_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let internal = metadata
                .get("internal")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let scope = if internal { "internal" } else { "external" };
            format!("{} recipient(s), {}", count, scope)
        }
        "drop.opened" => {
            let sender = metadata
                .get("sender_email")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("from {}", sender)
        }
        "drop.deleted" => {
            let count = metadata
                .get("recipient_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            format!("{} recipient(s)", count)
        }
        "drop.failed" => {
            let reason = metadata
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            reason.to_string()
        }
        _ => String::new(),
    }
}

/// Parse duration string like "24h", "7d", "30d".
fn parse_since(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();
    if s.ends_with('h') {
        let hours: i64 = s.trim_end_matches('h').parse().ok()?;
        Some(Duration::hours(hours))
    } else if s.ends_with('d') {
        let days: i64 = s.trim_end_matches('d').parse().ok()?;
        Some(Duration::days(days))
    } else if s.ends_with('w') {
        let weeks: i64 = s.trim_end_matches('w').parse().ok()?;
        Some(Duration::weeks(weeks))
    } else {
        None
    }
}

pub async fn run(
    config: &Config,
    since: Option<String>,
    event_type: Option<String>,
    limit: Option<u32>,
    all: bool,
) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.to_string());

    // Parse since duration (default: 7 days)
    let since_dt = match &since {
        Some(s) => {
            if let Some(duration) = parse_since(s) {
                Some(Utc::now() - duration)
            } else {
                // Try parsing as ISO date
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }
        }
        None => Some(Utc::now() - Duration::days(7)),
    };

    // --all means unlimited, --limit N means N, default is 50
    let effective_limit = if all { None } else { Some(limit.unwrap_or(50) as i32) };

    let query = ActivityLogQuery {
        since: since_dt.map(|dt| dt.timestamp()),
        event_type: event_type.clone(),
        limit: effective_limit,
    };

    let response = ui::spin(
        "Fetching activity...",
        api.get_activity(api_key, query),
    )
    .await?;

    if response.entries.is_empty() {
        println!("No activity found");
        if since.is_some() || event_type.is_some() {
            ui::hint("Try adjusting filters: --since 30d or remove --type filter");
        }
        return Ok(());
    }

    let rows: Vec<ActivityRow> = response
        .entries
        .into_iter()
        .map(|entry| ActivityRow {
            time: HumanTime::from(entry.created_at).to_string(),
            event: format_event_type(&entry.event_type).to_string(),
            user: entry.actor_email,
            details: format_details(&entry.event_type, &entry.metadata),
        })
        .collect();

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}
