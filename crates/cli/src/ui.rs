//! Terminal UI helpers for consistent colored output.

use std::future::Future;
use std::io::{Write, stdin, stdout};

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;

/// Print a success message with green checkmark.
pub fn success(msg: &str) {
    println!("{} {}", "✓".green(), msg);
}

/// Print an info message with blue info icon.
pub fn info(msg: &str) {
    eprintln!("{} {}", "ℹ".blue(), msg);
}

/// Print an error message with red X.
fn error(msg: &str) {
    eprintln!("{} {}", "✗".red(), msg);
}

/// Print a hint/suggestion (dimmed, indented).
fn hint(msg: &str) {
    eprintln!("  {} {}", "→".dimmed(), msg.dimmed());
}

/// Format a value as bold (for IDs, emails, etc.).
pub fn bold(s: &str) -> String {
    s.bold().to_string()
}

/// Run an async operation with a spinner showing the given message.
/// Returns the result of the operation.
pub async fn spin<T, F: Future<Output = T>>(msg: &str, fut: F) -> T {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.dim} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let result = fut.await;

    spinner.finish_and_clear();
    result
}

/// Display an error with contextual hints based on the error message.
pub fn print_error(err: &anyhow::Error) {
    let msg = err.to_string();
    error(&msg);

    // Add contextual hints based on error patterns (more specific checks first)
    if msg.contains("Not signed in") {
        // Already has suggestion in message
    } else if msg.contains("Recipient not found") {
        hint("Ask them to sign up first: 30s init <their-email>");
    } else if msg.contains("Could not decrypt") {
        hint("Ask the sender to re-send it to your current device.");
    } else if msg.contains("Invalid code") {
        hint("The code may have expired (15 min). Request a new one.");
    } else if msg.contains("401") || msg.contains("Unauthorized") {
        hint("Your session may have expired. Run: 30s init <email>");
    } else if msg.contains("403") || msg.contains("Forbidden") {
        hint("You don't have permission for this action.");
    } else if msg.contains("Drop not found") {
        hint("The drop may have expired or been deleted.");
    } else if msg.contains("connection")
        || msg.contains("Connection")
        || msg.contains("dns")
        || msg.contains("DNS")
        || msg.contains("timeout")
        || msg.contains("Timeout")
        || msg.contains("Network")
        || msg.contains("network")
        || msg.contains("No such host")
        || msg.contains("resolve")
    {
        hint("Check your internet connection and try again.");
    }
}

/// Print an update hint when a new version is available.
pub fn update_hint(current: &str, latest: &str) {
    eprintln!();
    eprintln!(
        "{} {} {} {}",
        "Update available:".yellow(),
        current.dimmed(),
        "→".dimmed(),
        latest.green()
    );
    eprintln!(
        "  {} {}",
        "→".dimmed(),
        "curl -sSL https://30s.sh/install.sh | sh".dimmed()
    );
}

/// Prompt the user for a verification code sent to their email.
/// Returns the trimmed code or an error if empty.
pub fn prompt_code() -> Result<String> {
    println!("Code sent to your email. Enter it below:");
    stdout().flush()?;

    let mut code = String::new();
    stdin().read_line(&mut code)?;
    let code = code.trim().to_string();

    if code.is_empty() {
        anyhow::bail!("No code entered. Check your email for the 6-digit code.");
    }

    Ok(code)
}
