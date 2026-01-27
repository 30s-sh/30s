//! Version checking for CLI updates.

use semver::Version;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASES_URL: &str = "https://30s-releases.sfo3.cdn.digitaloceanspaces.com/latest.txt";

/// Fetch the latest version from the releases server.
/// Returns None on any error (network, parse, etc.) to avoid blocking the CLI.
pub async fn fetch_latest() -> Option<String> {
    let response = reqwest::get(RELEASES_URL).await.ok()?;
    let text = response.text().await.ok()?;
    let version = text.trim().trim_start_matches('v').to_string();

    // Validate it's a proper semver before returning
    Version::parse(&version).ok()?;

    Some(version)
}

/// Check if the latest version is newer than the current version.
pub fn is_update_available(current: &str, latest: &str) -> bool {
    let current = current.trim_start_matches('v');
    let latest = latest.trim_start_matches('v');

    match (Version::parse(current), Version::parse(latest)) {
        (Ok(current), Ok(latest)) => latest > current,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_available() {
        assert!(is_update_available("0.1.0", "0.2.0"));
        assert!(is_update_available("0.1.0", "1.0.0"));
        assert!(is_update_available("1.0.0", "1.0.1"));
    }

    #[test]
    fn test_no_update_available() {
        assert!(!is_update_available("0.2.0", "0.1.0"));
        assert!(!is_update_available("0.1.0", "0.1.0"));
        assert!(!is_update_available("1.0.0", "0.9.0"));
    }

    #[test]
    fn test_handles_v_prefix() {
        assert!(is_update_available("v0.1.0", "v0.2.0"));
        assert!(is_update_available("0.1.0", "v0.2.0"));
        assert!(is_update_available("v0.1.0", "0.2.0"));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!is_update_available("invalid", "0.2.0"));
        assert!(!is_update_available("0.1.0", "invalid"));
        assert!(!is_update_available("invalid", "also-invalid"));
    }
}
