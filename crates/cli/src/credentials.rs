//! Credential storage with keyring and file-based fallback.
//!
//! Tries system keyring first (macOS Keychain, Windows Credential Manager, Linux Secret Service).
//! Falls back to file storage (~/.config/30s/credentials.json) if keyring isn't available.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use keyring::KeyringEntry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileCredentials {
    api_key: Option<String>,
    private_key: Option<String>,
}

fn credentials_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("30s")
        .join("credentials.json")
}

fn load_file_credentials() -> FileCredentials {
    let path = credentials_path();
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        FileCredentials::default()
    }
}

fn save_file_credentials(creds: &FileCredentials) -> Result<()> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)?;
    std::fs::write(&path, json)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load API key, with a helpful error if not signed in.
pub async fn get_api_key() -> Result<String> {
    // Try keyring first
    if let Ok(entry) = KeyringEntry::try_new("api-key")
        && let Ok(secret) = entry.get_secret().await
    {
        return Ok(secret);
    }

    // Fall back to file
    let creds = load_file_credentials();
    creds
        .api_key
        .ok_or_else(|| anyhow!("Not signed in. Run: 30s init <email>"))
}

/// Load private key.
pub async fn get_private_key() -> Result<String> {
    // Try keyring first
    if let Ok(entry) = KeyringEntry::try_new("private-key")
        && let Ok(secret) = entry.get_secret().await
    {
        return Ok(secret);
    }

    // Fall back to file
    let creds = load_file_credentials();
    creds
        .private_key
        .ok_or_else(|| anyhow!("Not signed in. Run: 30s init <email>"))
}

/// Store API key.
pub async fn set_api_key(value: String) -> Result<()> {
    // Try keyring first
    if let Ok(entry) = KeyringEntry::try_new("api-key")
        && entry.set_secret(value.clone()).await.is_ok()
    {
        return Ok(());
    }

    // Fall back to file
    let mut creds = load_file_credentials();
    creds.api_key = Some(value);
    save_file_credentials(&creds)
}

/// Store private key.
pub async fn set_private_key(value: String) -> Result<()> {
    // Try keyring first
    if let Ok(entry) = KeyringEntry::try_new("private-key")
        && entry.set_secret(value.clone()).await.is_ok()
    {
        return Ok(());
    }

    // Fall back to file
    let mut creds = load_file_credentials();
    creds.private_key = Some(value);
    save_file_credentials(&creds)
}

/// Delete all stored credentials.
pub async fn delete_all() -> Result<()> {
    // Try keyring
    if let Ok(entry) = KeyringEntry::try_new("api-key") {
        let _ = entry.delete_secret().await;
    }
    if let Ok(entry) = KeyringEntry::try_new("private-key") {
        let _ = entry.delete_secret().await;
    }

    // Also delete file if it exists
    let path = credentials_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    Ok(())
}
