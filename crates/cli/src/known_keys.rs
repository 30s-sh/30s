//! TOFU key pinning - Trust On First Use.
//!
//! Stores known public key fingerprints for contacts. Each contact can have multiple
//! device keys. On first contact, all keys are pinned. On subsequent contacts:
//! - If all keys match exactly: Trusted
//! - If new keys appear (but known keys still present): warn about new devices
//! - If known keys are missing: warn about potential compromise

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// A pinned device key for a known contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedDevice {
    /// The SHA-256 fingerprint of the public key.
    pub fingerprint: String,
    /// When this key was first seen.
    pub first_seen: DateTime<Utc>,
}

/// All pinned keys for a contact (may have multiple devices).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinnedContact {
    #[serde(default)]
    pub devices: Vec<PinnedDevice>,
}

impl PinnedContact {
    /// Get all fingerprints as a set.
    pub fn fingerprints(&self) -> HashSet<&str> {
        self.devices.iter().map(|d| d.fingerprint.as_str()).collect()
    }
}

/// Collection of known keys, keyed by email address.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownKeys {
    #[serde(default)]
    pub contacts: HashMap<String, PinnedContact>,
}

/// Result of checking keys against known keys.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyCheckResult {
    /// First time seeing this contact - all keys will be pinned.
    FirstContact,
    /// All keys match pinned set exactly.
    Trusted,
    /// Known keys present, but new unknown keys appeared (new devices).
    NewKeys { new: Vec<String> },
    /// Previously pinned keys are missing (potential compromise).
    KeysMissing { missing: Vec<String> },
}

/// Get the path to the known_keys.toml file.
fn path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("30s")
        .join("known_keys.toml")
}

/// Load known keys from disk.
pub fn load() -> KnownKeys {
    let path = path();

    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        KnownKeys::default()
    }
}

/// Save known keys to disk.
pub fn save(keys: &KnownKeys) -> Result<()> {
    let path = path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let toml = toml::to_string_pretty(keys)?;

    std::fs::write(&path, toml)?;

    Ok(())
}

impl KnownKeys {
    /// Check a set of fingerprints against known keys for an email.
    pub fn check(&self, email: &str, fingerprints: &[String]) -> KeyCheckResult {
        let current: HashSet<&str> = fingerprints.iter().map(|s| s.as_str()).collect();

        match self.contacts.get(email) {
            None => KeyCheckResult::FirstContact,
            Some(contact) => {
                let pinned = contact.fingerprints();

                // Check for missing keys (previously pinned but not in current set)
                let missing: Vec<String> = pinned
                    .iter()
                    .filter(|fp| !current.contains(*fp))
                    .map(|s| s.to_string())
                    .collect();

                if !missing.is_empty() {
                    return KeyCheckResult::KeysMissing { missing };
                }

                // Check for new keys (in current but not pinned)
                let new: Vec<String> = current
                    .iter()
                    .filter(|fp| !pinned.contains(*fp))
                    .map(|s| s.to_string())
                    .collect();

                if !new.is_empty() {
                    return KeyCheckResult::NewKeys { new };
                }

                KeyCheckResult::Trusted
            }
        }
    }

    /// Pin all fingerprints for an email address.
    pub fn pin_all(&mut self, email: &str, fingerprints: &[String]) {
        let now = Utc::now();
        let devices = fingerprints
            .iter()
            .map(|fp| PinnedDevice {
                fingerprint: fp.clone(),
                first_seen: now,
            })
            .collect();

        self.contacts
            .insert(email.to_string(), PinnedContact { devices });
    }

    /// Add new fingerprints to an existing contact (keeps existing ones).
    pub fn add_keys(&mut self, email: &str, new_fingerprints: &[String]) {
        let now = Utc::now();

        if let Some(contact) = self.contacts.get_mut(email) {
            // Collect existing fingerprints as owned strings to avoid borrow conflict
            let existing: HashSet<String> = contact
                .devices
                .iter()
                .map(|d| d.fingerprint.clone())
                .collect();

            for fp in new_fingerprints {
                if !existing.contains(fp) {
                    contact.devices.push(PinnedDevice {
                        fingerprint: fp.clone(),
                        first_seen: now,
                    });
                }
            }
        } else {
            self.pin_all(email, new_fingerprints);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_contact() {
        let keys = KnownKeys::default();

        let result = keys.check("alice@example.com", &["AAAA".to_string()]);
        assert_eq!(result, KeyCheckResult::FirstContact);
    }

    #[test]
    fn test_trusted_single_key() {
        let mut keys = KnownKeys::default();
        keys.pin_all("alice@example.com", &["AAAA".to_string()]);

        let result = keys.check("alice@example.com", &["AAAA".to_string()]);
        assert_eq!(result, KeyCheckResult::Trusted);
    }

    #[test]
    fn test_trusted_multiple_keys() {
        let mut keys = KnownKeys::default();
        keys.pin_all(
            "alice@example.com",
            &["AAAA".to_string(), "BBBB".to_string()],
        );

        // Order shouldn't matter
        let result = keys.check(
            "alice@example.com",
            &["BBBB".to_string(), "AAAA".to_string()],
        );
        assert_eq!(result, KeyCheckResult::Trusted);
    }

    #[test]
    fn test_new_keys_detected() {
        let mut keys = KnownKeys::default();
        keys.pin_all("alice@example.com", &["AAAA".to_string()]);

        let result = keys.check(
            "alice@example.com",
            &["AAAA".to_string(), "BBBB".to_string()],
        );
        assert_eq!(
            result,
            KeyCheckResult::NewKeys {
                new: vec!["BBBB".to_string()]
            }
        );
    }

    #[test]
    fn test_missing_keys_detected() {
        let mut keys = KnownKeys::default();
        keys.pin_all(
            "alice@example.com",
            &["AAAA".to_string(), "BBBB".to_string()],
        );

        let result = keys.check("alice@example.com", &["AAAA".to_string()]);
        assert_eq!(
            result,
            KeyCheckResult::KeysMissing {
                missing: vec!["BBBB".to_string()]
            }
        );
    }

    #[test]
    fn test_missing_takes_precedence_over_new() {
        let mut keys = KnownKeys::default();
        keys.pin_all("alice@example.com", &["AAAA".to_string()]);

        // AAAA is missing, CCCC is new - missing should be reported
        let result = keys.check("alice@example.com", &["CCCC".to_string()]);
        assert_eq!(
            result,
            KeyCheckResult::KeysMissing {
                missing: vec!["AAAA".to_string()]
            }
        );
    }

    #[test]
    fn test_add_keys() {
        let mut keys = KnownKeys::default();
        keys.pin_all("alice@example.com", &["AAAA".to_string()]);
        keys.add_keys("alice@example.com", &["BBBB".to_string()]);

        let result = keys.check(
            "alice@example.com",
            &["AAAA".to_string(), "BBBB".to_string()],
        );
        assert_eq!(result, KeyCheckResult::Trusted);
    }

    #[test]
    fn test_toml_round_trip() {
        let mut keys = KnownKeys::default();
        keys.pin_all(
            "alice@example.com",
            &["AAAA".to_string(), "BBBB".to_string()],
        );
        keys.pin_all("bob@example.com", &["CCCC".to_string()]);

        let toml_str = toml::to_string_pretty(&keys).unwrap();
        let loaded: KnownKeys = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.contacts.len(), 2);
        assert_eq!(
            loaded.contacts.get("alice@example.com").unwrap().devices.len(),
            2
        );
        assert_eq!(
            loaded.contacts.get("bob@example.com").unwrap().devices.len(),
            1
        );
    }
}
