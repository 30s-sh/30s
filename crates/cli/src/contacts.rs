//! Contact aliases and groups storage.
//!
//! Provides shorthand names for frequently-used email addresses. Aliases are
//! stored locally in `~/.config/30s/contacts.toml` and expanded client-side
//! before API calls.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Contacts storage containing aliases and groups.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    /// Alias name → email address mapping.
    #[serde(default)]
    pub aliases: HashMap<String, String>,
    /// Group name → list of email addresses.
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
}

/// Get the path to the contacts.toml file.
fn path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("30s")
        .join("contacts.toml")
}

/// Load contacts from disk, returning empty contacts if file doesn't exist.
pub fn load() -> Contacts {
    let path = path();

    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Contacts::default()
    }
}

/// Save contacts to disk.
pub fn save(contacts: &Contacts) -> Result<()> {
    let path = path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let toml = toml::to_string_pretty(contacts)?;
    std::fs::write(&path, toml)?;

    Ok(())
}

/// Check if a string looks like an email address.
fn is_email(s: &str) -> bool {
    // Simple check: contains @ and has something before and after
    let parts: Vec<&str> = s.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

/// Expand a list of recipients, resolving aliases to email addresses.
///
/// - Bare name (`bob`) → look up in aliases, error if not found
/// - Group name (`@team`) → look up in groups, error if not found
/// - Email (`bob@co.com`) → pass through unchanged
///
/// Returns a deduplicated list of email addresses.
pub fn expand_recipients(raw: &[String], contacts: &Contacts) -> Result<Vec<String>> {
    let mut emails = Vec::new();
    let mut seen = HashSet::new();

    let mut add_email = |email: String| {
        if seen.insert(email.clone()) {
            emails.push(email);
        }
    };

    for recipient in raw {
        if let Some(group_name) = recipient.strip_prefix('@') {
            // Group expansion
            match contacts.groups.get(group_name) {
                Some(members) => {
                    for email in members {
                        add_email(email.clone());
                    }
                }
                None => {
                    return Err(anyhow!(
                        "Unknown group '@{}'. Use `30s groups` to manage groups.",
                        group_name
                    ));
                }
            }
        } else if is_email(recipient) {
            // Direct email address - pass through
            add_email(recipient.clone());
        } else {
            // Alias lookup
            match contacts.aliases.get(recipient) {
                Some(email) => {
                    add_email(email.clone());
                }
                None => {
                    return Err(anyhow!(
                        "Unknown recipient '{}'. Did you mean an email address?",
                        recipient
                    ));
                }
            }
        }
    }

    Ok(emails)
}

/// Validate an alias or group name.
fn validate_name(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("{} name cannot be empty", kind));
    }

    if name.contains('@') {
        return Err(anyhow!("{} name cannot contain '@'", kind));
    }

    if name.chars().any(|c| c.is_whitespace()) {
        return Err(anyhow!("{} name cannot contain whitespace", kind));
    }

    Ok(())
}

/// Validate an alias name.
pub fn validate_alias_name(name: &str) -> Result<()> {
    validate_name(name, "Alias")
}

/// Validate a group name.
pub fn validate_group_name(name: &str) -> Result<()> {
    validate_name(name, "Group")
}

/// Validate an email address format.
pub fn validate_email(email: &str) -> Result<()> {
    if !is_email(email) {
        return Err(anyhow!("Invalid email format: {}", email));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_email() {
        assert!(is_email("bob@example.com"));
        assert!(is_email("alice.jones@company.co.uk"));
        assert!(!is_email("bob"));
        assert!(!is_email("@example.com"));
        assert!(!is_email("bob@"));
        assert!(!is_email("bob@com"));
    }

    #[test]
    fn test_expand_direct_email() {
        let contacts = Contacts::default();
        let result = expand_recipients(&["bob@example.com".to_string()], &contacts).unwrap();
        assert_eq!(result, vec!["bob@example.com"]);
    }

    #[test]
    fn test_expand_alias() {
        let mut contacts = Contacts::default();
        contacts
            .aliases
            .insert("bob".to_string(), "bob.smith@company.com".to_string());

        let result = expand_recipients(&["bob".to_string()], &contacts).unwrap();
        assert_eq!(result, vec!["bob.smith@company.com"]);
    }

    #[test]
    fn test_expand_mixed() {
        let mut contacts = Contacts::default();
        contacts
            .aliases
            .insert("bob".to_string(), "bob.smith@company.com".to_string());

        let result = expand_recipients(
            &["bob".to_string(), "alice@example.com".to_string()],
            &contacts,
        )
        .unwrap();
        assert_eq!(result, vec!["bob.smith@company.com", "alice@example.com"]);
    }

    #[test]
    fn test_expand_deduplicates() {
        let mut contacts = Contacts::default();
        contacts
            .aliases
            .insert("bob".to_string(), "bob@example.com".to_string());

        let result = expand_recipients(
            &["bob".to_string(), "bob@example.com".to_string()],
            &contacts,
        )
        .unwrap();
        assert_eq!(result, vec!["bob@example.com"]);
    }

    #[test]
    fn test_expand_unknown_alias_error() {
        let contacts = Contacts::default();
        let result = expand_recipients(&["unknown".to_string()], &contacts);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown recipient")
        );
    }

    #[test]
    fn test_expand_group() {
        let mut contacts = Contacts::default();
        contacts.groups.insert(
            "team".to_string(),
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string(),
            ],
        );

        let result = expand_recipients(&["@team".to_string()], &contacts).unwrap();
        assert_eq!(result, vec!["alice@example.com", "bob@example.com"]);
    }

    #[test]
    fn test_expand_unknown_group_error() {
        let contacts = Contacts::default();
        let result = expand_recipients(&["@unknown".to_string()], &contacts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown group"));
    }

    #[test]
    fn test_validate_alias_name() {
        assert!(validate_alias_name("bob").is_ok());
        assert!(validate_alias_name("alice123").is_ok());
        assert!(validate_alias_name("my-alias").is_ok());

        assert!(validate_alias_name("").is_err());
        assert!(validate_alias_name("@bob").is_err());
        assert!(validate_alias_name("bob@company").is_err());
        assert!(validate_alias_name("my alias").is_err());
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("bob@example.com").is_ok());
        assert!(validate_email("alice.jones@company.co.uk").is_ok());

        assert!(validate_email("bob").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("bob@").is_err());
    }

    #[test]
    fn test_validate_group_name() {
        assert!(validate_group_name("team").is_ok());
        assert!(validate_group_name("backend-team").is_ok());
        assert!(validate_group_name("team123").is_ok());

        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("team@work").is_err());
        assert!(validate_group_name("my team").is_err());
    }

    #[test]
    fn test_toml_round_trip() {
        let mut contacts = Contacts::default();
        contacts
            .aliases
            .insert("bob".to_string(), "bob@example.com".to_string());
        contacts
            .aliases
            .insert("alice".to_string(), "alice@example.com".to_string());
        contacts.groups.insert(
            "team".to_string(),
            vec![
                "bob@example.com".to_string(),
                "alice@example.com".to_string(),
            ],
        );

        let toml_str = toml::to_string_pretty(&contacts).unwrap();
        let loaded: Contacts = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.aliases.len(), 2);
        assert_eq!(
            loaded.aliases.get("bob"),
            Some(&"bob@example.com".to_string())
        );
        assert_eq!(loaded.groups.len(), 1);
        assert_eq!(loaded.groups.get("team").unwrap().len(), 2);
    }
}
