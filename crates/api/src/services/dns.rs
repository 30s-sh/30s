//! DNS resolver abstraction for domain verification.
//!
//! Provides a trait-based DNS resolver that can be swapped for testing.
//! Production uses hickory-resolver, tests use a mock implementation.

use anyhow::Result;
use async_trait::async_trait;
use hickory_resolver::{Resolver, config::ResolverConfig, name_server::TokioConnectionProvider};
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for DNS TXT record lookups.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Look up TXT records for the given domain.
    /// Domain should be a fully-qualified domain name (e.g., "_30s.example.com.").
    async fn lookup_txt(&self, domain: &str) -> Result<Vec<String>>;
}

/// Production DNS resolver using hickory-resolver.
pub struct HickoryDnsResolver {
    resolver: Resolver<TokioConnectionProvider>,
}

impl HickoryDnsResolver {
    /// Create a new resolver with system configuration.
    pub fn new() -> Result<Self> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn lookup_txt(&self, domain: &str) -> Result<Vec<String>> {
        let lookup = self.resolver.txt_lookup(domain).await?;
        let records: Vec<String> = lookup
            .iter()
            .map(|txt| {
                txt.iter()
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect();
        Ok(records)
    }
}

/// Mock DNS resolver for testing.
#[derive(Default)]
pub struct MockDnsResolver {
    records: Mutex<HashMap<String, Vec<String>>>,
}

impl MockDnsResolver {
    /// Create a new mock resolver with no records.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a TXT record for testing.
    #[allow(dead_code)]
    pub fn add_txt(&self, domain: &str, value: &str) {
        let mut records = self.records.lock().unwrap();
        records
            .entry(domain.to_string())
            .or_default()
            .push(value.to_string());
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn lookup_txt(&self, domain: &str) -> Result<Vec<String>> {
        let records = self.records.lock().unwrap();
        Ok(records.get(domain).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_configured_records() {
        let mock = MockDnsResolver::new();
        mock.add_txt("_30s.example.com.", "30s-verify=abc123");

        let records = mock.lookup_txt("_30s.example.com.").await.unwrap();
        assert_eq!(records, vec!["30s-verify=abc123"]);
    }

    #[tokio::test]
    async fn mock_returns_empty_for_unknown_domain() {
        let mock = MockDnsResolver::new();

        let records = mock.lookup_txt("_30s.unknown.com.").await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn mock_supports_multiple_records() {
        let mock = MockDnsResolver::new();
        mock.add_txt("_dmarc.example.com.", "v=DMARC1; p=none");
        mock.add_txt("_dmarc.example.com.", "another record");

        let records = mock.lookup_txt("_dmarc.example.com.").await.unwrap();
        assert_eq!(records.len(), 2);
    }
}
