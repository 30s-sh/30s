//! Webhook delivery service for sending drop notifications.
//!
//! Webhooks are fired asynchronously (fire-and-forget) when users receive drops.
//! Payloads are signed with HMAC-SHA256 for verification.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use std::time::Duration;

/// Event payload sent when a drop is received.
#[derive(Debug, Clone, Serialize)]
pub struct DropReceivedEvent {
    /// Event type identifier.
    pub event: &'static str,
    /// The drop ID.
    pub drop_id: String,
    /// Sender's email address.
    pub sender_email: String,
    /// Recipient's email address.
    pub recipient_email: String,
    /// When the drop expires.
    pub expires_at: DateTime<Utc>,
    /// When this event was generated.
    pub timestamp: DateTime<Utc>,
}

/// Trait for sending webhooks (mockable for tests).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait WebhookSender: Send + Sync {
    /// Send a drop.received webhook event.
    /// Fire-and-forget: errors are logged but not propagated.
    async fn send_drop_received(&self, url: &str, secret: &str, event: DropReceivedEvent);
}

/// HTTP-based webhook sender.
#[derive(Clone)]
pub struct HttpWebhookSender {
    client: Client,
}

impl Default for HttpWebhookSender {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpWebhookSender {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        Self { client }
    }

    /// Compute HMAC-SHA256 signature for the payload.
    fn compute_signature(secret: &str, timestamp: i64, payload: &str) -> String {
        let message = format!("{}.{}", timestamp, payload);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }
}

#[async_trait]
impl WebhookSender for HttpWebhookSender {
    async fn send_drop_received(&self, url: &str, secret: &str, event: DropReceivedEvent) {
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize webhook payload");
                return;
            }
        };

        let timestamp = Utc::now().timestamp();
        let signature = Self::compute_signature(secret, timestamp, &payload);

        let result = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-30s-Signature", &signature)
            .header("X-30s-Timestamp", timestamp.to_string())
            .body(payload)
            .send()
            .await;

        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    tracing::info!(
                        url = %url,
                        drop_id = %event.drop_id,
                        status = %status,
                        "Webhook delivered successfully"
                    );
                } else {
                    tracing::warn!(
                        url = %url,
                        drop_id = %event.drop_id,
                        status = %status,
                        "Webhook delivery failed with status"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    url = %url,
                    drop_id = %event.drop_id,
                    error = %e,
                    "Webhook delivery failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_computation() {
        let secret = "test-secret";
        let timestamp = 1706745600i64;
        let payload = r#"{"event":"drop.received","drop_id":"abc123"}"#;

        let signature = HttpWebhookSender::compute_signature(secret, timestamp, payload);

        // Verify signature format
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), 7 + 64); // "sha256=" + 64 hex chars

        // Same inputs should produce same signature
        let signature2 = HttpWebhookSender::compute_signature(secret, timestamp, payload);
        assert_eq!(signature, signature2);

        // Different secret should produce different signature
        let signature3 = HttpWebhookSender::compute_signature("other-secret", timestamp, payload);
        assert_ne!(signature, signature3);

        // Different timestamp should produce different signature
        let signature4 = HttpWebhookSender::compute_signature(secret, timestamp + 1, payload);
        assert_ne!(signature, signature4);
    }

    #[test]
    fn test_drop_received_event_serialization() {
        let event = DropReceivedEvent {
            event: "drop.received",
            drop_id: "abc123".to_string(),
            sender_email: "alice@example.com".to_string(),
            recipient_email: "bob@example.com".to_string(),
            expires_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:29:30Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""event":"drop.received""#));
        assert!(json.contains(r#""drop_id":"abc123""#));
        assert!(json.contains(r#""sender_email":"alice@example.com""#));
        assert!(json.contains(r#""recipient_email":"bob@example.com""#));
    }
}
