//! Shared API request/response types used by both CLI and API server.

use chrono::{DateTime, Utc};
use garde::Validate;
use serde::{Deserialize, Serialize};

/// Request to send a verification code to an email address.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RequestCodePayload {
    #[garde(email)]
    pub email: String,
}

/// Submit the verification code received via email.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyCodePayload {
    #[garde(email)]
    pub email: String,
    #[garde(length(min = 6, max = 6), pattern(r"^[0-9]+$"))]
    pub code: String,
}

/// Returned after successful verification, contains the API key for future requests.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyCodeResponse {
    pub api_key: String,
}

/// Register a device's public key for receiving encrypted secrets.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterDevicePayload {
    /// X25519 public key, base64 encoded.
    #[garde(length(min = 1))]
    pub public_key: String,
}

/// 1MB base64 ≈ 750KB plaintext. Generous limit for secrets.
const MAX_CIPHERTEXT_LEN: usize = 1_048_576;
/// Max recipients per drop.
const MAX_RECIPIENTS: usize = 50;
/// Max TTL for drops (1 day).
const MAX_TTL_SECS: i64 = 24 * 60 * 60;

/// Create an encrypted drop for one or more recipients.
#[derive(Debug, Serialize, Deserialize, Validate)]
#[garde(context(DateTime<Utc>))]
pub struct CreateDropPayload {
    /// Sender's X25519 public key (base64). Recipients need this to unwrap the symmetric key.
    #[garde(length(min = 1))]
    pub sender_public_key: String,
    /// AES-256-GCM encrypted payload (base64). Same ciphertext for all recipients.
    #[garde(length(min = 1, max = MAX_CIPHERTEXT_LEN))]
    pub ciphertext: String,
    /// AES-256-GCM nonce (base64).
    #[garde(length(min = 1))]
    pub aes_nonce: String,
    /// Per-recipient wrapped symmetric keys.
    #[garde(length(min = 1, max = MAX_RECIPIENTS), dive)]
    pub wrapped_keys: Vec<WrappedKeyPayload>,
    /// When this drop expires and is automatically deleted.
    #[garde(custom(validate_expires_at))]
    pub expires_at: DateTime<Utc>,
    /// Delete the drop after it's read once (burn-after-reading mode).
    #[garde(skip)]
    #[serde(default)]
    pub once: bool,
}

fn validate_expires_at(value: &DateTime<Utc>, now: &DateTime<Utc>) -> garde::Result {
    if value <= now {
        return Err(garde::Error::new("expires_at must be in the future"));
    }
    let max_expires = *now + chrono::Duration::seconds(MAX_TTL_SECS);
    if value > &max_expires {
        return Err(garde::Error::new(
            "expires_at cannot be more than 1 day from now",
        ));
    }
    Ok(())
}

/// A symmetric key wrapped (encrypted) for a specific recipient.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[garde(context(DateTime<Utc>))]
pub struct WrappedKeyPayload {
    /// Recipient's email address.
    #[garde(email)]
    pub recipient_email: String,
    /// crypto_box nonce (base64).
    #[garde(length(min = 1))]
    pub nonce: String,
    /// Symmetric key encrypted with recipient's public key (base64).
    #[garde(length(min = 1))]
    pub wrapped_key: String,
}

/// A recipient's public key, returned when looking up keys for sending.
#[derive(Debug, Serialize, Deserialize)]
pub struct DevicePublicKey {
    pub email: String,
    /// X25519 public key, base64 encoded.
    pub public_key: String,
}

/// Request public keys for a list of recipient emails.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct GetPublicKeysPayload {
    #[garde(length(min = 1))]
    pub emails: Vec<String>,
}

/// Returned after creating a drop.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDropResponse {
    pub id: String,
    /// Workspace policies that were applied to this drop (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_policies: Option<AppliedPolicies>,
}

/// Indicates which workspace policies were applied to a drop.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppliedPolicies {
    /// Workspace default TTL was applied (value in seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_ttl_applied: Option<i32>,
    /// Burn-after-reading was enforced by workspace policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub once_enforced: Option<bool>,
}

/// Summary of a drop in the inbox listing.
#[derive(Debug, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: String,
    pub sender_email: String,
    pub created_at: DateTime<Utc>,
}

/// Full drop data returned when fetching a specific drop.
#[derive(Debug, Serialize, Deserialize)]
pub struct Drop {
    pub id: String,
    pub sender_email: String,
    /// Sender's X25519 public key (base64). Needed to unwrap the symmetric key.
    pub sender_public_key: String,
    /// AES-256-GCM encrypted payload (base64).
    pub ciphertext: String,
    /// AES-256-GCM nonce (base64).
    pub aes_nonce: String,
    /// Per-recipient wrapped symmetric keys.
    pub wrapped_keys: Vec<WrappedKeyPayload>,
    pub created_at: DateTime<Utc>,
    /// Whether this drop was deleted after being read (burn-after-reading mode).
    #[serde(default)]
    pub once: bool,
}

/// Current user info.
#[derive(Debug, Serialize, Deserialize)]
pub struct MeResponse {
    pub email: String,
}

/// Device info returned when listing devices.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
}

/// Submit the verification code for API key rotation.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RotateVerifyPayload {
    #[garde(length(min = 6, max = 6), pattern(r"^[0-9]+$"))]
    pub code: String,
}

/// Returned after successful API key rotation.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotateVerifyResponse {
    pub api_key: String,
}

// ============================================================================
// Workspace types
// ============================================================================

/// Request to add a domain for verification.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct AddDomainPayload {
    #[garde(length(min = 1, max = 253))]
    pub domain: String,
}

/// Response after adding a domain, contains verification instructions.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddDomainResponse {
    /// The domain being verified (normalized to lowercase).
    pub domain: String,
    /// The DNS TXT record host (e.g., "_30s.acme.com").
    pub txt_host: String,
    /// The DNS TXT record value (e.g., "30s-verify=abc123...").
    pub txt_value: String,
}

/// Response after successfully verifying a domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyDomainResponse {
    /// The domain that was verified.
    pub domain: String,
    /// The workspace name.
    pub workspace_name: String,
    /// Whether a new workspace was created (true) or domain added to existing (false).
    pub workspace_created: bool,
}

/// Information about a verified domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainInfo {
    /// The domain name.
    pub domain: String,
    /// Whether the domain has been verified.
    pub verified: bool,
    /// When the domain was added.
    pub created_at: DateTime<Utc>,
}

/// Information about a workspace.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    /// Workspace ID.
    pub id: uuid::Uuid,
    /// Workspace name (usually the primary domain).
    pub name: String,
    /// When the workspace was created.
    pub created_at: DateTime<Utc>,
    /// Subscription status: none, active, past_due, canceled, unpaid.
    pub subscription_status: String,
    /// Whether the workspace has an active subscription.
    pub is_paid: bool,
}

// ============================================================================
// Billing types
// ============================================================================

/// Request to create a workspace.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateWorkspacePayload {
    #[garde(length(min = 1, max = 100))]
    pub name: String,
}

/// Response after creating a Stripe Checkout session.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCheckoutSessionResponse {
    /// URL to redirect the user to Stripe Checkout.
    pub checkout_url: String,
}

/// Response after creating a Stripe Customer Portal session.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePortalSessionResponse {
    /// URL to redirect the user to Stripe Customer Portal.
    pub portal_url: String,
}

/// Billing status for a workspace.
#[derive(Debug, Serialize, Deserialize)]
pub struct BillingStatus {
    /// Subscription status: none, active, past_due, canceled, unpaid.
    pub subscription_status: String,
    /// Whether the workspace has an active subscription.
    pub is_paid: bool,
}

// ============================================================================
// Workspace Policy types
// ============================================================================

/// Workspace policies response.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspacePolicies {
    /// Maximum allowed TTL in seconds (NULL = no limit beyond global 24h).
    pub max_ttl_seconds: Option<i32>,
    /// Minimum required TTL in seconds (NULL = no minimum).
    pub min_ttl_seconds: Option<i32>,
    /// Default TTL applied when sender uses 30s default.
    pub default_ttl_seconds: Option<i32>,
    /// Force burn-after-reading for all drops.
    pub require_once: Option<bool>,
    /// Default burn-after-reading when sender does not specify.
    pub default_once: Option<bool>,
    /// Allow sending to recipients outside workspace domains.
    pub allow_external: Option<bool>,
}

/// Request to update workspace policies.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdatePoliciesPayload {
    /// Maximum allowed TTL in seconds (NULL = no limit beyond global 24h).
    #[garde(skip)]
    pub max_ttl_seconds: Option<i32>,
    /// Minimum required TTL in seconds (NULL = no minimum).
    #[garde(skip)]
    pub min_ttl_seconds: Option<i32>,
    /// Default TTL applied when sender uses 30s default.
    #[garde(skip)]
    pub default_ttl_seconds: Option<i32>,
    /// Force burn-after-reading for all drops.
    #[garde(skip)]
    pub require_once: Option<bool>,
    /// Default burn-after-reading when sender does not specify.
    #[garde(skip)]
    pub default_once: Option<bool>,
    /// Allow sending to recipients outside workspace domains.
    #[garde(skip)]
    pub allow_external: Option<bool>,
}

// ============================================================================
// Activity Log types
// ============================================================================

/// A single activity log entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogEntry {
    /// Unique event ID.
    pub id: uuid::Uuid,
    /// Event type: drop.sent, drop.opened, drop.deleted, drop.expired, drop.failed.
    pub event_type: String,
    /// User who performed the action.
    pub actor_email: String,
    /// Drop ID (None for failed events).
    pub drop_id: Option<uuid::Uuid>,
    /// Event metadata (recipient_count, reason, etc.).
    pub metadata: serde_json::Value,
    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Response from the activity log endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogResponse {
    /// Activity log entries.
    pub entries: Vec<ActivityLogEntry>,
}

/// Query parameters for the activity log endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityLogQuery {
    /// Filter events after this Unix timestamp (seconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    /// Filter by event type (e.g., "drop.sent").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Max entries to return (default 50, 0 = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use garde::Validate;

    // Verification code validation - catches injection/malformed input
    mod verify_code {
        use super::*;

        #[test]
        fn rejects_non_numeric_code() {
            let payload = VerifyCodePayload {
                email: "test@example.com".into(),
                code: "abc123".into(),
            };

            assert!(payload.validate().is_err());
        }

        #[test]
        fn rejects_code_with_spaces() {
            let payload = VerifyCodePayload {
                email: "test@example.com".into(),
                code: "123 45".into(),
            };

            assert!(payload.validate().is_err());
        }

        #[test]
        fn rejects_short_code() {
            let payload = VerifyCodePayload {
                email: "test@example.com".into(),
                code: "12345".into(),
            };

            assert!(payload.validate().is_err());
        }

        #[test]
        fn rejects_long_code() {
            let payload = VerifyCodePayload {
                email: "test@example.com".into(),
                code: "1234567".into(),
            };

            assert!(payload.validate().is_err());
        }

        #[test]
        fn accepts_valid_code() {
            let payload = VerifyCodePayload {
                email: "test@example.com".into(),
                code: "123456".into(),
            };

            assert!(payload.validate().is_ok());
        }

        #[test]
        fn rejects_invalid_email() {
            let payload = VerifyCodePayload {
                email: "not-an-email".into(),
                code: "123456".into(),
            };

            assert!(payload.validate().is_err());
        }
    }

    // Drop expiration - time boundary conditions
    mod create_drop_expiration {
        use super::*;

        fn make_payload(expires_at: DateTime<Utc>) -> CreateDropPayload {
            CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: "encrypted".into(),
                aes_nonce: "nonce".into(),
                wrapped_keys: vec![WrappedKeyPayload {
                    recipient_email: "recipient@example.com".into(),
                    nonce: "nonce".into(),
                    wrapped_key: "wrapped".into(),
                }],
                expires_at,
                once: false,
            }
        }

        #[test]
        fn rejects_expiry_in_past() {
            let now = Utc::now();
            let payload = make_payload(now - Duration::seconds(1));

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn rejects_expiry_at_exact_now() {
            let now = Utc::now();
            let payload = make_payload(now);

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn rejects_expiry_over_24_hours() {
            let now = Utc::now();
            let payload = make_payload(now + Duration::hours(24) + Duration::seconds(1));

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn accepts_expiry_at_exactly_24_hours() {
            let now = Utc::now();
            let payload = make_payload(now + Duration::hours(24));

            assert!(payload.validate_with(&now).is_ok());
        }

        #[test]
        fn accepts_30_second_expiry() {
            let now = Utc::now();
            let payload = make_payload(now + Duration::seconds(30));

            assert!(payload.validate_with(&now).is_ok());
        }
    }

    // Drop recipient limits
    mod create_drop_recipients {
        use super::*;

        fn make_wrapped_key(email: &str) -> WrappedKeyPayload {
            WrappedKeyPayload {
                recipient_email: email.into(),
                nonce: "nonce".into(),
                wrapped_key: "key".into(),
            }
        }

        #[test]
        fn rejects_empty_recipients() {
            let now = Utc::now();
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: "encrypted".into(),
                aes_nonce: "nonce".into(),
                wrapped_keys: vec![],
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn rejects_over_50_recipients() {
            let now = Utc::now();
            let wrapped_keys: Vec<_> = (0..51)
                .map(|i| make_wrapped_key(&format!("user{}@example.com", i)))
                .collect();
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: "encrypted".into(),
                aes_nonce: "nonce".into(),
                wrapped_keys,
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn accepts_exactly_50_recipients() {
            let now = Utc::now();
            let wrapped_keys: Vec<_> = (0..50)
                .map(|i| make_wrapped_key(&format!("user{}@example.com", i)))
                .collect();
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: "encrypted".into(),
                aes_nonce: "nonce".into(),
                wrapped_keys,
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_ok());
        }

        #[test]
        fn validates_nested_recipient_email() {
            let now = Utc::now();
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: "encrypted".into(),
                aes_nonce: "nonce".into(),
                wrapped_keys: vec![WrappedKeyPayload {
                    recipient_email: "not-an-email".into(),
                    nonce: "nonce".into(),
                    wrapped_key: "key".into(),
                }],
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_err());
        }
    }

    // Ciphertext size limits - prevents memory exhaustion
    mod ciphertext_limits {
        use super::*;

        #[test]
        fn rejects_oversized_ciphertext() {
            let now = Utc::now();
            // MAX_CIPHERTEXT_LEN is 1MB, create one byte over
            let oversized = "x".repeat(1_048_577);
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: oversized,
                aes_nonce: "nonce".into(),
                wrapped_keys: vec![WrappedKeyPayload {
                    recipient_email: "test@example.com".into(),
                    nonce: "nonce".into(),
                    wrapped_key: "key".into(),
                }],
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_err());
        }

        #[test]
        fn accepts_max_ciphertext() {
            let now = Utc::now();
            let max_size = "x".repeat(1_048_576);
            let payload = CreateDropPayload {
                sender_public_key: "key".into(),
                ciphertext: max_size,
                aes_nonce: "nonce".into(),
                wrapped_keys: vec![WrappedKeyPayload {
                    recipient_email: "test@example.com".into(),
                    nonce: "nonce".into(),
                    wrapped_key: "key".into(),
                }],
                expires_at: now + Duration::hours(1),
                once: false,
            };

            assert!(payload.validate_with(&now).is_ok());
        }
    }
}
