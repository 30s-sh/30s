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
#[derive(Debug, Serialize, Deserialize, Validate)]
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
            };

            assert!(payload.validate_with(&now).is_ok());
        }
    }
}
