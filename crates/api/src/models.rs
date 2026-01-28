use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::api::WrappedKeyPayload;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub unkey_key_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WorkspaceDomain {
    pub id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub domain: String,
    pub verification_token: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WorkspaceAdmin {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Drop stored in Redis with automatic expiration via TTL.
///
/// Drops are ephemeral encrypted secrets. The server only stores ciphertext and
/// per-recipient wrapped keys - it never sees the plaintext. Each drop expires
/// automatically via Redis TTL based on the sender's chosen expiration time.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredDrop {
    pub id: String,
    pub sender_email: String,
    /// Sender's device public key (needed by recipients to unwrap keys)
    pub sender_public_key: String,
    /// Encrypted secret payload (base64)
    pub ciphertext: String,
    /// Nonce for AES-256-GCM decryption (base64)
    pub aes_nonce: String,
    /// Per-recipient wrapped symmetric keys
    pub wrapped_keys: Vec<WrappedKeyPayload>,
    pub created_at: DateTime<Utc>,
    /// Delete the drop after it's read once (burn-after-reading mode).
    #[serde(default)]
    pub once: bool,
}
