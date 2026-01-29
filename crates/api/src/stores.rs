//! Ephemeral stores (Redis).
//!
//! This module contains traits and implementations for ephemeral data storage.
//! All data stored here has automatic TTL-based expiration.
//!
//! ## Stores
//!
//! - **drops** - Encrypted drop storage with TTL (max 24 hours)
//! - **inbox** - Per-user sorted sets of pending drops
//! - **verification** - Email verification codes (15 min TTL)
//! - **rate_limit** - Rate limiting counters (hourly/monthly)
//!
//! ## Redis Key Patterns
//!
//! ```text
//! drop:{uuid}                           → StoredDrop JSON (auto-expires)
//! inbox:{user_id}                       → Sorted set of drop IDs
//! verify-{hash}                         → Verification code state
//! ratelimit:code:{email}                → Code request limit
//! ratelimit:verify:{email}              → Verify attempt limit
//! ratelimit:drops:{user_id}:{YYYY-MM}   → Monthly drop count
//! ```
//!
//! ## Usage in Handlers
//!
//! Stores are accessed via `state.stores`:
//!
//! ```ignore
//! async fn handler(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
//!     state.stores.drops.store(&drop, ttl_secs).await?;
//!     state.stores.inbox.add(user_id, &drop_id, score).await?;
//! }
//! ```

mod drops;
mod inbox;
mod rate_limit;
mod verification;

pub use drops::{DropStore, RedisDropStore};
pub use inbox::{InboxStore, RedisInboxStore};
pub use rate_limit::{RateLimiter, RedisRateLimiter};
pub use verification::{RedisVerificationStore, VerificationStore};

#[cfg(test)]
pub use drops::MockDropStore;
#[cfg(test)]
pub use inbox::MockInboxStore;
#[cfg(test)]
pub use rate_limit::{MockRateLimiter, RateLimitResult};
#[cfg(test)]
pub use verification::{MockVerificationStore, VerifyState};

use std::sync::Arc;

/// Collection of all ephemeral stores.
#[derive(Clone)]
pub struct Stores {
    pub drops: Arc<dyn DropStore>,
    pub inbox: Arc<dyn InboxStore>,
    pub verification: Arc<dyn VerificationStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
}
