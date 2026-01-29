//! Rate limiting for Redis.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Months, NaiveDate, Utc};

/// Rate limiter trait for checking and incrementing counters.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Check rate limit with simple TTL-based expiry.
    /// Returns Ok(()) if under limit, Err with count if over.
    async fn check_simple(&self, key: &str, limit: i64, ttl_secs: u64) -> Result<RateLimitResult>;

    /// Check monthly rate limit (expires at start of next month).
    /// Returns Ok(()) if under limit, Err with count if over.
    async fn check_monthly(
        &self,
        key_prefix: &str,
        user_id: &str,
        limit: i64,
        now: DateTime<Utc>,
    ) -> Result<RateLimitResult>;
}

/// Result of a rate limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Under the limit, includes current count.
    Allowed(i64),
    /// Over the limit, includes current count.
    Exceeded(i64),
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed(_))
    }
}

/// Redis implementation of RateLimiter.
#[derive(Clone)]
pub struct RedisRateLimiter {
    client: redis::Client,
}

impl RedisRateLimiter {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check_simple(&self, key: &str, limit: i64, ttl_secs: u64) -> Result<RateLimitResult> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let count: i64 = redis::cmd("INCR").arg(key).query_async(&mut conn).await?;

        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query_async(&mut conn)
                .await?;
        }

        if count > limit {
            Ok(RateLimitResult::Exceeded(count))
        } else {
            Ok(RateLimitResult::Allowed(count))
        }
    }

    async fn check_monthly(
        &self,
        key_prefix: &str,
        user_id: &str,
        limit: i64,
        now: DateTime<Utc>,
    ) -> Result<RateLimitResult> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("{}:{}:{}", key_prefix, user_id, now.format("%Y-%m"));

        let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;

        if count == 1 {
            // Set TTL to expire at start of next month
            let next_month_start = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .expect("day 1 is always valid")
                .checked_add_months(Months::new(1))
                .expect("month arithmetic overflow")
                .and_hms_opt(0, 0, 0)
                .expect("midnight is always valid")
                .and_utc();
            let ttl = (next_month_start - now).num_seconds();

            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(ttl)
                .query_async(&mut conn)
                .await?;
        }

        if count > limit {
            Ok(RateLimitResult::Exceeded(count))
        } else {
            Ok(RateLimitResult::Allowed(count))
        }
    }
}
