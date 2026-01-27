use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    /// SMTP URL for development email (e.g., smtp://localhost:1025)
    #[serde(default)]
    pub smtp_url: Option<String>,
    /// Resend API key for production email
    #[serde(default)]
    pub resend_api_key: Option<String>,
    pub unkey_root_key: String,
    pub unkey_api_id: String,
    /// Set to "production" for JSON logging, anything else for human-readable.
    #[serde(default)]
    pub env: String,
    /// Sentry DSN for error tracking (Better Stack compatible)
    #[serde(default)]
    pub sentry_dsn: Option<String>,
}

impl Config {
    pub fn is_production(&self) -> bool {
        self.env == "production"
    }
}
