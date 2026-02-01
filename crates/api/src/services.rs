//! External service abstractions.
//!
//! This module contains traits and implementations for external services
//! that the API depends on. Each service is abstracted behind a trait to
//! enable mocking in tests.
//!
//! ## Services
//!
//! - **auth** - API key management via Unkey (verify, create, revoke keys)
//! - **email** - Transactional email via Resend (prod) or SMTP (dev)
//! - **dns** - DNS TXT record lookups for domain verification
//! - **unkey** - Low-level Unkey HTTP client (used by auth service)
//!
//! ## Usage in Handlers
//!
//! Services are accessed via `AppState`:
//!
//! ```ignore
//! async fn handler(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
//!     // Auth service for API key operations
//!     let key = state.auth.create_key(&user_id, "my-key").await?;
//!
//!     // Email service for sending verification codes
//!     state.email.send_verification_code(&email, &code).await?;
//!
//!     // DNS service for domain verification
//!     let records = state.dns.lookup_txt("_30s.example.com.").await?;
//! }
//! ```

mod auth;
mod dns;
mod email;
pub mod unkey;
mod webhook;

pub use auth::{AuthService, UnkeyAuthService};
pub use dns::{DnsResolver, HickoryDnsResolver};
pub use webhook::{DropReceivedEvent, HttpWebhookSender, WebhookSender};

#[cfg(test)]
pub use dns::MockDnsResolver;
pub use email::{EmailSender, EmailSenderImpl};

#[cfg(test)]
pub use auth::{CreateKeyResult, MockAuthService};

#[cfg(test)]
pub use email::MockEmailSender;

#[cfg(test)]
pub use webhook::MockWebhookSender;
