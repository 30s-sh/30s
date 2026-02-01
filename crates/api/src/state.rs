use std::sync::Arc;

use stripe::Client as StripeClient;

use crate::{
    config::Config,
    repos::Repos,
    services::{AuthService, DnsResolver, EmailSender, WebhookSender},
    stores::Stores,
};

#[derive(Clone)]
pub struct AppState {
    /// Application configuration.
    pub config: Config,
    /// Database repositories.
    pub repos: Repos,
    /// Ephemeral stores (Redis).
    pub stores: Stores,
    /// Authentication service (Unkey).
    pub auth: Arc<dyn AuthService>,
    /// Email sender.
    pub email: Arc<dyn EmailSender>,
    /// DNS resolver.
    pub dns: Arc<dyn DnsResolver>,
    /// Stripe client.
    pub stripe: StripeClient,
    /// Webhook sender.
    pub webhook: Arc<dyn WebhookSender>,
}
