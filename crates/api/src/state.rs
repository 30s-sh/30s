use std::sync::Arc;

use sqlx::{Pool, Postgres};
use stripe::Client as StripeClient;

use crate::{dns::DnsResolver, email::EmailSender, unkey};

#[derive(Clone)]
pub struct AppState {
    pub database: Pool<Postgres>,
    pub redis: redis::Client,
    pub unkey: unkey::Client,
    pub email: Arc<EmailSender>,
    pub dns: Arc<dyn DnsResolver>,
    pub stripe: StripeClient,
    pub stripe_webhook_secret: String,
    pub stripe_price_id: String,
}
