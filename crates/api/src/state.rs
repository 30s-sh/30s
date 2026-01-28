use std::sync::Arc;

use sqlx::{Pool, Postgres};

use crate::{dns::DnsResolver, email::EmailSender, unkey};

#[derive(Clone)]
pub struct AppState {
    pub database: Pool<Postgres>,
    pub redis: redis::Client,
    pub unkey: unkey::Client,
    pub email: Arc<EmailSender>,
    pub dns: Arc<dyn DnsResolver>,
}
