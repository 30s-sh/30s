use std::sync::Arc;

use sqlx::{Pool, Postgres};

use crate::{email::EmailSender, unkey};

#[derive(Clone)]
pub struct AppState {
    pub database: Pool<Postgres>,
    pub redis: redis::Client,
    pub unkey: unkey::Client,
    pub email: Arc<EmailSender>,
}
