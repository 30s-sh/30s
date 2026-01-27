//! Delete a drop before it expires.
//!
//! Only the sender can delete their own drops. Useful for:
//! - Sent the wrong secret
//! - Need to revoke access immediately
//! - Cleaning up after recipient confirms they got it
//!
//! The command succeeds even if the drop already expired (idempotent).

use anyhow::Result;

use crate::{api::Api, config::Config, credentials, ui};

pub async fn run(config: &Config, id: &str) -> Result<()> {
    let api_key = credentials::get_api_key().await?;

    let api = Api::new(config.api_url.clone());
    ui::spin("Deleting...", api.delete_drop(api_key, id)).await?;

    ui::success("Deleted");

    Ok(())
}
