//! Show the email address of the currently signed-in user.
//!
//! Fetches user info from the API using the stored credentials.
//! Useful for verifying which account is active when managing multiple identities.

use anyhow::Result;

use crate::{api::Api, config::Config, credentials, ui};

pub async fn run(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;

    let api = Api::new(config.api_url.clone());
    let me = ui::spin("Fetching...", api.get_me(api_key)).await?;

    println!("{}", ui::bold(&me.email));

    Ok(())
}
