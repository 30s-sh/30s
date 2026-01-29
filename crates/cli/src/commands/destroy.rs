//! Permanently delete user account and all associated data.

use anyhow::Result;
use dialoguer::{Confirm, theme::ColorfulTheme};

use crate::{api::Api, config::Config, credentials, ui};

pub async fn run(config: &Config) -> Result<()> {
    let api = Api::new(config.api_url.to_string());
    let api_key = credentials::get_api_key().await?;

    // Get user email for confirmation message
    let me = ui::spin("Fetching account info...", api.get_me(api_key.clone())).await?;

    println!();
    println!("This will permanently delete your account and all associated data:");
    println!("  - Your user profile");
    println!("  - All registered devices");
    println!("  - All drops you've sent or received");
    println!();

    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Delete account {}?", me.email))
        .default(false)
        .interact()?;

    if !confirmed {
        println!("Aborted.");
        return Ok(());
    }

    ui::spin("Deleting account...", api.delete_account(api_key)).await?;

    // Clear local credentials
    credentials::delete_all().await?;

    ui::success("Account deleted");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn delete_account_succeeds() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/auth/me"))
            .and(header("Authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.delete_account("test-key".to_string()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delete_account_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/auth/me"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.delete_account("bad-key".to_string()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_account_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/auth/me"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "User not found"})),
            )
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.delete_account("test-key".to_string()).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("User not found"));
    }
}
