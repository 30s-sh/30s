//! List encrypted drops waiting in your inbox.
//!
//! Shows all non-expired drops sent to you, displaying:
//! - Drop ID (used with `open` command)
//! - Sender's email
//! - When it was created
//!
//! The secrets are still encrypted at this point - use `open <id>` to decrypt.

use anyhow::Result;
use chrono_humanize::HumanTime;
use tabled::{Table, Tabled, settings::Style};

use crate::{api::Api, config::Config, credentials, ui};

#[derive(Tabled)]
struct InboxRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "From")]
    from: String,
    #[tabled(rename = "Received")]
    received: String,
}

pub async fn run(config: &Config) -> Result<()> {
    let api_key = credentials::get_api_key().await?;
    let api = Api::new(config.api_url.to_string());

    let inbox = ui::spin("Fetching inbox...", api.get_inbox(api_key)).await?;

    if inbox.is_empty() {
        println!("No drops in your inbox");
        return Ok(());
    }

    let rows: Vec<InboxRow> = inbox
        .into_iter()
        .map(|item| InboxRow {
            id: item.id,
            from: item.sender_email,
            received: HumanTime::from(item.created_at).to_string(),
        })
        .collect();

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{table}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use chrono::Utc;
    use shared::api::InboxItem;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn get_inbox_returns_drops() {
        let mock_server = MockServer::start().await;

        let items = vec![
            InboxItem {
                id: "drop-1".to_string(),
                sender_email: "alice@example.com".to_string(),
                created_at: Utc::now(),
            },
            InboxItem {
                id: "drop-2".to_string(),
                sender_email: "bob@example.com".to_string(),
                created_at: Utc::now(),
            },
        ];

        Mock::given(method("GET"))
            .and(path("/drops/inbox"))
            .and(header("Authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&items))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.get_inbox("test-key".to_string()).await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "drop-1");
        assert_eq!(result[0].sender_email, "alice@example.com");
        assert_eq!(result[1].id, "drop-2");
    }

    #[tokio::test]
    async fn get_inbox_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/drops/inbox"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<InboxItem>::new()))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.get_inbox("test-key".to_string()).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn get_inbox_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/drops/inbox"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let api = Api::new(mock_server.uri());
        let result = api.get_inbox("bad-key".to_string()).await;

        assert!(result.is_err());
    }
}
