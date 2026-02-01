//! Webhook configuration endpoints.
//!
//! Users can configure a webhook URL to receive notifications when they receive drops.
//! Each webhook is assigned a unique secret for HMAC signature verification.
//!
//! ## Endpoints
//!
//! - PUT /webhooks - Set webhook URL (generates new secret)
//! - GET /webhooks - Get current config (404 if none)
//! - DELETE /webhooks - Clear webhook
//! - POST /webhooks/test - Send test event

use axum::{
    Json, Router, debug_handler,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, put},
};
use chrono::Utc;
use garde::Validate;
use rand::Rng;
use shared::api::{SetWebhookPayload, WebhookConfig, WebhookTestResponse};

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    services::DropReceivedEvent,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", put(set_webhook).get(get_webhook).delete(clear_webhook))
        .route("/test", post(test_webhook))
}

/// Generate a random 32-byte secret as hex.
fn generate_secret() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

/// Set or replace the webhook URL for the authenticated user.
/// Generates a new secret each time.
#[debug_handler]
async fn set_webhook(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<SetWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Verify user exists in database
    state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let secret = generate_secret();

    let webhook = state
        .repos
        .webhooks
        .upsert_for_user(user.id, &payload.url, &secret)
        .await?;

    tracing::info!(user_id = %user.id, url = %payload.url, "webhook configured");

    Ok(Json(WebhookConfig {
        url: webhook.url,
        secret: webhook.secret,
    }))
}

/// Get the current webhook configuration.
#[debug_handler]
async fn get_webhook(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let webhook = state
        .repos
        .webhooks
        .get_by_user(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "No webhook configured"))?;

    Ok(Json(WebhookConfig {
        url: webhook.url,
        secret: webhook.secret,
    }))
}

/// Clear the webhook configuration.
#[debug_handler]
async fn clear_webhook(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    state.repos.webhooks.delete_for_user(user.id).await?;

    tracing::info!(user_id = %user.id, "webhook cleared");

    Ok(StatusCode::OK)
}

/// Send a test webhook event.
#[debug_handler]
async fn test_webhook(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let webhook = state
        .repos
        .webhooks
        .get_by_user(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "No webhook configured"))?;

    // Get user's email for the test event
    let db_user = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let now = Utc::now();
    let test_event = DropReceivedEvent {
        event: "drop.received",
        drop_id: "test-drop-id".to_string(),
        sender_email: "test@example.com".to_string(),
        recipient_email: db_user.email.clone(),
        expires_at: now + chrono::Duration::seconds(30),
        timestamp: now,
    };

    // Send webhook synchronously for test so we can report result
    state
        .webhook
        .send_drop_received(&webhook.url, &webhook.secret, test_event)
        .await;

    tracing::info!(user_id = %user.id, url = %webhook.url, "test webhook sent");

    Ok(Json(WebhookTestResponse {
        message: "Test webhook sent".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::MockWebhookRepo;
    use crate::repos::MockUserRepo;
    use crate::services::MockWebhookSender;
    use crate::test_utils::TestStateBuilder;
    use crate::models::Webhook;
    use chrono::Utc;
    use uuid::Uuid;

    fn mock_webhook(user_id: Uuid) -> Webhook {
        Webhook {
            id: Uuid::new_v4(),
            user_id,
            url: "https://example.com/webhook".to_string(),
            secret: "test-secret".to_string(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn set_webhook_creates_new_webhook() {
        let user_id = Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_id().returning(move |_| {
            Ok(Some(crate::models::User {
                id: user_id,
                email: "test@example.com".to_string(),
                unkey_key_id: Some("key".to_string()),
                created_at: Utc::now(),
                verified_at: Some(Utc::now()),
            }))
        });

        let mut webhook_repo = MockWebhookRepo::new();
        webhook_repo
            .expect_upsert_for_user()
            .returning(move |uid, url, secret| {
                Ok(Webhook {
                    id: Uuid::new_v4(),
                    user_id: uid,
                    url: url.to_string(),
                    secret: secret.to_string(),
                    created_at: Utc::now(),
                })
            });

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_webhook_repo(webhook_repo)
            .build();

        let payload = SetWebhookPayload {
            url: "https://example.com/webhook".to_string(),
        };

        let result = set_webhook(AuthUser { id: user_id }, State(state), Json(payload))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn set_webhook_validates_url() {
        let user_id = Uuid::new_v4();
        let state = TestStateBuilder::new().build();

        let payload = SetWebhookPayload {
            url: "not-a-valid-url".to_string(),
        };

        let result = set_webhook(AuthUser { id: user_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected validation error");
        };
        match err {
            AppError::Validation(_) => {}
            _ => panic!("Expected Validation error"),
        }
    }

    #[tokio::test]
    async fn get_webhook_returns_config() {
        let user_id = Uuid::new_v4();
        let webhook = mock_webhook(user_id);

        let mut webhook_repo = MockWebhookRepo::new();
        let webhook_clone = webhook.clone();
        webhook_repo
            .expect_get_by_user()
            .returning(move |_| Ok(Some(webhook_clone.clone())));

        let state = TestStateBuilder::new()
            .with_webhook_repo(webhook_repo)
            .build();

        let result = get_webhook(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_webhook_returns_not_found_when_none() {
        let user_id = Uuid::new_v4();

        let mut webhook_repo = MockWebhookRepo::new();
        webhook_repo
            .expect_get_by_user()
            .returning(|_| Ok(None));

        let state = TestStateBuilder::new()
            .with_webhook_repo(webhook_repo)
            .build();

        let result = get_webhook(AuthUser { id: user_id }, State(state)).await;

        let Err(err) = result else {
            panic!("Expected error");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn clear_webhook_succeeds() {
        let user_id = Uuid::new_v4();

        let mut webhook_repo = MockWebhookRepo::new();
        webhook_repo
            .expect_delete_for_user()
            .returning(|_| Ok(true));

        let state = TestStateBuilder::new()
            .with_webhook_repo(webhook_repo)
            .build();

        let result = clear_webhook(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_webhook_sends_event() {
        let user_id = Uuid::new_v4();
        let webhook = mock_webhook(user_id);

        let mut webhook_repo = MockWebhookRepo::new();
        let webhook_clone = webhook.clone();
        webhook_repo
            .expect_get_by_user()
            .returning(move |_| Ok(Some(webhook_clone.clone())));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_id().returning(move |_| {
            Ok(Some(crate::models::User {
                id: user_id,
                email: "test@example.com".to_string(),
                unkey_key_id: Some("key".to_string()),
                created_at: Utc::now(),
                verified_at: Some(Utc::now()),
            }))
        });

        let mut webhook_sender = MockWebhookSender::new();
        webhook_sender
            .expect_send_drop_received()
            .times(1)
            .returning(|_, _, _| ());

        let state = TestStateBuilder::new()
            .with_webhook_repo(webhook_repo)
            .with_user_repo(user_repo)
            .with_webhook_sender(webhook_sender)
            .build();

        let result = test_webhook(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
