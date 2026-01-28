//! Stripe billing endpoints for workspace subscriptions.
//!
//! ## Endpoints
//!
//! - POST /billing/checkout - Create Stripe Checkout session for subscription
//! - POST /billing/portal - Create Stripe Customer Portal session
//! - POST /billing/webhook - Handle Stripe webhook events
//! - GET /billing/status - Get current billing status

use axum::{
    Json, Router,
    body::Bytes,
    debug_handler,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use shared::api::{BillingStatus, CreateCheckoutSessionResponse, CreatePortalSessionResponse};
use stripe::{
    CheckoutSession, CheckoutSessionMode, CreateBillingPortalSession, CreateCheckoutSession,
    CreateCheckoutSessionLineItems, CustomerId,
};

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{Workspace, WorkspaceAdmin},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/checkout", post(create_checkout))
        .route("/portal", post(create_portal))
        .route("/webhook", post(handle_webhook))
        .route("/status", get(get_status))
}

/// Maximum age of webhook events (5 minutes) to prevent replay attacks.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

/// Verify Stripe webhook signature using HMAC-SHA256.
/// Signature header format: t=<timestamp>,v1=<sig1>,v1=<sig2>,...
fn verify_stripe_signature(
    payload: &str,
    signature_header: &str,
    secret: &str,
) -> Result<(), &'static str> {
    // Parse signature header
    let mut timestamp = None;
    let mut signatures = Vec::new();

    for part in signature_header.split(',') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next().ok_or("Invalid signature header format")?;
        let value = kv.next().ok_or("Invalid signature header format")?;

        match key {
            "t" => timestamp = Some(value),
            "v1" => signatures.push(value),
            _ => {} // Ignore unknown keys
        }
    }

    let timestamp_str = timestamp.ok_or("Missing timestamp in signature")?;
    if signatures.is_empty() {
        return Err("Missing signature in header");
    }

    // Check timestamp to prevent replay attacks
    let timestamp_secs: i64 = timestamp_str.parse().map_err(|_| "Invalid timestamp")?;
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp_secs).abs() > WEBHOOK_TOLERANCE_SECS {
        return Err("Timestamp outside tolerance window");
    }

    // Compute expected signature: HMAC-SHA256(secret, "{timestamp}.{payload}")
    let signed_payload = format!("{}.{}", timestamp_str, payload);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid webhook secret")?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Check if any provided signature matches
    if signatures.iter().any(|sig| sig == &expected) {
        Ok(())
    } else {
        Err("Signature mismatch")
    }
}

/// Get the workspace the user is an admin of.
async fn get_admin_workspace(state: &AppState, user_id: uuid::Uuid) -> Result<Workspace, AppError> {
    let admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.database)
    .await?;

    let admin = admin.ok_or_else(|| {
        AppError::External(
            StatusCode::FORBIDDEN,
            "You must be a workspace admin to manage billing",
        )
    })?;

    let workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT id, name, created_at, stripe_customer_id, stripe_subscription_id, subscription_status
        FROM workspaces WHERE id = $1
        "#,
        admin.workspace_id
    )
    .fetch_one(&state.database)
    .await?;

    Ok(workspace)
}

/// Create a Stripe Checkout session for workspace subscription.
/// Requires the user to be a workspace admin.
#[debug_handler]
async fn create_checkout(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let workspace = get_admin_workspace(&state, user.id).await?;

    // Check if already subscribed
    if workspace.has_active_subscription() {
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "Workspace already has an active subscription",
        ));
    }

    // Get or create Stripe customer
    let customer_id = match workspace.stripe_customer_id {
        Some(ref id) => id
            .parse::<CustomerId>()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid customer ID: {}", e)))?,
        None => {
            // Create a new Stripe customer
            let customer = stripe::Customer::create(
                &state.stripe,
                stripe::CreateCustomer {
                    name: Some(&workspace.name),
                    metadata: Some(
                        [("workspace_id".to_string(), workspace.id.to_string())]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await?;

            // Save customer ID to database
            sqlx::query!(
                "UPDATE workspaces SET stripe_customer_id = $1 WHERE id = $2",
                customer.id.as_str(),
                workspace.id
            )
            .execute(&state.database)
            .await?;

            customer.id
        }
    };

    // Create Checkout session
    let checkout_session = CheckoutSession::create(
        &state.stripe,
        CreateCheckoutSession {
            customer: Some(customer_id.clone()),
            mode: Some(CheckoutSessionMode::Subscription),
            line_items: Some(vec![CreateCheckoutSessionLineItems {
                price: Some(state.stripe_price_id.clone()),
                quantity: Some(1),
                ..Default::default()
            }]),
            success_url: None,
            cancel_url: None,
            metadata: Some(
                [("workspace_id".to_string(), workspace.id.to_string())]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        },
    )
    .await?;

    let checkout_url = checkout_session
        .url
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Checkout session missing URL")))?;

    tracing::info!(
        workspace_id = %workspace.id,
        customer_id = %customer_id,
        "checkout session created"
    );

    Ok(Json(CreateCheckoutSessionResponse { checkout_url }))
}

/// Create a Stripe Customer Portal session for managing subscription.
/// Requires the user to be a workspace admin with an existing customer.
#[debug_handler]
async fn create_portal(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let workspace = get_admin_workspace(&state, user.id).await?;

    let customer_id = workspace.stripe_customer_id.ok_or_else(|| {
        AppError::External(
            StatusCode::BAD_REQUEST,
            "No billing account exists for this workspace",
        )
    })?;

    let customer: CustomerId = customer_id
        .parse()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid customer ID: {}", e)))?;

    let portal_session = stripe::BillingPortalSession::create(
        &state.stripe,
        CreateBillingPortalSession {
            customer,
            return_url: Some("https://30s.sh/billing"),
            configuration: None,
            expand: &[],
            flow_data: None,
            locale: None,
            on_behalf_of: None,
        },
    )
    .await?;

    tracing::info!(
        workspace_id = %workspace.id,
        "portal session created"
    );

    Ok(Json(CreatePortalSessionResponse {
        portal_url: portal_session.url,
    }))
}

/// Handle Stripe webhook events for subscription lifecycle.
/// We parse events manually to be resilient to Stripe API version changes.
#[debug_handler]
async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let signature_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::External(StatusCode::BAD_REQUEST, "Missing stripe-signature header")
        })?;

    let payload = std::str::from_utf8(&body)
        .map_err(|_| AppError::External(StatusCode::BAD_REQUEST, "Invalid payload encoding"))?;

    // Manually verify Stripe webhook signature (HMAC-SHA256)
    verify_stripe_signature(payload, signature_header, &state.stripe_webhook_secret).map_err(
        |e| {
            tracing::warn!("Webhook signature verification failed: {}", e);
            AppError::External(StatusCode::BAD_REQUEST, "Invalid webhook signature")
        },
    )?;

    // Parse just the fields we need
    let event: WebhookEvent = serde_json::from_str(payload).map_err(|e| {
        tracing::warn!("Failed to parse webhook event: {}", e);
        AppError::External(StatusCode::BAD_REQUEST, "Invalid event payload")
    })?;

    tracing::info!(event_type = %event.event_type, event_id = %event.id, "webhook received");

    match event.event_type.as_str() {
        "checkout.session.completed" => {
            if let Some(session) = event.data.object.as_checkout_session() {
                handle_checkout_completed(&state, session).await?;
            }
        }
        "customer.subscription.created" | "customer.subscription.updated" => {
            if let Some(sub) = event.data.object.as_subscription() {
                handle_subscription_updated(&state, sub).await?;
            }
        }
        "customer.subscription.deleted" => {
            if let Some(sub) = event.data.object.as_subscription() {
                handle_subscription_deleted(&state, sub).await?;
            }
        }
        _ => {
            tracing::debug!(event_type = %event.event_type, "ignoring unhandled event type");
        }
    }

    Ok(StatusCode::OK)
}

/// Minimal webhook event structure for lenient parsing.
#[derive(Debug, serde::Deserialize)]
struct WebhookEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: WebhookEventData,
}

#[derive(Debug, serde::Deserialize)]
struct WebhookEventData {
    object: WebhookObject,
}

/// Webhook object - we only extract fields we need.
/// Order matters for untagged enums - Subscription must come first because
/// CheckoutSessionData has all optional fields and would match anything.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum WebhookObject {
    Subscription(SubscriptionData),
    CheckoutSession(CheckoutSessionData),
    #[allow(dead_code)]
    Other(serde_json::Value),
}

impl WebhookObject {
    fn as_checkout_session(&self) -> Option<&CheckoutSessionData> {
        match self {
            WebhookObject::CheckoutSession(s) if s.object == "checkout.session" => Some(s),
            _ => None,
        }
    }

    fn as_subscription(&self) -> Option<&SubscriptionData> {
        match self {
            WebhookObject::Subscription(s) if s.object == "subscription" => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct CheckoutSessionData {
    object: String,
    subscription: Option<String>,
    metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, serde::Deserialize)]
struct SubscriptionData {
    object: String,
    id: String,
    customer: String,
    status: String,
}

/// Handle checkout.session.completed event.
async fn handle_checkout_completed(
    state: &AppState,
    session: &CheckoutSessionData,
) -> Result<(), AppError> {
    let workspace_id_str = session
        .metadata
        .as_ref()
        .and_then(|m| m.get("workspace_id"))
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "Checkout session missing workspace_id metadata"
            ))
        })?;

    let workspace_id: uuid::Uuid = workspace_id_str.parse().map_err(|e| {
        AppError::Internal(anyhow::anyhow!("Invalid workspace_id in metadata: {}", e))
    })?;

    let Some(ref sub_id) = session.subscription else {
        tracing::warn!(workspace_id = %workspace_id, "checkout completed without subscription");
        return Ok(());
    };

    sqlx::query!(
        r#"
        UPDATE workspaces
        SET stripe_subscription_id = $1, subscription_status = 'active'
        WHERE id = $2
        "#,
        sub_id,
        workspace_id
    )
    .execute(&state.database)
    .await?;

    tracing::info!(
        workspace_id = %workspace_id,
        subscription_id = %sub_id,
        "subscription activated via checkout"
    );

    Ok(())
}

/// Handle subscription created/updated events.
async fn handle_subscription_updated(
    state: &AppState,
    subscription: &SubscriptionData,
) -> Result<(), AppError> {
    let status = match subscription.status.as_str() {
        "active" => "active",
        "past_due" => "past_due",
        "canceled" => "canceled",
        "unpaid" => "unpaid",
        "trialing" => "active", // Treat trial as active
        _ => "none",
    };

    let result = sqlx::query!(
        r#"
        UPDATE workspaces
        SET stripe_subscription_id = $1, subscription_status = $2
        WHERE stripe_customer_id = $3
        "#,
        subscription.id,
        status,
        subscription.customer
    )
    .execute(&state.database)
    .await?;

    if result.rows_affected() > 0 {
        tracing::info!(
            customer_id = %subscription.customer,
            subscription_id = %subscription.id,
            status = %status,
            "subscription status updated"
        );
    } else {
        tracing::warn!(
            customer_id = %subscription.customer,
            "subscription update for unknown customer"
        );
    }

    Ok(())
}

/// Handle subscription deleted event.
async fn handle_subscription_deleted(
    state: &AppState,
    subscription: &SubscriptionData,
) -> Result<(), AppError> {
    let result = sqlx::query!(
        r#"
        UPDATE workspaces
        SET stripe_subscription_id = NULL, subscription_status = 'none'
        WHERE stripe_customer_id = $1
        "#,
        subscription.customer
    )
    .execute(&state.database)
    .await?;

    if result.rows_affected() > 0 {
        tracing::info!(
            customer_id = %subscription.customer,
            subscription_id = %subscription.id,
            "subscription deleted"
        );
    } else {
        tracing::warn!(
            customer_id = %subscription.customer,
            "subscription deletion for unknown customer"
        );
    }

    Ok(())
}

/// Get the billing status for the user's workspace.
#[debug_handler]
async fn get_status(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let workspace = get_admin_workspace(&state, user.id).await?;

    Ok(Json(BillingStatus {
        subscription_status: workspace.subscription_status.clone(),
        is_paid: workspace.has_active_subscription(),
    }))
}
