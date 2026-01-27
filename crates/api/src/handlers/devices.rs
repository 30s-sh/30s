//! Device management for end-to-end encryption.
//!
//! Each device has a unique keypair. The public key is stored server-side so others
//! can encrypt secrets for that device. The private key never leaves the device.
//!
//! Users may have multiple devices (laptop, desktop, etc.). When sending a secret,
//! we encrypt to ALL devices for each recipient, so they can decrypt on any device.
//!
//! Endpoints:
//! - POST /devices/register - Register a new device's public key
//! - POST /devices/public-keys - Get public keys for a list of emails (for sending)
//! - GET /devices - List the authenticated user's devices
//! - DELETE /devices/{id} - Delete a device (only own devices)

use axum::{
    Json, Router, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use garde::Validate;
use shared::api::{DeviceInfo, DevicePublicKey, GetPublicKeysPayload, RegisterDevicePayload};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{Device, User},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_device))
        .route("/public-keys", post(get_public_keys))
        .route("/", get(list_devices))
        .route(
            "/{id}",
            get(get_device).put(update_device).delete(delete_device),
        )
}

#[debug_handler]
async fn register_device(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<RegisterDevicePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let device = sqlx::query_as!(
        Device,
        "INSERT INTO devices (user_id, public_key) VALUES ($1, $2) RETURNING *",
        user.id,
        payload.public_key,
    )
    .fetch_one(&state.database)
    .await?;

    tracing::info!(user_id = %user.id, device_id = %device.id, "device registered");

    Ok(StatusCode::CREATED)
}

/// Fetches all device public keys for each email address.
/// Used by senders to encrypt secrets for recipients. Returns one key per device,
/// so recipients can decrypt on any of their registered devices.
#[debug_handler]
async fn get_public_keys(
    _user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<GetPublicKeysPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let mut result = Vec::new();

    for email in payload.emails {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1 AND verified_at IS NOT NULL",
            email
        )
        .fetch_optional(&state.database)
        .await?;

        if let Some(user) = user {
            // Get ALL devices so the recipient can decrypt on any device
            let devices =
                sqlx::query_as!(Device, "SELECT * FROM devices WHERE user_id = $1", user.id)
                    .fetch_all(&state.database)
                    .await?;

            for device in devices {
                result.push(DevicePublicKey {
                    email: user.email.clone(),
                    public_key: device.public_key,
                });
            }
        }
    }

    Ok(Json(result))
}

/// Lists all devices for the authenticated user.
#[debug_handler]
async fn list_devices(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let devices = sqlx::query_as!(
        Device,
        "SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC",
        user.id
    )
    .fetch_all(&state.database)
    .await?;

    let result: Vec<DeviceInfo> = devices
        .into_iter()
        .map(|d| DeviceInfo {
            id: d.id.to_string(),
            created_at: d.created_at,
        })
        .collect();

    Ok(Json(result))
}

/// Gets a single device by ID. Only returns devices owned by the authenticated user.
#[debug_handler]
async fn get_device(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let device = sqlx::query_as!(
        Device,
        "SELECT * FROM devices WHERE id = $1 AND user_id = $2",
        id,
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    match device {
        Some(d) => Ok(Json(DeviceInfo {
            id: d.id.to_string(),
            created_at: d.created_at,
        })),
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "Device not found",
        )),
    }
}

/// Updates a device's public key. Only the owner can update their own devices.
#[debug_handler]
async fn update_device(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<RegisterDevicePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let result = sqlx::query!(
        "UPDATE devices SET public_key = $1 WHERE id = $2 AND user_id = $3",
        payload.public_key,
        id,
        user.id
    )
    .execute(&state.database)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::External(
            StatusCode::NOT_FOUND,
            "Device not found",
        ));
    }

    tracing::info!(user_id = %user.id, device_id = %id, "device public key updated");

    Ok(StatusCode::OK)
}

/// Deletes a device. Only the owner can delete their own devices.
/// Returns 200 OK even if device doesn't exist (idempotent).
#[debug_handler]
async fn delete_device(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    // Delete only if owned by the authenticated user
    let result = sqlx::query!(
        "DELETE FROM devices WHERE id = $1 AND user_id = $2",
        id,
        user.id
    )
    .execute(&state.database)
    .await?;

    if result.rows_affected() > 0 {
        tracing::info!(user_id = %user.id, device_id = %id, "device deleted");
    }

    Ok(StatusCode::OK)
}
