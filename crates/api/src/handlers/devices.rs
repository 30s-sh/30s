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

use crate::{error::AppError, middleware::auth::AuthUser, state::AppState};

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

    let device = state
        .repos
        .devices
        .create(user.id, &payload.public_key)
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
        if let Some(user) = state.repos.users.find_verified_by_email(&email).await? {
            // Get ALL devices so the recipient can decrypt on any device
            let devices = state.repos.devices.list_by_user(user.id).await?;

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
    let devices = state.repos.devices.list_by_user(user.id).await?;

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
    let device = state
        .repos
        .devices
        .find_by_id_and_user(id, user.id)
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

    let updated = state
        .repos
        .devices
        .update_public_key(id, user.id, &payload.public_key)
        .await?;

    if !updated {
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
    let deleted = state.repos.devices.delete(id, user.id).await?;

    if deleted {
        tracing::info!(user_id = %user.id, device_id = %id, "device deleted");
    }

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::MockDeviceRepo;
    use crate::test_utils::{mock_device, TestStateBuilder};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn list_devices_returns_user_devices() {
        let user_id = Uuid::new_v4();
        let device1 = mock_device(user_id);
        let device2 = mock_device(user_id);
        let devices = vec![device1.clone(), device2.clone()];

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_list_by_user()
            .with(mockall::predicate::eq(user_id))
            .returning(move |_| Ok(devices.clone()));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let result = list_devices(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn register_device_creates_new_device() {
        let user_id = Uuid::new_v4();
        let device = mock_device(user_id);

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_create()
            .with(
                mockall::predicate::eq(user_id),
                mockall::predicate::eq("new-public-key"),
            )
            .returning(move |_, _| Ok(device.clone()));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let payload = RegisterDevicePayload {
            public_key: "new-public-key".to_string(),
        };

        let result = register_device(
            AuthUser { id: user_id },
            State(state),
            Json(payload),
        )
        .await
        .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn delete_device_returns_ok_when_deleted() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_delete()
            .with(
                mockall::predicate::eq(device_id),
                mockall::predicate::eq(user_id),
            )
            .returning(|_, _| Ok(true));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let result = delete_device(AuthUser { id: user_id }, State(state), Path(device_id))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_device_returns_ok_when_not_found() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_delete()
            .returning(|_, _| Ok(false)); // Device not found

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let result = delete_device(AuthUser { id: user_id }, State(state), Path(device_id))
            .await
            .unwrap();

        // Should still return OK (idempotent)
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_device_returns_device_info() {
        let user_id = Uuid::new_v4();
        let device = mock_device(user_id);
        let device_id = device.id;

        let mut device_repo = MockDeviceRepo::new();
        let device_clone = device.clone();
        device_repo
            .expect_find_by_id_and_user()
            .with(
                mockall::predicate::eq(device_id),
                mockall::predicate::eq(user_id),
            )
            .returning(move |_, _| Ok(Some(device_clone.clone())));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let result = get_device(AuthUser { id: user_id }, State(state), Path(device_id))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_device_returns_not_found() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_find_by_id_and_user()
            .returning(|_, _| Ok(None));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let result = get_device(AuthUser { id: user_id }, State(state), Path(device_id)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn update_device_updates_public_key() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_update_public_key()
            .with(
                mockall::predicate::eq(device_id),
                mockall::predicate::eq(user_id),
                mockall::predicate::eq("updated-key"),
            )
            .returning(|_, _, _| Ok(true));

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let payload = RegisterDevicePayload {
            public_key: "updated-key".to_string(),
        };

        let result = update_device(
            AuthUser { id: user_id },
            State(state),
            Path(device_id),
            Json(payload),
        )
        .await
        .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn update_device_returns_not_found() {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_update_public_key()
            .returning(|_, _, _| Ok(false)); // Device not found

        let state = TestStateBuilder::new()
            .with_device_repo(device_repo)
            .build();

        let payload = RegisterDevicePayload {
            public_key: "updated-key".to_string(),
        };

        let result = update_device(
            AuthUser { id: user_id },
            State(state),
            Path(device_id),
            Json(payload),
        )
        .await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            _ => panic!("Expected External error"),
        }
    }
}
