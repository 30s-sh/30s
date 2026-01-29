//! Email-based passwordless authentication.
//!
//! Flow:
//! 1. User requests a code via POST /auth/code with their email
//! 2. A 6-digit code is generated, hashed (SHA256), and stored in Redis keyed by the hash
//! 3. The plaintext code is emailed to the user
//! 4. User submits email + code to POST /auth/verify
//! 5. Code is hashed and looked up in Redis; if valid and email matches, user is created/verified
//! 6. An Unkey API key is generated and returned to the user
//!
//! Security notes:
//! - Codes are hashed before storage (Redis compromise doesn't leak valid codes)
//! - Codes expire after 15 minutes
//! - Already-verified users get 200 OK (prevents email enumeration)
//! - Code is only deleted after full validation (email mismatch doesn't invalidate legitimate codes)
//! - Rate limiting should be handled by a reverse proxy (Caddy, Kong, etc.)

use axum::{
    Json, Router, debug_handler,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use garde::Validate;
use rand::Rng;
use sha2::{Digest, Sha256};
use shared::api::{
    MeResponse, RequestCodePayload, RotateVerifyPayload, RotateVerifyResponse, VerifyCodePayload,
    VerifyCodeResponse,
};

use crate::{error::AppError, middleware::auth::AuthUser, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/code", post(request_code))
        .route("/verify", post(verify_code))
        .route("/me", get(get_me).delete(delete_account))
        .route("/rotate", post(request_rotate))
        .route("/rotate/verify", post(verify_rotate))
}

#[debug_handler]
async fn get_me(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let db_user = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    Ok(Json(MeResponse { email: db_user.email }))
}

#[debug_handler]
async fn request_code(
    State(state): State<AppState>,
    Json(payload): Json<RequestCodePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Rate limit: 5 code requests per hour per email
    let result = state
        .stores
        .rate_limiter
        .check_simple(&format!("ratelimit:code:{}", payload.email), 5, 3600)
        .await?;
    if !result.is_allowed() {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Try again later.",
        ));
    }

    let code: String = {
        let mut rng = rand::rng();
        (0..6)
            .map(|_| rng.random_range(0..10).to_string())
            .collect()
    };

    // Hash the code so it can't be stolen from Redis
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // Store keyed by hash so verification is O(1) lookup. TTL of 15 minutes.
    state
        .stores
        .verification
        .store_verify_code(&hashed, &payload.email, 15 * 60)
        .await?;

    state
        .email
        .send_verification_code(&payload.email, &code)
        .await?;

    tracing::info!(email = %payload.email, "verification code requested");

    Ok(StatusCode::OK)
}

#[debug_handler]
async fn verify_code(
    State(state): State<AppState>,
    Json(payload): Json<VerifyCodePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Rate limit: 10 verify attempts per 15 minutes per email
    let result = state
        .stores
        .rate_limiter
        .check_simple(
            &format!("ratelimit:verify_code:{}", payload.email),
            10,
            15 * 60,
        )
        .await?;
    if !result.is_allowed() {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Try again later.",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(payload.code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // GET first, DEL only after full validation. This way an attacker guessing
    // a valid code with the wrong email doesn't invalidate the legitimate user's code.
    let verify_state = match state.stores.verification.get_verify_code(&hashed).await? {
        Some(s) => s,
        None => {
            tracing::warn!(email = %payload.email, "verification failed: invalid code");
            return Ok(AppError::External(StatusCode::BAD_REQUEST, "Invalid code").into_response());
        }
    };

    // Prevents using an intercepted code with a different email
    if verify_state.email != payload.email {
        tracing::warn!(email = %payload.email, "verification failed: email mismatch");
        return Ok(AppError::External(StatusCode::BAD_REQUEST, "Invalid code").into_response());
    }

    // Code validated, now safe to delete
    state.stores.verification.delete_verify_code(&hashed).await?;

    // Create user on verify (not on code request) so we don't store unverified emails
    let user = match state.repos.users.find_by_email(&payload.email).await? {
        Some(user) => user,
        None => state.repos.users.create(&payload.email).await?,
    };

    // Create API key via auth service
    let key_response = state
        .auth
        .create_key(&user.id.to_string(), &format!("30s-cli-{}", &payload.email))
        .await?;

    // Store key_id for revocation/lookup; return the actual key to the user (shown only once)
    state
        .repos
        .users
        .set_verified(&user.email, &key_response.key_id)
        .await?;

    tracing::info!(user_id = %user.id, email = %payload.email, "user verified");

    Ok(Json(VerifyCodeResponse {
        api_key: key_response.key,
    })
    .into_response())
}

/// Request a verification code for API key rotation.
/// Requires authentication with the current API key.
#[debug_handler]
async fn request_rotate(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Rate limit: 3 rotation code requests per hour per user
    let result = state
        .stores
        .rate_limiter
        .check_simple(&format!("ratelimit:rotate:{}", user.id), 3, 3600)
        .await?;
    if !result.is_allowed() {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Try again later.",
        ));
    }

    // Look up user's email
    let db_user = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let code: String = {
        let mut rng = rand::rng();
        (0..6)
            .map(|_| rng.random_range(0..10).to_string())
            .collect()
    };

    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    // Store with "rotate-" prefix to distinguish from init codes
    state
        .stores
        .verification
        .store_rotate_code(&hashed, &db_user.email, 15 * 60)
        .await?;

    state
        .email
        .send_verification_code(&db_user.email, &code)
        .await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "rotation code requested");

    Ok(StatusCode::OK)
}

/// Verify the rotation code and issue a new API key.
/// Revokes the old key and returns a new one.
#[debug_handler]
async fn verify_rotate(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<RotateVerifyPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Rate limit: 10 verify attempts per 15 minutes per user
    let result = state
        .stores
        .rate_limiter
        .check_simple(&format!("ratelimit:verify_rotate:{}", user.id), 10, 15 * 60)
        .await?;
    if !result.is_allowed() {
        return Err(AppError::External(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Try again later.",
        ));
    }

    // Look up user
    let db_user = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    let mut hasher = Sha256::new();
    hasher.update(payload.code.as_bytes());
    let hashed = hex::encode(hasher.finalize());

    let verify_state = match state.stores.verification.get_rotate_code(&hashed).await? {
        Some(s) => s,
        None => {
            tracing::warn!(user_id = %user.id, "rotation failed: invalid code");
            return Err(AppError::External(StatusCode::BAD_REQUEST, "Invalid code"));
        }
    };

    // Verify the code was requested for this user's email
    if verify_state.email != db_user.email {
        tracing::warn!(user_id = %user.id, "rotation failed: email mismatch");
        return Err(AppError::External(StatusCode::BAD_REQUEST, "Invalid code"));
    }

    // Code validated, delete it
    state
        .stores
        .verification
        .delete_rotate_code(&hashed)
        .await?;

    // Revoke old key if it exists
    if let Some(old_key_id) = &db_user.unkey_key_id
        && let Err(e) = state.auth.delete_key(old_key_id).await
    {
        tracing::warn!(user_id = %user.id, "Failed to revoke old API key: {}", e);
    }

    // Create new API key
    let key_response = state
        .auth
        .create_key(
            &db_user.id.to_string(),
            &format!("30s-cli-{}", &db_user.email),
        )
        .await?;

    // Update stored key_id
    state
        .repos
        .users
        .update_key_id(db_user.id, &key_response.key_id)
        .await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "API key rotated");

    Ok(Json(RotateVerifyResponse {
        api_key: key_response.key,
    }))
}

/// Delete user account and all associated data.
/// Removes: user record, all devices, all drops (sent and received).
#[debug_handler]
async fn delete_account(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let db_user = state
        .repos
        .users
        .find_by_id(user.id)
        .await?
        .ok_or_else(|| AppError::External(StatusCode::NOT_FOUND, "User not found"))?;

    // Revoke Unkey API key
    if let Some(key_id) = &db_user.unkey_key_id
        && let Err(e) = state.auth.delete_key(key_id).await
    {
        tracing::warn!(user_id = %user.id, "Failed to revoke Unkey key during account deletion: {}", e);
    }

    // Delete devices (cascade will handle this if FK is set, but be explicit)
    state.repos.devices.delete_all_by_user(user.id).await?;

    // Delete user (this is the source of truth)
    state.repos.users.delete(user.id).await?;

    // Clean up any drops from Redis inbox
    state.stores.inbox.delete_all(user.id).await?;

    tracing::info!(user_id = %user.id, email = %db_user.email, "account deleted");

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::User;
    use crate::repos::{MockDeviceRepo, MockUserRepo};
    use crate::services::{CreateKeyResult, MockAuthService, MockEmailSender};
    use crate::stores::{
        MockInboxStore, MockRateLimiter, MockVerificationStore, RateLimitResult, VerifyState,
    };
    use crate::test_utils::{mock_user, TestStateBuilder};
    use axum::http::StatusCode;
    use chrono::Utc;

    #[tokio::test]
    async fn get_me_returns_user_email() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .with(mockall::predicate::eq(user_id))
            .returning(move |_| Ok(Some(user_clone.clone())));

        let state = TestStateBuilder::new().with_user_repo(user_repo).build();

        let result = get_me(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_me_returns_not_found_for_missing_user() {
        let user_id = uuid::Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_id().returning(|_| Ok(None));

        let state = TestStateBuilder::new().with_user_repo(user_repo).build();

        let result = get_me(AuthUser { id: user_id }, State(state)).await;

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
    async fn delete_account_removes_user_and_devices() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .with(mockall::predicate::eq(user_id))
            .returning(move |_| Ok(Some(user_clone.clone())));
        user_repo
            .expect_delete()
            .with(mockall::predicate::eq(user_id))
            .returning(|_| Ok(()));

        let mut device_repo = MockDeviceRepo::new();
        device_repo
            .expect_delete_all_by_user()
            .with(mockall::predicate::eq(user_id))
            .returning(|_| Ok(()));

        let mut auth_service = MockAuthService::new();
        auth_service.expect_delete_key().returning(|_| Ok(()));

        let mut inbox_store = MockInboxStore::new();
        inbox_store
            .expect_delete_all()
            .with(mockall::predicate::eq(user_id))
            .returning(|_| Ok(()));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_device_repo(device_repo)
            .with_auth_service(auth_service)
            .with_inbox_store(inbox_store)
            .build();

        let result = delete_account(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_code_stores_and_sends_code() {
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store
            .expect_store_verify_code()
            .returning(|_, _, _| Ok(()));

        let mut email_sender = MockEmailSender::new();
        email_sender
            .expect_send_verification_code()
            .returning(|_, _| Ok(()));

        let state = TestStateBuilder::new()
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .with_email_sender(email_sender)
            .build();

        let payload = RequestCodePayload {
            email: "alice@example.com".to_string(),
        };

        let result = request_code(State(state), Json(payload)).await.unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_code_rate_limited() {
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Exceeded(6)));

        let state = TestStateBuilder::new()
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = RequestCodePayload {
            email: "alice@example.com".to_string(),
        };

        let result = request_code(State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn verify_code_creates_user_and_returns_api_key() {
        let user = mock_user("alice@example.com");
        let user_clone = user.clone();

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store
            .expect_get_verify_code()
            .returning(move |_| {
                Ok(Some(VerifyState {
                    email: "alice@example.com".to_string(),
                    code: "123456".to_string(),
                    created_at: Utc::now().timestamp(),
                }))
            });
        verification_store
            .expect_delete_verify_code()
            .returning(|_| Ok(()));

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_email().returning(|_| Ok(None)); // New user
        user_repo
            .expect_create()
            .returning(move |_| Ok(user_clone.clone()));
        user_repo.expect_set_verified().returning(move |_, _| {
            Ok(User {
                id: user.id,
                email: user.email.clone(),
                unkey_key_id: Some("key_new".to_string()),
                created_at: user.created_at,
                verified_at: Some(Utc::now()),
            })
        });

        let mut auth_service = MockAuthService::new();
        auth_service.expect_create_key().returning(|_, _| {
            Ok(CreateKeyResult {
                key: "30s_test_key".to_string(),
                key_id: "key_new".to_string(),
            })
        });

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .with_auth_service(auth_service)
            .build();

        let payload = VerifyCodePayload {
            email: "alice@example.com".to_string(),
            code: "123456".to_string(),
        };

        let result = verify_code(State(state), Json(payload)).await.unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_code_not_found_returns_bad_request() {
        // Test: code was never requested (not in store)
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store
            .expect_get_verify_code()
            .returning(|_| Ok(None)); // No code in store

        let state = TestStateBuilder::new()
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = VerifyCodePayload {
            email: "alice@example.com".to_string(),
            code: "123456".to_string(),
        };

        let result = verify_code(State(state), Json(payload)).await.unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_code_email_mismatch_returns_bad_request() {
        // Test: valid code used with wrong email (prevents code theft)
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store.expect_get_verify_code().returning(|_| {
            Ok(Some(VerifyState {
                email: "alice@example.com".to_string(), // Code was requested for alice
                code: "123456".to_string(),
                created_at: Utc::now().timestamp(),
            }))
        });
        // Note: delete is NOT called because email mismatch happens first

        let state = TestStateBuilder::new()
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = VerifyCodePayload {
            email: "attacker@example.com".to_string(), // Attacker tries to use alice's code
            code: "123456".to_string(),
        };

        let result = verify_code(State(state), Json(payload)).await.unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_code_rate_limited() {
        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Exceeded(11)));

        let state = TestStateBuilder::new()
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = VerifyCodePayload {
            email: "alice@example.com".to_string(),
            code: "123456".to_string(),
        };

        let result = verify_code(State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected External error"),
        }
    }

    // request_rotate tests

    #[tokio::test]
    async fn request_rotate_stores_and_sends_code() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store
            .expect_store_rotate_code()
            .returning(|_, _, _| Ok(()));

        let mut email_sender = MockEmailSender::new();
        email_sender
            .expect_send_verification_code()
            .returning(|_, _| Ok(()));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .with_email_sender(email_sender)
            .build();

        let result = request_rotate(AuthUser { id: user_id }, State(state))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_rotate_rate_limited() {
        let user_id = uuid::Uuid::new_v4();

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Exceeded(4)));

        let state = TestStateBuilder::new()
            .with_rate_limiter(rate_limiter)
            .build();

        let result = request_rotate(AuthUser { id: user_id }, State(state)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn request_rotate_returns_not_found_for_missing_user() {
        let user_id = uuid::Uuid::new_v4();

        let mut user_repo = MockUserRepo::new();
        user_repo.expect_find_by_id().returning(|_| Ok(None));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_rate_limiter(rate_limiter)
            .build();

        let result = request_rotate(AuthUser { id: user_id }, State(state)).await;

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

    // verify_rotate tests

    #[tokio::test]
    async fn verify_rotate_issues_new_key() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;
        let user_email = user.email.clone();

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));
        user_repo.expect_update_key_id().returning(|_, _| Ok(()));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        let email_clone = user_email.clone();
        verification_store
            .expect_get_rotate_code()
            .returning(move |_| {
                Ok(Some(VerifyState {
                    email: email_clone.clone(),
                    code: "123456".to_string(),
                    created_at: Utc::now().timestamp(),
                }))
            });
        verification_store
            .expect_delete_rotate_code()
            .returning(|_| Ok(()));

        let mut auth_service = MockAuthService::new();
        auth_service.expect_delete_key().returning(|_| Ok(()));
        auth_service.expect_create_key().returning(|_, _| {
            Ok(CreateKeyResult {
                key: "30s_new_key".to_string(),
                key_id: "key_rotated".to_string(),
            })
        });

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .with_auth_service(auth_service)
            .build();

        let payload = RotateVerifyPayload {
            code: "123456".to_string(),
        };

        let result = verify_rotate(AuthUser { id: user_id }, State(state), Json(payload))
            .await
            .unwrap();

        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_rotate_invalid_code_returns_bad_request() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store
            .expect_get_rotate_code()
            .returning(|_| Ok(None)); // Code not found

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = RotateVerifyPayload {
            code: "999999".to_string(),
        };

        let result = verify_rotate(AuthUser { id: user_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn verify_rotate_rate_limited() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Exceeded(11)));

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = RotateVerifyPayload {
            code: "123456".to_string(),
        };

        let result = verify_rotate(AuthUser { id: user_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected External error"),
        }
    }

    #[tokio::test]
    async fn verify_rotate_email_mismatch_returns_bad_request() {
        let user = mock_user("alice@example.com");
        let user_id = user.id;

        let mut user_repo = MockUserRepo::new();
        let user_clone = user.clone();
        user_repo
            .expect_find_by_id()
            .returning(move |_| Ok(Some(user_clone.clone())));

        let mut rate_limiter = MockRateLimiter::new();
        rate_limiter
            .expect_check_simple()
            .returning(|_, _, _| Ok(RateLimitResult::Allowed(1)));

        let mut verification_store = MockVerificationStore::new();
        verification_store.expect_get_rotate_code().returning(|_| {
            Ok(Some(VerifyState {
                email: "different@example.com".to_string(), // Different email
                code: "123456".to_string(),
                created_at: Utc::now().timestamp(),
            }))
        });

        let state = TestStateBuilder::new()
            .with_user_repo(user_repo)
            .with_verification_store(verification_store)
            .with_rate_limiter(rate_limiter)
            .build();

        let payload = RotateVerifyPayload {
            code: "123456".to_string(),
        };

        let result = verify_rotate(AuthUser { id: user_id }, State(state), Json(payload)).await;

        let Err(err) = result else {
            panic!("Expected error, got Ok");
        };
        match err {
            AppError::External(status, _) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
            }
            _ => panic!("Expected External error"),
        }
    }
}
