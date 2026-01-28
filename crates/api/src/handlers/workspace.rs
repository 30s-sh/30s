//! Workspace management endpoints for domain verification and workspace info.

use axum::{
    Json, Router,
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use shared::api::{
    AddDomainPayload, AddDomainResponse, DomainInfo, VerifyDomainResponse, WorkspaceInfo,
};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{User, Workspace, WorkspaceAdmin, WorkspaceDomain},
    state::AppState,
};

/// DNS TXT record host prefix for domain verification.
const DNS_PREFIX: &str = "_30s";
/// DNS TXT record value prefix for domain verification.
const VERIFY_PREFIX: &str = "30s-verify=";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_workspace))
        .route("/domains", get(list_domains).post(add_domain))
        .route("/domains/{domain}/verify", post(verify_domain))
}

/// Extract the domain portion from an email address.
fn extract_email_domain(email: &str) -> Result<&str, AppError> {
    email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid email format")))
}

/// Fetch a user by ID and return their email domain.
async fn get_user_email_domain(db: &Pool<Postgres>, user_id: Uuid) -> Result<String, AppError> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(db)
        .await?;
    extract_email_domain(&user.email).map(|s| s.to_string())
}

/// Format the DNS TXT record host for a domain.
fn txt_record_host(domain: &str) -> String {
    format!("{}.{}", DNS_PREFIX, domain)
}

/// Format the DNS TXT record value for a verification token.
fn txt_record_value(token: &str) -> String {
    format!("{}{}", VERIFY_PREFIX, token)
}

/// Get the user's workspace (if they belong to one via email domain).
#[debug_handler]
async fn get_workspace(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let email_domain = get_user_email_domain(&state.database, user.id).await?;

    // Find a verified domain that matches the user's email domain
    let workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT w.id, w.name, w.created_at
        FROM workspaces w
        JOIN workspace_domains wd ON wd.workspace_id = w.id
        WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
        "#,
        &email_domain
    )
    .fetch_optional(&state.database)
    .await?;

    match workspace {
        Some(w) => Ok(Json(WorkspaceInfo {
            id: w.id,
            name: w.name,
            created_at: w.created_at,
        })),
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "No workspace found for your email domain",
        )),
    }
}

/// Add a domain for verification. User's email must match the domain.
#[debug_handler]
async fn add_domain(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<AddDomainPayload>,
) -> Result<impl IntoResponse, AppError> {
    // Validate domain format (basic check)
    let domain = payload.domain.to_lowercase();
    if domain.is_empty() || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.')
    {
        return Err(AppError::Validation("Invalid domain format".to_string()));
    }

    // Verify user's email matches the domain they're trying to verify
    let email_domain = get_user_email_domain(&state.database, user.id).await?;
    if email_domain != domain {
        return Err(AppError::External(
            StatusCode::FORBIDDEN,
            "Your email domain must match the domain you're verifying",
        ));
    }

    // Check if domain already exists
    let existing = sqlx::query_as!(
        WorkspaceDomain,
        "SELECT * FROM workspace_domains WHERE domain = $1",
        domain
    )
    .fetch_optional(&state.database)
    .await?;

    if let Some(existing) = existing {
        if existing.verified_at.is_some() {
            return Err(AppError::External(
                StatusCode::CONFLICT,
                "Domain is already verified",
            ));
        }
        // Domain exists but not verified - could return existing token or regenerate
        // For simplicity, we'll return an error asking them to verify the existing one
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "Domain verification already pending",
        ));
    }

    // Generate verification token (16 bytes = 32 hex chars)
    let token_bytes: [u8; 16] = rand::random();
    let token = hex::encode(token_bytes);

    // Insert the domain (no workspace_id yet - will be set on verification)
    sqlx::query_as!(
        WorkspaceDomain,
        r#"
        INSERT INTO workspace_domains (domain, verification_token)
        VALUES ($1, $2)
        RETURNING *
        "#,
        domain,
        token
    )
    .fetch_one(&state.database)
    .await?;

    let txt_host = txt_record_host(&domain);
    let txt_value = txt_record_value(&token);

    Ok((
        StatusCode::CREATED,
        Json(AddDomainResponse {
            domain,
            txt_host,
            txt_value,
        }),
    ))
}

/// Verify a domain via DNS TXT record lookup.
#[debug_handler]
async fn verify_domain(
    user: AuthUser,
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let domain = domain.to_lowercase();

    // Verify user's email matches the domain they're trying to verify
    let email_domain = get_user_email_domain(&state.database, user.id).await?;
    if email_domain != domain {
        return Err(AppError::External(
            StatusCode::FORBIDDEN,
            "Your email domain must match the domain you're verifying",
        ));
    }

    // Get the pending domain verification
    let pending = sqlx::query_as!(
        WorkspaceDomain,
        "SELECT * FROM workspace_domains WHERE domain = $1",
        domain
    )
    .fetch_optional(&state.database)
    .await?;

    let pending = match pending {
        Some(p) => p,
        None => {
            return Err(AppError::External(
                StatusCode::NOT_FOUND,
                "No pending verification for this domain",
            ))
        }
    };

    if pending.verified_at.is_some() {
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "Domain is already verified",
        ));
    }

    // Perform DNS lookup (trailing dot for FQDN)
    let txt_host = format!("{}.", txt_record_host(&domain));
    let expected_value = txt_record_value(&pending.verification_token);

    let records = state
        .dns
        .lookup_txt(&txt_host)
        .await
        .map_err(|e| {
            tracing::warn!("DNS lookup failed for {}: {}", txt_host, e);
            AppError::External(
                StatusCode::BAD_REQUEST,
                "DNS lookup failed - please ensure the TXT record is configured",
            )
        })?;

    let verified = records.iter().any(|r| r.contains(&expected_value));

    if !verified {
        tracing::info!(
            "Domain verification failed for {}: expected '{}', found {:?}",
            domain,
            expected_value,
            records
        );
        return Err(AppError::External(
            StatusCode::BAD_REQUEST,
            "Verification failed - TXT record not found or incorrect",
        ));
    }

    // Check if there's already a workspace for this domain (shouldn't happen, but be safe)
    let (workspace_id, workspace_name, workspace_created) = if let Some(ws_id) = pending.workspace_id
    {
        // Workspace already exists (edge case)
        let ws = sqlx::query_as!(Workspace, "SELECT * FROM workspaces WHERE id = $1", ws_id)
            .fetch_one(&state.database)
            .await?;
        (ws_id, ws.name, false)
    } else {
        // Create workspace, link domain, and add admin in a transaction
        let workspace_name = domain.clone();
        let mut tx = state.database.begin().await?;

        let ws = sqlx::query_as!(
            Workspace,
            "INSERT INTO workspaces (name) VALUES ($1) RETURNING *",
            workspace_name
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query_as!(
            WorkspaceDomain,
            "UPDATE workspace_domains SET workspace_id = $1, verified_at = NOW() WHERE domain = $2 RETURNING *",
            ws.id,
            domain
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query_as!(
            WorkspaceAdmin,
            "INSERT INTO workspace_admins (workspace_id, user_id) VALUES ($1, $2) RETURNING *",
            ws.id,
            user.id
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        (ws.id, workspace_name, true)
    };

    tracing::info!(
        "Domain {} verified for workspace {} (created: {})",
        domain,
        workspace_id,
        workspace_created
    );

    Ok(Json(VerifyDomainResponse {
        domain,
        workspace_name,
        workspace_created,
    }))
}

/// List all domains for the user's workspace (admin only).
#[debug_handler]
async fn list_domains(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Check if user is an admin of any workspace
    let admin_workspace = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    let workspace_id = match admin_workspace {
        Some(a) => a.workspace_id,
        None => {
            return Err(AppError::External(
                StatusCode::FORBIDDEN,
                "You must be a workspace admin to list domains",
            ))
        }
    };

    let domains = sqlx::query_as!(
        WorkspaceDomain,
        "SELECT * FROM workspace_domains WHERE workspace_id = $1 ORDER BY created_at DESC",
        workspace_id
    )
    .fetch_all(&state.database)
    .await?;

    let domain_infos: Vec<DomainInfo> = domains
        .into_iter()
        .map(|d| DomainInfo {
            domain: d.domain,
            verified: d.verified_at.is_some(),
            created_at: d.created_at,
        })
        .collect();

    Ok(Json(domain_infos))
}
