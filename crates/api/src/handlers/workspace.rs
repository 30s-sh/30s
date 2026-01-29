//! Workspace management endpoints for domain verification and workspace info.

use axum::{
    Json, Router, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use garde::Validate;
use shared::api::{
    AddDomainPayload, AddDomainResponse, CreateWorkspacePayload, DomainInfo, UpdatePoliciesPayload,
    VerifyDomainResponse, WorkspaceInfo, WorkspacePolicies,
};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthUser,
    models::{User, Workspace, WorkspaceAdmin, WorkspaceDomain, WorkspacePolicy},
    state::AppState,
};

/// DNS TXT record host prefix for domain verification.
const DNS_PREFIX: &str = "_30s";
/// DNS TXT record value prefix for domain verification.
const VERIFY_PREFIX: &str = "30s-verify=";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_workspace).post(create_workspace))
        .route("/domains", get(list_domains).post(add_domain))
        .route("/domains/{domain}/verify", post(verify_domain))
        .route("/policies", get(get_policies).put(update_policies))
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

/// Get the user's workspace (if they belong to one via email domain or are admin).
#[debug_handler]
async fn get_workspace(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // First check if user is an admin of any workspace
    let admin_workspace = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    if let Some(admin) = admin_workspace {
        let workspace = sqlx::query_as!(
            Workspace,
            "SELECT * FROM workspaces WHERE id = $1",
            admin.workspace_id
        )
        .fetch_one(&state.database)
        .await?;

        let is_paid = workspace.has_active_subscription();
        return Ok(Json(WorkspaceInfo {
            id: workspace.id,
            name: workspace.name,
            created_at: workspace.created_at,
            subscription_status: workspace.subscription_status,
            is_paid,
        }));
    }

    // Otherwise, find a verified domain that matches the user's email domain
    let email_domain = get_user_email_domain(&state.database, user.id).await?;

    let workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT w.*
        FROM workspaces w
        JOIN workspace_domains wd ON wd.workspace_id = w.id
        WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
        "#,
        &email_domain
    )
    .fetch_optional(&state.database)
    .await?;

    match workspace {
        Some(w) => {
            let is_paid = w.has_active_subscription();
            Ok(Json(WorkspaceInfo {
                id: w.id,
                name: w.name,
                created_at: w.created_at,
                subscription_status: w.subscription_status,
                is_paid,
            }))
        }
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "No workspace found for your email domain",
        )),
    }
}

/// Create a new workspace. The user becomes an admin.
#[debug_handler]
async fn create_workspace(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<CreateWorkspacePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Check if user is already an admin of a workspace
    let existing_admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    if existing_admin.is_some() {
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "You are already an admin of a workspace",
        ));
    }

    // Create workspace and add user as admin in a transaction
    let mut tx = state.database.begin().await?;

    let workspace = sqlx::query_as!(
        Workspace,
        "INSERT INTO workspaces (name) VALUES ($1) RETURNING *",
        payload.name
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO workspace_admins (workspace_id, user_id) VALUES ($1, $2)",
        workspace.id,
        user.id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        workspace_id = %workspace.id,
        user_id = %user.id,
        name = %workspace.name,
        "workspace created"
    );

    let is_paid = workspace.has_active_subscription();
    Ok((
        StatusCode::CREATED,
        Json(WorkspaceInfo {
            id: workspace.id,
            name: workspace.name,
            created_at: workspace.created_at,
            subscription_status: workspace.subscription_status,
            is_paid,
        }),
    ))
}

/// Add a domain for verification. User must be workspace admin.
#[debug_handler]
async fn add_domain(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<AddDomainPayload>,
) -> Result<impl IntoResponse, AppError> {
    // Validate domain format (basic check)
    let domain = payload.domain.to_lowercase();
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(AppError::Validation("Invalid domain format".to_string()));
    }

    // Verify user's email matches the domain they're trying to add
    let email_domain = get_user_email_domain(&state.database, user.id).await?;
    if email_domain != domain {
        return Err(AppError::External(
            StatusCode::FORBIDDEN,
            "Your email domain must match the domain you're adding",
        ));
    }

    // Check if user is an admin of a workspace
    let admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    let workspace_id = match admin {
        Some(a) => a.workspace_id,
        None => {
            return Err(AppError::External(
                StatusCode::FORBIDDEN,
                "You must create a workspace first: 30s workspace create <name>",
            ));
        }
    };

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
        // Domain exists but not verified
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "Domain verification already pending",
        ));
    }

    // Generate verification token (16 bytes = 32 hex chars)
    let token_bytes: [u8; 16] = rand::random();
    let token = hex::encode(token_bytes);

    // Insert the domain linked to the workspace
    sqlx::query!(
        r#"
        INSERT INTO workspace_domains (workspace_id, domain, verification_token)
        VALUES ($1, $2, $3)
        "#,
        workspace_id,
        domain,
        token
    )
    .execute(&state.database)
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
/// Requires an active subscription.
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
                "No pending verification for this domain. Add it first: 30s workspace domain add",
            ));
        }
    };

    if pending.verified_at.is_some() {
        return Err(AppError::External(
            StatusCode::CONFLICT,
            "Domain is already verified",
        ));
    }

    // Get the workspace and check subscription status
    let workspace_id = pending
        .workspace_id
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Domain not linked to a workspace")))?;

    let workspace = sqlx::query_as!(
        Workspace,
        "SELECT * FROM workspaces WHERE id = $1",
        workspace_id
    )
    .fetch_one(&state.database)
    .await?;

    // Check if workspace has active subscription
    if !workspace.has_active_subscription() {
        return Err(AppError::External(
            StatusCode::PAYMENT_REQUIRED,
            "Active subscription required to verify domains. Run: 30s billing subscribe",
        ));
    }

    // Perform DNS lookup (trailing dot for FQDN)
    let txt_host = format!("{}.", txt_record_host(&domain));
    let expected_value = txt_record_value(&pending.verification_token);

    let records = state.dns.lookup_txt(&txt_host).await.map_err(|e| {
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

    // Mark domain as verified
    sqlx::query!(
        "UPDATE workspace_domains SET verified_at = NOW() WHERE domain = $1",
        domain
    )
    .execute(&state.database)
    .await?;

    tracing::info!("Domain {} verified for workspace {}", domain, workspace_id);

    Ok(Json(VerifyDomainResponse {
        domain,
        workspace_name: workspace.name,
        workspace_created: false,
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
            ));
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

/// Get workspace policies (any workspace member can view).
#[debug_handler]
async fn get_policies(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Get workspace for this user (via admin or domain membership)
    let workspace_id = get_user_workspace_id(&state, user.id).await?;

    let policy = sqlx::query_as!(
        WorkspacePolicy,
        "SELECT * FROM workspace_policies WHERE workspace_id = $1",
        workspace_id
    )
    .fetch_optional(&state.database)
    .await?;

    let response = match policy {
        Some(p) => WorkspacePolicies {
            max_ttl_seconds: p.max_ttl_seconds,
            min_ttl_seconds: p.min_ttl_seconds,
            default_ttl_seconds: p.default_ttl_seconds,
            require_once: p.require_once,
            default_once: p.default_once,
            allow_external: p.allow_external,
        },
        None => WorkspacePolicies {
            max_ttl_seconds: None,
            min_ttl_seconds: None,
            default_ttl_seconds: None,
            require_once: None,
            default_once: None,
            allow_external: None,
        },
    };

    Ok(Json(response))
}

/// Update workspace policies (admin only).
#[debug_handler]
async fn update_policies(
    user: AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<UpdatePoliciesPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Verify user is a workspace admin
    let admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.database)
    .await?;

    let workspace_id = match admin {
        Some(a) => a.workspace_id,
        None => {
            return Err(AppError::External(
                StatusCode::FORBIDDEN,
                "Only workspace admins can update policies",
            ));
        }
    };

    // Verify workspace has active subscription
    let workspace = sqlx::query_as!(
        Workspace,
        "SELECT * FROM workspaces WHERE id = $1",
        workspace_id
    )
    .fetch_one(&state.database)
    .await?;

    if !workspace.has_active_subscription() {
        return Err(AppError::External(
            StatusCode::PAYMENT_REQUIRED,
            "Active subscription required to set policies. Run: 30s billing subscribe",
        ));
    }

    // Validate TTL consistency
    if let (Some(min), Some(max)) = (payload.min_ttl_seconds, payload.max_ttl_seconds)
        && min > max
    {
        return Err(AppError::Validation(
            "min_ttl_seconds cannot be greater than max_ttl_seconds".to_string(),
        ));
    }

    if let Some(default) = payload.default_ttl_seconds {
        if let Some(min) = payload.min_ttl_seconds
            && default < min
        {
            return Err(AppError::Validation(
                "default_ttl_seconds cannot be less than min_ttl_seconds".to_string(),
            ));
        }
        if let Some(max) = payload.max_ttl_seconds
            && default > max
        {
            return Err(AppError::Validation(
                "default_ttl_seconds cannot be greater than max_ttl_seconds".to_string(),
            ));
        }
    }

    // Validate once consistency
    if payload.require_once == Some(true) && payload.default_once == Some(false) {
        return Err(AppError::Validation(
            "default_once cannot be false when require_once is true".to_string(),
        ));
    }

    // Upsert policies
    sqlx::query!(
        r#"
        INSERT INTO workspace_policies (
            workspace_id, max_ttl_seconds, min_ttl_seconds, default_ttl_seconds,
            require_once, default_once, allow_external, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (workspace_id) DO UPDATE SET
            max_ttl_seconds = $2,
            min_ttl_seconds = $3,
            default_ttl_seconds = $4,
            require_once = $5,
            default_once = $6,
            allow_external = $7,
            updated_at = NOW()
        "#,
        workspace_id,
        payload.max_ttl_seconds,
        payload.min_ttl_seconds,
        payload.default_ttl_seconds,
        payload.require_once,
        payload.default_once,
        payload.allow_external
    )
    .execute(&state.database)
    .await?;

    tracing::info!(
        workspace_id = %workspace_id,
        user_id = %user.id,
        "workspace policies updated"
    );

    Ok(StatusCode::OK)
}

/// Get workspace ID for a user (via admin membership or domain).
async fn get_user_workspace_id(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<uuid::Uuid, AppError> {
    // First check if user is an admin
    let admin = sqlx::query_as!(
        WorkspaceAdmin,
        "SELECT * FROM workspace_admins WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.database)
    .await?;

    if let Some(a) = admin {
        return Ok(a.workspace_id);
    }

    // Otherwise, find workspace via email domain
    let email_domain = get_user_email_domain(&state.database, user_id).await?;

    let workspace = sqlx::query_as!(
        Workspace,
        r#"
        SELECT w.*
        FROM workspaces w
        JOIN workspace_domains wd ON wd.workspace_id = w.id
        WHERE wd.domain = $1 AND wd.verified_at IS NOT NULL
        "#,
        &email_domain
    )
    .fetch_optional(&state.database)
    .await?;

    match workspace {
        Some(w) => Ok(w.id),
        None => Err(AppError::External(
            StatusCode::NOT_FOUND,
            "No workspace found for your email domain",
        )),
    }
}
