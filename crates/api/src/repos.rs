//! Database repositories (PostgreSQL).
//!
//! This module contains traits and implementations for database access.
//! Each repository is abstracted behind a trait to enable mocking in tests.
//!
//! ## Repositories
//!
//! - **users** - User CRUD operations
//! - **devices** - Device management (public keys for encryption)
//! - **workspaces** - Workspace, domain verification, and policies
//! - **activity** - Audit logging for workspace activity
//!
//! ## Usage in Handlers
//!
//! Repositories are accessed via `state.repos`:
//!
//! ```ignore
//! async fn handler(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
//!     let user = state.repos.users.find_by_id(user_id).await?;
//!     let devices = state.repos.devices.list_by_user(user_id).await?;
//! }
//! ```

mod activity;
mod devices;
mod status;
mod users;
mod workspaces;

pub use activity::{events, is_internal_send, ActivityQuery, ActivityRepo, PgActivityRepo};
pub use devices::{DeviceRepo, PgDeviceRepo};
pub use status::{PgStatusRepo, StatusRepo};
pub use users::{PgUserRepo, UserRepo};
pub use workspaces::{PgWorkspaceRepo, WorkspaceRepo};

#[cfg(test)]
pub use activity::MockActivityRepo;
#[cfg(test)]
pub use devices::MockDeviceRepo;
#[cfg(test)]
pub use status::MockStatusRepo;
#[cfg(test)]
pub use users::MockUserRepo;
#[cfg(test)]
pub use workspaces::MockWorkspaceRepo;

use std::sync::Arc;

/// Collection of all database repositories.
#[derive(Clone)]
pub struct Repos {
    pub users: Arc<dyn UserRepo>,
    pub devices: Arc<dyn DeviceRepo>,
    pub workspaces: Arc<dyn WorkspaceRepo>,
    pub activity: Arc<dyn ActivityRepo>,
    pub status: Arc<dyn StatusRepo>,
}
