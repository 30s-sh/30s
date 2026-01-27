//! Sign out of the current device.
//!
//! Clears credentials from the system keyring and file storage.
//! Does not revoke the device server-side - use device management to clean
//! up orphaned devices.
//!
//! Signing back in with `30s init` will create a new device with a fresh keypair.

use anyhow::Result;

use crate::{credentials, ui};

pub async fn run() -> Result<()> {
    credentials::delete_all().await?;
    ui::success("Signed out");
    Ok(())
}
