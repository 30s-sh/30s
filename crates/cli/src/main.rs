mod api;
mod commands;
mod config;
mod credentials;
mod crypto;
mod known_keys;
mod ui;
mod version;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use futures::FutureExt;
use keyring::set_global_service_name;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "30s")]
#[command(about = "End-to-end encrypted secret sharing")]
#[command(version)]
#[command(after_help = "Examples:
  30s init alice@example.com          Sign in or create account
  30s send -t bob@example.com 'secret' Send with 30s expiration (default)
  30s send -t bob@example.com 'pw' 5m  Send with 5 minute expiration
  30s inbox                            List received drops
  30s open <id>                        Decrypt and view a drop")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign in or create a new account
    #[command(after_help = "Example: 30s init alice@example.com")]
    Init {
        /// Your email address
        email: String,
    },

    /// Send an encrypted secret to one or more recipients
    #[command(after_help = "Examples:
  30s send -t bob@example.com 'database password'
  30s send -t alice@example.com -t bob@example.com 'shared secret' 1h
  30s send -t bob@example.com -o 'one-time secret'
  echo 'secret' | 30s send -t bob@example.com -")]
    Send {
        /// Recipient email (use multiple times for multiple recipients)
        #[arg(short = 't', long = "to", required = true)]
        to: Vec<String>,
        /// The secret to send (use '-' to read from stdin)
        message: String,
        /// How long until the secret expires
        #[arg(default_value = "30s")]
        expires_in: String,
        /// Delete the secret after it's read once
        #[arg(short = 'o', long = "once")]
        once: bool,
    },

    /// List drops in your inbox
    #[command(after_help = "Example: 30s inbox")]
    Inbox,

    /// Decrypt and display a drop
    #[command(after_help = "Example: 30s open abc123-def456")]
    Open {
        /// Drop ID from your inbox
        id: String,
    },

    /// Delete a drop you sent
    #[command(after_help = "Example: 30s delete abc123-def456")]
    Delete {
        /// Drop ID to delete
        id: String,
    },

    /// List or manage your registered devices
    #[command(after_help = "Examples:
  30s devices                List all devices
  30s devices delete <id>    Remove a device")]
    Devices {
        #[command(subcommand)]
        action: Option<DeviceCommands>,
    },

    /// Sign out of this device
    #[command(after_help = "Example: 30s logout")]
    Logout,

    /// Permanently delete your account and all data
    #[command(after_help = "Example: 30s destroy")]
    Destroy,

    /// Show your email address
    #[command(after_help = "Example: 30s whoami")]
    Whoami,

    /// Rotate API key or device keys
    #[command(after_help = "Examples:
  30s rotate auth    Rotate your API key (requires email verification)
  30s rotate keys    Rotate your device encryption keys")]
    Rotate {
        #[command(subcommand)]
        action: RotateCommands,
    },

    /// Generate shell completions
    #[command(after_help = "Examples:
  30s completions bash > ~/.bash_completion.d/30s
  30s completions zsh > ~/.zfunc/_30s
  30s completions fish > ~/.config/fish/completions/30s.fish")]
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// Remove a device (secrets can no longer be sent to it)
    #[command(after_help = "Example: 30s devices delete abc123-def456")]
    Delete {
        /// Device ID to delete
        id: String,
    },
}

#[derive(Subcommand)]
enum RotateCommands {
    /// Rotate your API key (requires email verification)
    #[command(after_help = "Example: 30s rotate auth")]
    Auth,
    /// Rotate your device encryption keys (inbox must be empty)
    #[command(after_help = "Example: 30s rotate keys")]
    Keys,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        ui::print_error(&err);
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    set_global_service_name("30s");

    // Spawn version check in background (non-blocking)
    let update_check = tokio::spawn(version::fetch_latest());

    let config = envy::prefixed("THIRTY_SECS_").from_env::<Config>()?;

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { email } => commands::init::run(&config, &email).await,
        Commands::Send {
            to,
            message,
            expires_in,
            once,
        } => commands::send::run(&config, &to, &expires_in, &message, once).await,
        Commands::Inbox => commands::inbox::run(&config).await,
        Commands::Open { id } => commands::open::run(&config, id).await,
        Commands::Delete { id } => commands::delete::run(&config, &id).await,
        Commands::Devices { action } => match action {
            Some(DeviceCommands::Delete { id }) => commands::devices::delete(&config, &id).await,
            None => commands::devices::list(&config).await,
        },
        Commands::Logout => commands::logout::run().await,
        Commands::Destroy => commands::destroy::run(&config).await,
        Commands::Whoami => commands::whoami::run(&config).await,
        Commands::Rotate { action } => match action {
            RotateCommands::Auth => commands::rotate::auth(&config).await,
            RotateCommands::Keys => commands::rotate::keys(&config).await,
        },
        Commands::Completions { shell } => {
            generate(shell, &mut Cli::command(), "30s", &mut std::io::stdout());
            Ok(())
        }
    };

    // Check if update is available (only if the check completed)
    if let Some(Ok(Some(latest))) = update_check.now_or_never()
        && version::is_update_available(version::CURRENT_VERSION, &latest)
    {
        ui::update_hint(version::CURRENT_VERSION, &latest);
    }

    result
}
