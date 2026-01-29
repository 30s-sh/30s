mod api;
mod commands;
mod config;
mod contacts;
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
        /// Recipient email, alias, or @group (use multiple times for multiple recipients)
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
  30s devices                       List all devices
  30s devices delete abc123-def456  Remove a device")]
    Devices {
        #[command(subcommand)]
        action: Option<DeviceCommands>,
    },

    /// Manage contact aliases for quick recipient lookup
    #[command(after_help = "Examples:
  30s alias                         List all aliases
  30s alias bob                     Show what 'bob' maps to
  30s alias bob bob@company.com     Add or update an alias
  30s alias delete bob              Remove an alias")]
    Alias {
        #[command(subcommand)]
        action: Option<AliasCommands>,

        /// Alias name (when setting)
        name: Option<String>,

        /// Email address (when setting)
        email: Option<String>,
    },

    /// Manage contact groups for sending to multiple recipients
    #[command(after_help = "Examples:
  30s groups                                   List all groups
  30s groups team                              Show group members
  30s groups team alice@co.com bob@co.com      Create/update a group
  30s groups delete team                       Remove a group
  30s send -t @team 'secret'                   Send to all group members")]
    Groups {
        #[command(subcommand)]
        action: Option<GroupsCommands>,

        /// Group name (when setting)
        name: Option<String>,

        /// Email addresses (when setting)
        #[arg(trailing_var_arg = true)]
        emails: Vec<String>,
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

    /// Manage your workspace and domain verification
    #[command(after_help = "Examples:
  30s workspace                           Show workspace status
  30s workspace create 'Acme Corp'        Create a new workspace
  30s workspace domain add acme.com       Start domain verification
  30s workspace domain verify acme.com    Complete verification
  30s workspace domains                   List all domains")]
    Workspace {
        #[command(subcommand)]
        action: Option<WorkspaceCommands>,
    },

    /// Manage billing and subscription
    #[command(after_help = "Examples:
  30s billing                             Show billing status
  30s billing subscribe                   Subscribe to paid plan
  30s billing manage                      Open Stripe portal")]
    Billing {
        #[command(subcommand)]
        action: Option<BillingCommands>,
    },

    /// View workspace activity log (paid workspaces only)
    #[command(after_help = "Examples:
  30s activity                            Last 7 days, up to 50 entries
  30s activity --since 24h                Last 24 hours
  30s activity --since 30d                Last 30 days
  30s activity --type drop.sent           Filter by event type
  30s activity --limit 100                Fetch up to 100 entries
  30s activity --all                      Fetch all entries")]
    Activity {
        /// Time range: 24h, 7d, 30d, or ISO datetime
        #[arg(long)]
        since: Option<String>,
        /// Filter by event type: drop.sent, drop.opened, drop.deleted
        #[arg(long = "type")]
        event_type: Option<String>,
        /// Max entries to return (default 50)
        #[arg(long)]
        limit: Option<u32>,
        /// Fetch all entries
        #[arg(long)]
        all: bool,
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
enum AliasCommands {
    /// Remove an alias
    #[command(after_help = "Example: 30s alias delete bob")]
    Delete {
        /// Alias name to delete
        name: String,
    },
}

#[derive(Subcommand)]
enum GroupsCommands {
    /// Remove a group
    #[command(after_help = "Example: 30s groups delete team")]
    Delete {
        /// Group name to delete
        name: String,
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

#[derive(Subcommand)]
enum WorkspaceCommands {
    /// Create a new workspace
    #[command(after_help = "Example: 30s workspace create 'Acme Corp'")]
    Create {
        /// Name for the workspace
        name: String,
    },
    /// Add a domain for verification
    #[command(after_help = "Example: 30s workspace domain add acme.com")]
    Domain {
        #[command(subcommand)]
        action: DomainCommands,
    },
    /// List all domains for your workspace
    #[command(after_help = "Example: 30s workspace domains")]
    Domains,
    /// View workspace policies
    #[command(after_help = "Example: 30s workspace policies")]
    Policies,
    /// Set or clear a workspace policy (admin only)
    #[command(after_help = "Examples:
  30s workspace policy set max-ttl 1h
  30s workspace policy set require-once true
  30s workspace policy clear max-ttl")]
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum BillingCommands {
    /// Subscribe to a paid workspace plan
    #[command(after_help = "Example: 30s billing subscribe")]
    Subscribe,
    /// Open Stripe Customer Portal to manage subscription
    #[command(after_help = "Example: 30s billing manage")]
    Manage,
}

#[derive(Subcommand)]
enum DomainCommands {
    /// Add a domain to verify
    #[command(after_help = "Example: 30s workspace domain add acme.com")]
    Add {
        /// Domain to verify (must match your email domain)
        domain: String,
    },
    /// Verify a domain via DNS TXT record
    #[command(after_help = "Example: 30s workspace domain verify acme.com")]
    Verify {
        /// Domain to verify
        domain: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Set a policy value
    #[command(after_help = "Examples:
  30s workspace policy set max-ttl 1h
  30s workspace policy set min-ttl 5m
  30s workspace policy set default-ttl 10m
  30s workspace policy set require-once true
  30s workspace policy set default-once true
  30s workspace policy set allow-external false")]
    Set {
        /// Policy key: max-ttl, min-ttl, default-ttl, require-once, default-once, allow-external
        key: String,
        /// Policy value (duration for TTL, true/false for booleans)
        value: String,
    },
    /// Clear a policy restriction
    #[command(after_help = "Example: 30s workspace policy clear max-ttl")]
    Clear {
        /// Policy key to clear
        key: String,
    },
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
        } => {
            let contacts = contacts::load();
            let expanded = contacts::expand_recipients(&to, &contacts)?;
            commands::send::run(&config, &expanded, &expires_in, &message, once).await
        }
        Commands::Inbox => commands::inbox::run(&config).await,
        Commands::Open { id } => commands::open::run(&config, id).await,
        Commands::Delete { id } => commands::delete::run(&config, &id).await,
        Commands::Devices { action } => match action {
            Some(DeviceCommands::Delete { id }) => commands::devices::delete(&config, &id).await,
            None => commands::devices::list(&config).await,
        },
        Commands::Alias {
            action,
            name,
            email,
        } => match action {
            Some(AliasCommands::Delete { name }) => commands::alias::delete(&name).await,
            None => match (name, email) {
                (Some(n), Some(e)) => commands::alias::set(&n, &e).await,
                (Some(n), None) => commands::alias::show(&n).await,
                (None, None) => commands::alias::list().await,
                (None, Some(_)) => unreachable!(),
            },
        },
        Commands::Groups {
            action,
            name,
            emails,
        } => match action {
            Some(GroupsCommands::Delete { name }) => commands::groups::delete(&name).await,
            None => match (name, emails.is_empty()) {
                (Some(n), false) => commands::groups::set(&n, &emails).await,
                (Some(n), true) => commands::groups::show(&n).await,
                (None, true) => commands::groups::list().await,
                (None, false) => unreachable!(),
            },
        },
        Commands::Logout => commands::logout::run().await,
        Commands::Destroy => commands::destroy::run(&config).await,
        Commands::Whoami => commands::whoami::run(&config).await,
        Commands::Rotate { action } => match action {
            RotateCommands::Auth => commands::rotate::auth(&config).await,
            RotateCommands::Keys => commands::rotate::keys(&config).await,
        },
        Commands::Workspace { action } => match action {
            Some(WorkspaceCommands::Create { name }) => {
                commands::workspace::create(&config, &name).await
            }
            Some(WorkspaceCommands::Domain { action }) => match action {
                DomainCommands::Add { domain } => {
                    commands::workspace::add_domain(&config, &domain).await
                }
                DomainCommands::Verify { domain } => {
                    commands::workspace::verify_domain(&config, &domain).await
                }
            },
            Some(WorkspaceCommands::Domains) => commands::workspace::list_domains(&config).await,
            Some(WorkspaceCommands::Policies) => commands::workspace::policies(&config).await,
            Some(WorkspaceCommands::Policy { action }) => match action {
                PolicyCommands::Set { key, value } => {
                    commands::workspace::set_policy(&config, &key, &value).await
                }
                PolicyCommands::Clear { key } => {
                    commands::workspace::clear_policy(&config, &key).await
                }
            },
            None => commands::workspace::status(&config).await,
        },
        Commands::Billing { action } => match action {
            Some(BillingCommands::Subscribe) => commands::billing::subscribe(&config).await,
            Some(BillingCommands::Manage) => commands::billing::manage(&config).await,
            None => commands::billing::status(&config).await,
        },
        Commands::Activity {
            since,
            event_type,
            limit,
            all,
        } => commands::activity::run(&config, since, event_type, limit, all).await,
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
