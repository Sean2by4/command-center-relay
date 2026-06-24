mod audit;
mod auth;
mod broker;
mod db;
mod device;
mod protocol;
mod server;

use auth::AuthManager;
use broker::Broker;
use clap::{Parser, Subcommand};
use db::Database;
use server::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use totp_rs::Secret;

#[derive(Parser)]
#[command(name = "command-center-relay", version, about = "WebSocket relay for Command Center")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the relay server
    Serve {
        #[arg(long, default_value = "9876")]
        port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "relay.db")]
        db: PathBuf,
    },
    /// Manage user accounts
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Add a new user account
    Add {
        username: String,
        #[arg(long)]
        password: Option<String>,
        /// Database path
        #[arg(long, default_value = "relay.db")]
        db: PathBuf,
    },
    /// Remove a user account
    Remove {
        username: String,
        #[arg(long, default_value = "relay.db")]
        db: PathBuf,
    },
    /// List all user accounts
    List {
        #[arg(long, default_value = "relay.db")]
        db: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { port, host, db } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .json()
                .init();

            let database = Database::open(&db)?;
            let auth = AuthManager::new(database)?;
            let broker = Broker::new();
            let state = Arc::new(AppState::new(broker, auth));

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

            // Handle Ctrl+C
            let shutdown_tx_clone = shutdown_tx.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                let _ = shutdown_tx_clone.send(true);
            });

            let static_dir = PathBuf::from("./static");
            server::run(&host, port, state, static_dir, shutdown_rx).await?;
        }

        Commands::User { action } => match action {
            UserAction::Add {
                username,
                password,
                db,
            } => {
                let database = Database::open(&db)?;

                let password = match password {
                    Some(p) => p,
                    None => {
                        eprintln!("Error: --password flag is required (interactive prompts not supported)");
                        std::process::exit(1);
                    }
                };

                // Hash: sha256 of plaintext, then bcrypt
                use sha2::{Digest, Sha256};
                let sha256_hex = format!("{:x}", Sha256::digest(password.as_bytes()));
                let bcrypt_hash = AuthManager::hash_password(&sha256_hex)?;

                // Generate TOTP
                let (totp, encrypted_secret, nonce) =
                    AuthManager::generate_totp(&username, &bcrypt_hash)?;

                database.create_account(
                    &username,
                    &bcrypt_hash,
                    Some(&encrypted_secret),
                    Some(&nonce),
                )?;

                println!("Account created: {username}");
                println!();
                println!("TOTP Secret (base32): {}", Secret::Raw(totp.secret.clone()).to_encoded().to_string());
                println!("TOTP URI: {}", totp.get_url());
                println!();

                // Try to generate QR code to terminal
                match totp.get_qr_base64() {
                    Ok(qr_b64) => {
                        println!("QR code (base64 PNG): {qr_b64}");
                        println!();
                        println!("Scan the QR code with your authenticator app, or manually enter the secret above.");
                    }
                    Err(e) => {
                        println!("Could not generate QR code: {e}");
                        println!("Manually enter the TOTP secret above into your authenticator app.");
                    }
                }

                audit::log_audit(
                    &database,
                    audit::AuditEvent::AccountCreated,
                    Some(&username),
                    None,
                    None,
                    None,
                );
            }

            UserAction::Remove { username, db } => {
                let database = Database::open(&db)?;
                database.remove_account(&username)?;
                println!("Account removed: {username}");
                audit::log_audit(
                    &database,
                    audit::AuditEvent::AccountRemoved,
                    Some(&username),
                    None,
                    None,
                    None,
                );
            }

            UserAction::List { db } => {
                let database = Database::open(&db)?;
                let accounts = database.list_accounts()?;
                if accounts.is_empty() {
                    println!("No accounts.");
                } else {
                    println!("{:<20} {:<10} {:<24}", "USERNAME", "TOTP", "CREATED");
                    println!("{}", "-".repeat(54));
                    for acct in accounts {
                        let totp_status = if acct.totp_secret_encrypted.is_some() {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        println!("{:<20} {:<10} {:<24}", acct.username, totp_status, acct.created_at);
                    }
                }
            }
        },
    }

    Ok(())
}
