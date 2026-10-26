//! Phantom Key v2: Dealerless Threshold Key with Sealed Vault
//!
//! A secure system for LLM prompt processing that:
//! - Never sends real secrets to the model (uses format-preserving decoys)
//! - Never reconstructs the master key (uses dealerless threshold cryptography)
//! - Detects data reappearance (uses canaries with best-effort detection)
//! - Provides tamper-evident audit (uses signed, hash-chained ledger)
//!
//! Core Principle: The model never needs the secret to use it.

use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::Mutex;

mod crypto;
mod vault;
mod egress;
mod llm;

/// Phantom Key v2: Secure LLM prompt processing
#[derive(Parser, Debug)]
#[command(name = "phantom-key")]
#[command(author = "Your Name <your.email@example.com>")]
#[command(version = "0.2.0")]
#[command(about = "Dealerless threshold key with sealed vault for secure LLM prompt processing")]
#[command(long_about = None)]
struct Args {
    /// Configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the Phantom Key server
    Server {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Run the Attack Lab
    AttackLab,
    /// Generate a new key set
    GenerateKeys {
        /// Number of parties
        #[arg(short, long, default_value = "5")]
        parties: usize,
        /// Threshold
        #[arg(short, long, default_value = "3")]
        threshold: usize,
    },
    /// Run tests
    Test,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    match args.command {
        Commands::Server { port } => {
            run_server(port).await?;
        }
        Commands::AttackLab => {
            run_attack_lab().await?;
        }
        Commands::GenerateKeys { parties, threshold } => {
            generate_keys(parties, threshold).await?;
        }
        Commands::Test => {
            run_tests().await?;
        }
    }
    
    Ok(())
}

async fn run_server(port: u16) -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("phantom_key=info")
        .init();
    
    tracing::info!("Starting Phantom Key v2 server on port {}", port);
    
    // Load configuration
    let config = load_config(&args.config).await?;
    
    // Initialize Phantom Key system
    let phantom_key = initialize_phantom_key(&config).await?;
    
    // Start TUI in a separate task
    let phantom_key_tui = phantom_key.clone();
    tokio::spawn(async move {
        let mut tui = egress::tui::App::new(
            phantom_key_tui.ledger.clone(),
            phantom_key_tui.vault_storage.clone(),
            phantom_key_tui.dkg.clone(),
            phantom_key_tui.canary_registry.clone(),
        );
        tui.run().await.unwrap();
    });
    
    // Start HTTP server
    let app = llm::server::create_router(phantom_key);
    
    tracing::info!("Server listening on http://localhost:{}", port);
    warp::serve(app).run(([0, 0, 0, 0], port)).await;
    
    Ok(())
}

async fn run_attack_lab() -> anyhow::Result<()> {
    tracing::info!("Running Attack Lab...");
    
    // Initialize Phantom Key system
    let config = load_config("config.yaml").await?;
    let phantom_key = initialize_phantom_key(&config).await?;
    
    // Create Attack Lab
    let attack_lab = llm::attack_lab::AttackLab::new(phantom_key.clone());
    
    // Run all demos
    let results = attack_lab.run_all_demos().await;
    
    // Print results
    println!("\n=== Attack Lab Results ===");
    for (i, result) in results.iter().enumerate() {
        let demo_name = match i {
            0 => "Memory Safety",
            1 => "Log Inspection",
            2 => "Wire Inspection",
            3 => "DLEQ Validation",
            4 => "Ledger Tampering",
            5 => "Canary Detection",
            _ => "Unknown",
        };
        
        let status = if *result { "✓ PASS" } else { "✗ FAIL" };
        println!("Demo {}: {} - {}", i + 1, demo_name, status);
    }
    
    // Check if all passed
    if results.iter().all(|&r| r) {
        println!("\n✓ All Attack Lab demos passed!");
    } else {
        println!("\n✗ Some Attack Lab demos failed!");
        std::process::exit(1);
    }
    
    Ok(())
}

async fn generate_keys(parties: usize, threshold: usize) -> anyhow::Result<()> {
    tracing::info!("Generating new key set with {} parties, threshold {}", parties, threshold);
    
    // Initialize DKG
    let dkg = crypto::dkg::DKG::new(parties, threshold);
    
    // Generate contributions from all parties
    let contributions: Vec<crypto::dkg::PartyContribution> = (0..parties)
        .map(|i| dkg.generate_contribution(i))
        .collect();
    
    // Verify all contributions
    for contribution in &contributions {
        if !dkg.verify_contribution(contribution) {
            anyhow::bail!("Invalid contribution detected!");
        }
    }
    
    // Combine to get final shares
    let shares = dkg.combine_contributions(&contributions);
    
    // Get public key
    let public_key = dkg.get_public_key(&contributions);
    
    // Print results
    println!("✓ DKG completed successfully");
    println!("  Parties: {}", parties);
    println!("  Threshold: {}", threshold);
    println!("  Public Key: {}", hex::encode(public_key.to_bytes()));
    println!("\nShares:");
    for (i, share) in shares.iter().enumerate() {
        println!("  Party {}: {}", i + 1, hex::encode(share.to_bytes()));
    }
    
    // Save to files
    save_keys(&contributions, &shares, &public_key)?;
    
    Ok(())
}

async fn run_tests() -> anyhow::Result<()> {
    tracing::info!("Running tests...");
    
    // Run all tests
    std::process::Command::new("cargo")
        .args(&["test", "--all"])
        .status()?;
    
    Ok(())
}

async fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;
    Ok(config)
}

async fn initialize_phantom_key(config: &Config) -> anyhow::Result<llm::phantom_key::PhantomKey> {
    // Initialize storage
    let storage_backend: Arc<dyn vault::storage::VaultStorage> = match config.vault.storage.as_str() {
        "memory" => Arc::new(vault::storage::MemoryStorage::new()),
        "sqlite" => Arc::new(vault::storage::SqliteStorage::new(&config.vault.path)?),
        _ => anyhow::bail!("Unknown storage backend: {}", config.vault.storage),
    };
    
    // Initialize Phantom Key
    let phantom_key = llm::phantom_key::PhantomKey::new(
        config.parties,
        config.threshold,
        storage_backend,
    );
    
    Ok(phantom_key)
}

fn save_keys(
    contributions: &[crypto::dkg::PartyContribution],
    shares: &[crypto::group::GroupScalar],
    public_key: &crypto::group::GroupElement,
) -> anyhow::Result<()> {
    // Create keys directory
    std::fs::create_dir_all("keys")?;
    
    // Save each party's share
    for (i, share) in shares.iter().enumerate() {
        let path = format!("keys/party_{}.key", i + 1);
        let content = hex::encode(share.to_bytes());
        std::fs::write(path, content)?;
    }
    
    // Save public key
    let path = "keys/public.key";
    let content = hex::encode(public_key.to_bytes());
    std::fs::write(path, content)?;
    
    // Save contributions for verification
    let path = "keys/contributions.json";
    let content = serde_json::to_string_pretty(contributions)?;
    std::fs::write(path, content)?;
    
    Ok(())
}

/// Configuration
#[derive(Debug, Clone, serde::Deserialize)]
struct Config {
    /// Number of parties
    parties: usize,
    /// Threshold
    threshold: usize,
    /// Vault configuration
    vault: VaultConfig,
    /// Ledger configuration
    ledger: LedgerConfig,
    /// Provider configuration
    providers: ProviderConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct VaultConfig {
    /// Storage backend: "memory" or "sqlite"
    storage: String,
    /// Path for SQLite storage
    path: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct LedgerConfig {
    /// Storage backend: "memory" or "sqlite"
    storage: String,
    /// Path for SQLite storage
    path: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ProviderConfig {
    /// Bedrock configuration
    bedrock: Option<BedrockConfig>,
    /// OpenAI configuration
    openai: Option<OpenAIConfig>,
    /// Gemini configuration
    gemini: Option<GeminiConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BedrockConfig {
    endpoint: String,
    api_key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OpenAIConfig {
    api_key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GeminiConfig {
    api_key: String,
}
