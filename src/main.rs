use anyhow::Result;
use clap::{Parser, Subcommand};

mod crypto;

/// A no-nonsense file encryption tool.
/// 
/// Uses AES-256-GCM so the bad guys can't read or tamper with your files,
/// and Argon2id so brute-forcing your password takes forever.
#[derive(Parser)]
#[command(
    name = "encrpt",
    version,
    about = "A no-nonsense file encryption tool using AES-256-GCM and Argon2id.",
    long_about = r#"A no-nonsense file encryption tool.

Uses AES-256-GCM for authenticated encryption and Argon2id for key derivation.

USAGE:
  # Lock a file:
  encrpt encrypt -i secret.txt -o secret.enc

  # Unlock a file:
  encrpt decrypt -i secret.enc -o secret.txt

  # See what's inside an encrypted file:
  encrpt inspect -i secret.enc"#
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file. You'll be asked for a password twice to prevent typos.
    Encrypt {
        /// The file you want to encrypt
        #[arg(short, long)]
        input: String,

        /// Where to save the encrypted file
        #[arg(short, long)]
        output: String,

        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,
    },

    /// Decrypt a file. If the password is wrong, or the file was tampered with, it will fail.
    Decrypt {
        /// The file you want to decrypt
        #[arg(short, long)]
        input: String,

        /// Where to save the decrypted file
        #[arg(short, long)]
        output: String,

        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,
    },

    /// Peek inside an encrypted file to check its settings (doesn't need a password).
    Inspect {
        /// The encrypted file to inspect
        #[arg(short, long)]
        input: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            force,
        } => {
            // Check paths first so we don't waste time typing a password if it's going to fail
            crypto::validate_paths(&input, &output, force)?;

            let password = rpassword::prompt_password("Enter password: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;

            if password != confirm {
                anyhow::bail!("Typo? The passwords didn't match.");
            }

            crypto::encrypt_file(&input, &output, &password)?;

            println!("✅ Locked and loaded: {}", output);
        }

        Commands::Decrypt {
            input,
            output,
            force,
        } => {
            crypto::validate_paths(&input, &output, force)?;

            let password = rpassword::prompt_password("Enter password: ")?;

            crypto::decrypt_file(&input, &output, &password)?;

            println!("✅ Unlocked: {}", output);
        }

        Commands::Inspect { input } => {
            let (version, m_cost, t_cost, p_cost) = crypto::inspect_file(&input)?;

            println!("📄 File: {}", input);
            println!("   Version  : {}", version);
            println!("   Memory   : {} KiB", m_cost / 1024);
            println!("   Iterations: {}", t_cost);
            println!("   Parallelism: {}", p_cost);
        }
    }

    Ok(())
}