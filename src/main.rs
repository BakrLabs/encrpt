use anyhow::Result;
use clap::{Parser, Subcommand};

mod crypto;

/// A no-nonsense file encryption tool.
#[derive(Parser)]
#[command(
    name = "encrpt",
    version,
    about = "A no-nonsense file encryption tool using AES-256-GCM and Argon2id.",
    long_about = r#"A no-nonsense file encryption tool.

Uses AES-256-GCM for authenticated encryption and Argon2id for key derivation.
Supports streaming encryption for massive files and optional secure shredding.

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
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        output: String,

        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,

        /// Securely delete the original plaintext file after encryption
        #[arg(long)]
        shred: bool,
    },

    /// Decrypt a file. If the password is wrong, or the file was tampered with, it will fail.
    Decrypt {
        #[arg(short, long)]
        input: String,

        #[arg(short, long)]
        output: String,

        #[arg(short, long)]
        force: bool,
    },

    /// Peek inside an encrypted file to check its settings (doesn't need a password).
    Inspect {
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
            shred,
        } => {
            crypto::validate_paths(&input, &output, force)?;

            let password = rpassword::prompt_password("Enter password: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;

            if password != confirm {
                anyhow::bail!("Typo? The passwords didn't match.");
            }

            println!("Encrypting...");
            crypto::encrypt_file(&input, &output, &password)?;

            if shred {
                println!("Shredding original file...");
                crypto::shred_file(&input)?;
            }

            println!("✅ Locked and loaded: {}", output);
        }

        Commands::Decrypt {
            input,
            output,
            force,
        } => {
            crypto::validate_paths(&input, &output, force)?;

            let password = rpassword::prompt_password("Enter password: ")?;

            println!("Decrypting...");
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