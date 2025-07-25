use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ecies_encryption_lib::{
    PrivKey, PubKey, decrypt, decrypt_padded, encrypt, encrypt_padded, generate_keypair,
    utils::{from_hex, to_hex},
};

fn example() -> Result<()> {
    let (sk, pk) = generate_keypair();
    let sk_hex = to_hex(&sk.to_bytes());
    let pk_hex = to_hex(&pk.to_bytes());

    println!("Private key: {} (len: {})", sk_hex, sk_hex.len() / 2);
    println!("Public key:  {} (len: {})", pk_hex, pk_hex.len() / 2);

    let message = "hello from Rust";
    let ciphertext_bytes = encrypt(message.as_bytes(), &pk);
    println!(
        "Ciphertext hex: {} (len: {})",
        to_hex(&ciphertext_bytes),
        ciphertext_bytes.len()
    );
    println!(
        "Diff to plaintext: {}",
        ciphertext_bytes.len() - message.len()
    );

    let recovered = decrypt(&ciphertext_bytes, &sk)?;
    println!("Decrypted: {}", String::from_utf8(recovered)?);
    Ok(())
}

/// ECIES CLI: Encrypt, decrypt, and generate keys using secp256k1
#[derive(Parser)]
#[command(name = "ecies")]
#[command(about = "ECIES encryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new secp256k1 keypair
    GenerateKeypair,

    /// Encrypt a plaintext message with a public key
    Encrypt {
        /// Public key (hex)
        #[arg(short, long)]
        pubkey: String,

        /// Message to encrypt (or file path if --file is passed)
        #[arg(short, long)]
        message: String,
    },

    /// Decrypt a ciphertext with a private key
    Decrypt {
        /// Private key (hex)
        #[arg(short, long)]
        privkey: String,

        /// Ciphertext in hex (or file path if --file is passed)
        #[arg(short, long)]
        ciphertext: String,
    },
    /// Encrypt a plaintext message with a public key and padding
    EncryptPadded {
        /// Public key (hex)
        #[arg(short, long)]
        pubkey: String,

        /// Message to encrypt (or file path if --file is passed)
        #[arg(short, long)]
        message: String,

        #[arg(short, long)]
        ///
        padded_length: usize,
    },

    /// Decrypt a padded ciphertext with a private key
    DecryptPadded {
        /// Private key (hex)
        #[arg(short, long)]
        privkey: String,

        /// Ciphertext in hex (or file path if --file is passed)
        #[arg(short, long)]
        ciphertext: String,
    },
    Example,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeypair => {
            let (sk, pk) = generate_keypair();
            println!("Private key: {}", to_hex(&sk.to_bytes()));
            println!("Public key:  {}", to_hex(&pk.to_bytes()));
        }
        Commands::Encrypt { pubkey, message } => {
            let pubkey_bytes = from_hex(&pubkey)?;
            let pubkey = PubKey::from_bytes(&pubkey_bytes).context("Failed to parse public key")?;

            let message_bytes = message.as_bytes().to_vec();

            let ciphertext = encrypt(&message_bytes, &pubkey);
            println!("{}", to_hex(&ciphertext));
        }
        Commands::Decrypt {
            privkey,
            ciphertext,
        } => {
            let privkey_bytes = from_hex(&privkey).context("Invalid private key hex")?;
            let privkey =
                PrivKey::from_bytes(&privkey_bytes).context("Failed to parse private key")?;

            let ciphertext_bytes = from_hex(&ciphertext).context("Invalid ciphertext hex")?;

            let decrypted = decrypt(&ciphertext_bytes, &privkey).context("Decryption failed")?;
            println!("{}", String::from_utf8(decrypted)?);
        }
        Commands::Example => {
            example()?;
        }
        Commands::EncryptPadded {
            pubkey,
            message,
            padded_length,
        } => {
            let pubkey_bytes = from_hex(&pubkey)?;
            let pubkey = PubKey::from_bytes(&pubkey_bytes).context("Failed to parse public key")?;

            let message_bytes = message.as_bytes().to_vec();

            let ciphertext = encrypt_padded(&message_bytes, &pubkey, padded_length)?;
            println!("{}", to_hex(&ciphertext));
        }
        Commands::DecryptPadded {
            privkey,
            ciphertext,
        } => {
            let privkey_bytes = from_hex(&privkey).context("Invalid private key hex")?;
            let privkey =
                PrivKey::from_bytes(&privkey_bytes).context("Failed to parse private key")?;

            let ciphertext_bytes = from_hex(&ciphertext).context("Invalid ciphertext hex")?;

            let decrypted =
                decrypt_padded(&ciphertext_bytes, &privkey).context("Decryption failed")?;
            println!("{}", String::from_utf8(decrypted)?);
        }
    }

    Ok(())
}
