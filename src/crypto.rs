use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::fs;
use std::io::Write;
use zeroize::Zeroize;

// ── The file format ──────────────────────────────────────────
// 
// I decided to keep this dead simple. No complex TLV structures, 
// just a fixed header. It makes parsing a breeze.
//
//  Bytes  Field
//  0-5    Magic bytes "ENCRPT" (so we don't try to decrypt a jpeg)
//  6      Format version (0x01)
//  7-22   Salt          (16 bytes)
//  23-34  Nonce         (12 bytes)
//  35-38  Argon2 m_cost (u32 big-endian)
//  39-42  Argon2 t_cost (u32 big-endian)
//  43-46  Argon2 p_cost (u32 big-endian)
//  47+    Ciphertext + GCM tag
// ─────────────────────────────────────────────────────────────

const MAGIC: &[u8; 6] = b"ENCRPT";
const FORMAT_VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// 6 + 1 + 16 + 12 + 4 + 4 + 4 = 47 bytes
const HEADER_LEN: usize = 47;

// 64MB memory, 3 passes, 1 thread.
// It's the "Goldilocks" zone for Argon2id right now—hard enough on GPUs, 
// fast enough that users don't get annoyed waiting.
const DEFAULT_M_COST: u32 = 65536; 
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 1;

/// A quick struct to hold the parsed header data. 
/// Using a struct keeps the function signature clean instead of returning a 6-tuple.
struct EncryptedHeader<'a> {
    salt: &'a [u8],
    nonce: &'a [u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    ciphertext: &'a [u8],
}

// ── Public API ───────────────────────────────────────────────

/// Locks a file up tight. 
/// Uses AES-256-GCM so nobody can tamper with it, and Argon2id so 
/// brute-forcing the password takes forever.
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
    let plaintext = fs::read(input_path).context("Failed to read input file")?;

    // Cook up some random salt and nonce. 
    // OsRng pulls from the OS entropy pool—/dev/urandom on Linux, CryptoAPI on Windows.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Turn the password into a 256-bit key. This takes a second on purpose (Argon2).
    let mut key = derive_key(password, &salt, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)?;

    // Do the actual encryption. 
    // AES-GCM handles both secrecy and integrity (authentication tag) for us.
    let cipher = Aes256Gcm::new_from_slice(&key)
        .expect("Key is exactly 32 bytes, so this should never fail");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    write_encrypted_file(output_path, &salt, &nonce_bytes, &ciphertext)?;

    // Wipe the key from memory. No reason to leave the keys in the ignition.
    key.zeroize();

    Ok(())
}

pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
    let file_bytes = fs::read(input_path).context("Failed to read input file")?;

    // Pick apart the header before we do any expensive crypto math
    let header = parse_header(&file_bytes)?;

    // Re-derive the key. We read the params from the header so if we ever change 
    // the defaults, old files still decrypt fine.
    let mut key = derive_key(password, header.salt, header.m_cost, header.t_cost, header.p_cost)?;

    let nonce = Nonce::from_slice(header.nonce);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .expect("Key is exactly 32 bytes, so this should never fail");

    // If the password is wrong, or even a single bit flipped in the ciphertext, 
    // GCM will catch it and this will fail. That's the whole point of authenticated encryption.
    let plaintext = cipher
        .decrypt(nonce, header.ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed. Wrong password or corrupted data."))?;

    write_decrypted_file(output_path, &plaintext)?;

    key.zeroize();

    Ok(())
}

/// Kicks the tires before we do any heavy lifting.
/// There's nothing worse than typing a long password only to realize the output path is wrong.
pub fn validate_paths(input_path: &str, output_path: &str, force: bool) -> Result<()> {
    if std::path::Path::new(input_path) == std::path::Path::new(output_path) {
        bail!("Input and output paths can't be the same. That's a good way to lose your data.");
    }

    if !std::path::Path::new(input_path).exists() {
        bail!("Input file doesn't exist: {}", input_path);
    }

    if std::path::Path::new(output_path).exists() && !force {
        bail!(
            "Output file already exists: {}. Use --force if you really want to overwrite it.",
            output_path
        );
    }

    Ok(())
}

/// Peeks inside an encrypted file to see what Argon2 params were used.
/// Handy for debugging without having to type a password.
pub fn inspect_file(path: &str) -> Result<(u8, u32, u32, u32)> {
    let data = fs::read(path).context("Failed to read file")?;
    let header = parse_header(&data)?;
    Ok((FORMAT_VERSION, header.m_cost, header.t_cost, header.p_cost))
}

// ── Internal helpers ─────────────────────────────────────────

fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("Bad Argon2 parameters: {}", e))?;
    
    // Argon2id is the standard recommendation now. It resists both side-channel 
    // and GPU attacks better than Argon2i or Argon2d alone.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(key)
}

fn parse_header(data: &[u8]) -> Result<EncryptedHeader<'_>> {
    if data.len() < HEADER_LEN {
        bail!(
            "File is too short ({} bytes). Not a valid encrpt file.",
            data.len()
        );
    }

    let magic = &data[0..6];
    if magic != MAGIC {
        bail!(
            "Doesn't look like an encrpt file. Expected magic 'ENCRPT', got '{}'",
            String::from_utf8_lossy(magic)
        );
    }

    let version = data[6];
    if version != FORMAT_VERSION {
        bail!(
            "I only understand version {}, but this file is version {}.",
            FORMAT_VERSION,
            version
        );
    }

    let salt = &data[7..7 + SALT_LEN];
    let nonce = &data[7 + SALT_LEN..7 + SALT_LEN + NONCE_LEN];
    
    let m_cost = u32::from_be_bytes(data[35..39].try_into().unwrap());
    let t_cost = u32::from_be_bytes(data[39..43].try_into().unwrap());
    let p_cost = u32::from_be_bytes(data[43..47].try_into().unwrap());
    
    let ciphertext = &data[HEADER_LEN..];

    if ciphertext.is_empty() {
        bail!("The file header checks out, but there's no actual ciphertext inside.");
    }

    Ok(EncryptedHeader {
        salt,
        nonce,
        m_cost,
        t_cost,
        p_cost,
        ciphertext,
    })
}

fn write_encrypted_file(
    path: &str,
    salt: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    let mut file = fs::File::create(path).context("Couldn't create the output file")?;
    set_restrictive_permissions(&file);

    file.write_all(MAGIC)?;
    file.write_all(&[FORMAT_VERSION])?;
    file.write_all(salt)?;
    file.write_all(nonce_bytes)?;
    file.write_all(&DEFAULT_M_COST.to_be_bytes())?;
    file.write_all(&DEFAULT_T_COST.to_be_bytes())?;
    file.write_all(&DEFAULT_P_COST.to_be_bytes())?;
    file.write_all(ciphertext)?;

    Ok(())
}

fn write_decrypted_file(path: &str, plaintext: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).context("Couldn't create the output file")?;
    set_restrictive_permissions(&file);

    file.write_all(plaintext)
        .context("Failed to write the decrypted data")?;

    Ok(())
}

/// Sets files to owner-only read/write on Unix. No reason to leave decrypted 
/// files sitting around with 644 permissions for anyone to read.
fn set_restrictive_permissions(file: &fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();
        let dec = NamedTempFile::new().unwrap();

        let secret = b"the quick brown fox jumps over the lazy dog";
        fs::write(input.path(), secret).unwrap();

        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "test_password_123",
        )
        .unwrap();

        // The encrypted file should look like random garbage, except for the header
        let enc_data = fs::read(enc.path()).unwrap();
        assert_ne!(&enc_data[HEADER_LEN..], secret);
        assert!(enc_data.starts_with(b"ENCRPT"));

        decrypt_file(
            enc.path().to_str().unwrap(),
            dec.path().to_str().unwrap(),
            "test_password_123",
        )
        .unwrap();

        let decrypted = fs::read(dec.path()).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn wrong_password_fails() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();
        let dec = NamedTempFile::new().unwrap();

        fs::write(input.path(), b"secret data").unwrap();

        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "correct_password",
        )
        .unwrap();

        let result = decrypt_file(
            enc.path().to_str().unwrap(),
            dec.path().to_str().unwrap(),
            "wrong_password",
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Decryption failed"),
            "Expected decryption failure, but got: {}",
            err_msg
        );
    }

    #[test]
    fn empty_file_roundtrip() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();
        let dec = NamedTempFile::new().unwrap();

        fs::write(input.path(), b"").unwrap();

        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "password",
        )
        .unwrap();

        decrypt_file(
            enc.path().to_str().unwrap(),
            dec.path().to_str().unwrap(),
            "password",
        )
        .unwrap();

        let decrypted = fs::read(dec.path()).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_file_roundtrip() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();
        let dec = NamedTempFile::new().unwrap();

        let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        fs::write(input.path(), &large_data).unwrap();

        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "password",
        )
        .unwrap();

        decrypt_file(
            enc.path().to_str().unwrap(),
            dec.path().to_str().unwrap(),
            "password",
        )
        .unwrap();

        let decrypted = fs::read(dec.path()).unwrap();
        assert_eq!(decrypted.len(), 1_000_000);
        assert_eq!(decrypted, large_data);
    }

    #[test]
    fn detect_non_encrpt_file() {
        let tmp = NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"this is not an encrypted file").unwrap();

        let result = decrypt_file(
            tmp.path().to_str().unwrap(),
            "/dev/null",
            "password",
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Doesn't look like an encrpt file"),
            "Expected format detection error, got: {}",
            err_msg
        );
    }

    #[test]
    fn truncated_file_fails() {
        let tmp = NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"ENCRPT\x01\x00\x00").unwrap();

        let result = decrypt_file(
            tmp.path().to_str().unwrap(),
            "/dev/null",
            "password",
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_version_fails() {
        let tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; HEADER_LEN + 16];
        data[0..6].copy_from_slice(b"ENCRPT");
        data[6] = 0xFF; // version from the future
        fs::write(tmp.path(), &data).unwrap();

        let result = decrypt_file(
            tmp.path().to_str().unwrap(),
            "/dev/null",
            "password",
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("I only understand version"),
            "Expected version error, got: {}",
            err_msg
        );
    }

    #[test]
    fn validate_paths_rejects_same_path() {
        assert!(validate_paths("/tmp/x", "/tmp/x", false).is_err());
    }

    #[test]
    fn validate_paths_rejects_overwrite_without_force() {
        let tmp = NamedTempFile::new().unwrap();
        let output = tmp.path().to_str().unwrap();

        assert!(validate_paths("/dev/null", output, false).is_err());
        assert!(validate_paths("/dev/null", output, true).is_ok());
    }

    #[test]
    fn validate_paths_rejects_missing_input() {
        assert!(validate_paths("/nonexistent/path", "/tmp/out", false).is_err());
    }

    #[test]
    fn inspect_file_returns_params() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();

        fs::write(input.path(), b"test").unwrap();
        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "password",
        )
        .unwrap();

        let (version, m, t, p) = inspect_file(enc.path().to_str().unwrap()).unwrap();
        assert_eq!(version, 0x01);
        assert_eq!(m, DEFAULT_M_COST);
        assert_eq!(t, DEFAULT_T_COST);
        assert_eq!(p, DEFAULT_P_COST);
    }

    #[test]
    fn binary_data_roundtrip() {
        let input = NamedTempFile::new().unwrap();
        let enc = NamedTempFile::new().unwrap();
        let dec = NamedTempFile::new().unwrap();

        let binary_data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        fs::write(input.path(), &binary_data).unwrap();

        encrypt_file(
            input.path().to_str().unwrap(),
            enc.path().to_str().unwrap(),
            "binary_test",
        )
        .unwrap();

        decrypt_file(
            enc.path().to_str().unwrap(),
            dec.path().to_str().unwrap(),
            "binary_test",
        )
        .unwrap();

        let decrypted = fs::read(dec.path()).unwrap();
        assert_eq!(decrypted, binary_data);
    }
}