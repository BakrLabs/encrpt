use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use zeroize::Zeroize;

// ── The file format ──────────────────────────────────────────
// 
//  Bytes  Field
//  0-5    Magic bytes "ENCRPT"
//  6      Format version (0x02) - Bumped for chunked streaming
//  7-22   Salt          (16 bytes)
//  23-34  Nonce         (12 bytes)
//  35-38  Argon2 m_cost (u32 big-endian)
//  39-42  Argon2 t_cost (u32 big-endian)
//  43-46  Argon2 p_cost (u32 big-endian)
//  47+    Chunks: [u32 chunk_len LE] [ciphertext + 16 byte tag]
// ─────────────────────────────────────────────────────────────

const MAGIC: &[u8; 6] = b"ENCRPT";
const FORMAT_VERSION: u8 = 0x02;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 6 + 1 + SALT_LEN + NONCE_LEN + 4 + 4 + 4; // 47

// 64KB chunks. Sweet spot for I/O performance and memory usage.
const CHUNK_SIZE: usize = 64 * 1024;

// 64MB memory, 3 passes, 1 thread.
const DEFAULT_M_COST: u32 = 65536; 
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 1;

struct EncryptedHeader<'a> {
    salt: &'a [u8],
    nonce: &'a [u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

// ── Public API ───────────────────────────────────────────────

pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
    let mut input_file = fs::File::open(input_path).context("Failed to open input file")?;
    
    let tmp_output_path = format!("{}.tmp", output_path);
    let mut output_file = fs::File::create(&tmp_output_path).context("Couldn't create the temporary output file")?;
    set_restrictive_permissions(&output_file);

    // Wrap the core logic in a closure so we can catch errors and clean up
    let result = (|| {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let mut key = derive_key(password, &salt, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .expect("Key is exactly 32 bytes, so this should never fail");

        output_file.write_all(MAGIC)?;
        output_file.write_all(&[FORMAT_VERSION])?;
        output_file.write_all(&salt)?;
        output_file.write_all(&nonce_bytes)?;
        output_file.write_all(&DEFAULT_M_COST.to_be_bytes())?;
        output_file.write_all(&DEFAULT_T_COST.to_be_bytes())?;
        output_file.write_all(&DEFAULT_P_COST.to_be_bytes())?;

        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut chunk_index: u32 = 0;

        loop {
            let bytes_read = input_file.read(&mut buf)?;
            let is_last = bytes_read == 0;
            let plaintext = if is_last { &[][..] } else { &buf[..bytes_read] };

            let mut aad = Vec::with_capacity(5);
            aad.extend_from_slice(&chunk_index.to_le_bytes());
            aad.push(if is_last { 1 } else { 0 });

            let mut chunk_nonce = nonce_bytes;
            let idx_bytes = chunk_index.to_le_bytes();
            for i in 0..4 {
                chunk_nonce[NONCE_LEN - 4 + i] ^= idx_bytes[i];
            }
            let nonce = Nonce::from_slice(&chunk_nonce);

            let ciphertext = cipher
                .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
                .map_err(|e| anyhow::anyhow!("Encryption failed on chunk {}: {}", chunk_index, e))?;

            output_file.write_all(&(plaintext.len() as u32).to_le_bytes())?;
            output_file.write_all(&ciphertext)?;

            print!(".");
            std::io::stdout().flush()?;
            
            if is_last {
                break;
            }
            chunk_index += 1;
        }

        println!(); // Newline after dots
        key.zeroize();
        Ok(())
    })();

    // Close the file handle
    drop(output_file);

    // If encryption failed, delete the orphaned temp file before returning the error
    if result.is_err() {
        let _ = fs::remove_file(&tmp_output_path);
        return result;
    }

    // If it succeeded, rename the temp file to the final output
    fs::rename(&tmp_output_path, output_path).context("Failed to finalize the encrypted file")?;
    
    Ok(())
}

pub fn decrypt_file(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
    let mut input_file = fs::File::open(input_path).context("Failed to open input file")?;
    
    let tmp_output_path = format!("{}.tmp", output_path);
    let mut output_file = fs::File::create(&tmp_output_path).context("Couldn't create the temporary output file")?;
    set_restrictive_permissions(&output_file);

    // Wrap the core logic in a closure so we can catch errors and clean up
    let result = (|| {
        let mut header_buf = [0u8; HEADER_LEN];
        input_file.read_exact(&mut header_buf).context("File too short to contain a valid header")?;
        
        let header = parse_header(&header_buf)?;

        let mut key = derive_key(password, header.salt, header.m_cost, header.t_cost, header.p_cost)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .expect("Key is exactly 32 bytes, so this should never fail");

        let mut chunk_index: u32 = 0;

        loop {
            let mut len_bytes = [0u8; 4];
            match input_file.read_exact(&mut len_bytes) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    bail!("File is truncated. Missing final chunk.");
                }
                Err(e) => return Err(e).context("Failed to read chunk length"),
            }
            
            let chunk_len = u32::from_le_bytes(len_bytes) as usize;
            
            if chunk_len > CHUNK_SIZE {
                bail!("File is corrupted or tampered with. Invalid chunk size detected.");
            }

            let mut ct_buf = vec![0u8; chunk_len + 16]; // +16 for GCM tag

            input_file.read_exact(&mut ct_buf).map_err(|_| {
                anyhow::anyhow!("Decryption failed. The file has been truncated or tampered with.")
            })?;

            let is_last = chunk_len == 0;
            let mut aad = Vec::with_capacity(5);
            aad.extend_from_slice(&chunk_index.to_le_bytes());
            aad.push(if is_last { 1 } else { 0 });

            let mut chunk_nonce = [0u8; NONCE_LEN];
            chunk_nonce.copy_from_slice(header.nonce);
            let idx_bytes = chunk_index.to_le_bytes();
            for i in 0..4 {
                chunk_nonce[NONCE_LEN - 4 + i] ^= idx_bytes[i];
            }
            let nonce = Nonce::from_slice(&chunk_nonce);

            let plaintext = cipher
                .decrypt(nonce, Payload { msg: &ct_buf, aad: &aad })
                .map_err(|_| anyhow::anyhow!("Decryption failed. Wrong password or corrupted data."))?;

            if !plaintext.is_empty() {
                output_file.write_all(&plaintext)?;
            }

            print!(".");
            std::io::stdout().flush()?;

            if is_last {
                break;
            }
            chunk_index += 1;
        }

        println!(); // Newline after dots
        key.zeroize();
        Ok(())
    })();

    // Close the file handle
    drop(output_file);

    // If decryption failed, delete the orphaned temp file before returning the error
    if result.is_err() {
        let _ = fs::remove_file(&tmp_output_path);
        return result;
    }

    // If it succeeded, rename the temp file to the final output
    fs::rename(&tmp_output_path, output_path).context("Failed to finalize the decrypted file")?;
    
    Ok(())
}

/// Securely overwrites a file with random bytes, truncates it, and deletes it.
/// Note: This is best-effort. SSDs with wear-leveling may leave copies of the data elsewhere.
pub fn shred_file(path: &str) -> Result<()> {
    let file_size = fs::metadata(path)?.len();
    if file_size == 0 {
        fs::remove_file(path)?;
        return Ok(());
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .context("Failed to open file for shredding")?;

    let chunk_size = 4096;
    let mut buf = vec![0u8; chunk_size];
    let mut written = 0;

    while written < file_size {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let to_write = std::cmp::min(chunk_size as u64, file_size - written) as usize;
        file.write_all(&buf[..to_write])?;
        written += to_write as u64;
    }
    
    file.sync_all()?;
    file.set_len(0)?; // Truncate to hide original size
    drop(file); // Close the file handle before deleting

    fs::remove_file(path)?;
    Ok(())
}

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

pub fn inspect_file(path: &str) -> Result<(u8, u32, u32, u32)> {
    let mut file = fs::File::open(path).context("Failed to read file")?;
    let mut buf = [0u8; HEADER_LEN];
    file.read_exact(&mut buf).context("File too short to inspect")?;
    let header = parse_header(&buf)?;
    Ok((FORMAT_VERSION, header.m_cost, header.t_cost, header.p_cost))
}

// ── Internal helpers ─────────────────────────────────────────

fn derive_key(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<[u8; 32]> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("Bad Argon2 parameters: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(key)
}

fn parse_header(data: &[u8]) -> Result<EncryptedHeader<'_>> {
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

    Ok(EncryptedHeader { salt, nonce, m_cost, t_cost, p_cost })
}

fn set_restrictive_permissions(file: &fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
}