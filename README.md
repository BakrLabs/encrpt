# encrpt

A no-nonsense file encryption CLI tool written in Rust. 

![Rust](https://img.shields.io/badge/Rust-1.89+-orange)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/Status-Active-green)

No config files, no cloud sync, no backdoors. Just AES-256-GCM and Argon2id keeping your files safe.

## Why this exists

Sometimes you just need to encrypt a file from the terminal without setting up a whole vault. `encrpt` does exactly that, securely:

- **AES-256-GCM**: Encrypts your data *and* checks that nobody tampered with it. If a single bit changes in the encrypted file, decryption fails.
- **Argon2id**: The current gold standard for turning passwords into keys. It's deliberately slow and memory-hard, making brute-force attacks incredibly expensive.
- **Streaming I/O**: Files are encrypted in 64KB chunks. You can encrypt a 100GB video on a laptop with 4GB of RAM without crashing.
- **Atomic Writes**: Writes to a temporary file first. If decryption fails halfway through (e.g., wrong password), your original output file is never destroyed.
- **Zeroize**: Keys are wiped from memory the moment they're no longer needed.
- **Self-describing format**: The encryption parameters are saved inside the file. If you ever update the defaults, old files will still decrypt fine.
- **No footguns**: Refuses to overwrite files unless you use `--force`. Validates paths before asking for passwords.

## Install

If you have Rust installed, you can build it from source:

```bash
git clone https://github.com/BakrLabs/encrpt.git
cd encrpt
cargo install --path .
```
## How to use it

### Lock a file:

```bash
encrpt encrypt -i secret.txt -o secret.enc
```
You'll be asked for a password twice to make sure there are no typos.

### Unlock a file:

```bash
encrpt decrypt -i secret.enc -o secret.txt
```
If the password is wrong or the file was tampered with, it will refuse to decrypt.

### Peek inside an encrypted file:

```bash
encrpt inspect -i secret.enc
```
Shows you the format version and the Argon2 parameters used, no password required.

### Securely delete the original file after encryption:

```bash
encrpt encrypt -i secret.txt -o secret.enc --shred
```
Overwrites the plaintext file with random bytes, truncates it, and deletes it.

### Overwrite an existing file:

```bash
encrpt encrypt -i secret.txt -o existing.enc --force
```

## Under the hood (File Format)

The encrypted file is just a fixed 47-byte header followed by encrypted chunks. Keeping it simple means it's easy to parse and hard to mess up.

| Offset | Size | Field                        |
|--------|------|------------------------------|
| 0      | 6    | Magic bytes `ENCRPT`         |
| 6      | 1    | Format version (`0x02`)      |
| 7      | 16   | Argon2id salt                |
| 23     | 12   | AES-256-GCM base nonce       |
| 35     | 4    | Argon2id m_cost (u32 BE)     |
| 39     | 4    | Argon2id t_cost (u32 BE)     |
| 43     | 4    | Argon2id p_cost (u32 BE)     |
| 47     | ...  | Chunks: `[u32 len] [ciphertext + 16 byte tag]` |

*Note: Because the Argon2 parameters are baked into the header, you can safely change the defaults in a future version of the tool and it will still be able to decrypt older files.*
## Security Notes
- Don't forget your password. There is no recovery mechanism. If you lose it, the data is gone.

- This is not a backup tool. It encrypts files in-place/duplicates them. Make sure you keep backups.

- Memory safety. Rust prevents whole classes of vulnerabilities (buffer overflows, use-after-free) that have plagued C crypto tools for decades.

- File permissions. On Unix systems, output files are created with 0600 (owner read/write only). No more accidentally leaving your decrypted files world-readable.

- SSD Shredding. The ``` --shred ``` command is best-effort. On traditional HDDs, it completely destroys the data. On SSDs (due to wear-leveling), there is no way to guarantee physical overwriting from userspace, but it still prevents the file from being recovered through standard filesystem APIs.
