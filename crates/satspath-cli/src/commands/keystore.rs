//! Local identity-key store.
//!
//! Holds the **protocol identity key** — the secp256k1 key that signs a user's
//! public payment profile. It is *not* a wallet seed, spending key, xprv,
//! mnemonic, macaroon, or API secret, and it never enters a profile, a QR
//! payload, or the network.
//!
//! Keys live under `.satspath/identity/<identity_pubkey>.key` (hex). `.satspath/`
//! and `*.key` are both gitignored, and the file is created owner-only on Unix.
//! Persisting it is what lets a user attach ownership proofs to — and otherwise
//! update — their own profile later, since doing so re-signs the profile.

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::io::Write;

const IDENTITY_SUBDIR: &str = "identity";

fn identity_dir(base: &Path) -> PathBuf {
    base.join(IDENTITY_SUBDIR)
}

/// Path of the identity key file for a given identity pubkey (hex).
pub fn identity_key_path(base: &Path, identity_pubkey_hex: &str) -> PathBuf {
    identity_dir(base).join(format!("{identity_pubkey_hex}.key"))
}

fn pubkey_hex_of(secret_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    hex::encode(PublicKey::from_secret_key(&secp, secret_key).serialize())
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    key.copy_from_slice(&hasher.finalize());
    for _ in 0..100_000 {
        let mut h = Sha256::new();
        h.update(key);
        key.copy_from_slice(&h.finalize());
    }
    *Key::<Aes256Gcm>::from_slice(&key)
}

/// Persist the protocol identity secret key. Returns the path written.
pub fn save_identity_key(base: &Path, secret_key: &SecretKey) -> Result<PathBuf> {
    use std::io::IsTerminal;
    let password = std::env::var("SATSPATH_PASSWORD").unwrap_or_else(|_| {
        if !std::io::stdin().is_terminal() {
            String::new()
        } else {
            print!(
                "Enter a password to encrypt your identity key (or press enter for no password): "
            );
            let _ = std::io::stdout().flush();
            rpassword::read_password().unwrap_or_default()
        }
    });
    save_identity_key_with_password(base, secret_key, &password)
}

fn save_identity_key_with_password(
    base: &Path,
    secret_key: &SecretKey,
    password: &str,
) -> Result<PathBuf> {
    let pubkey_hex = pubkey_hex_of(secret_key);
    let dir = identity_dir(base);
    fs::create_dir_all(&dir).context("creating identity keystore directory")?;
    let path = identity_key_path(base, &pubkey_hex);

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret_key.secret_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {:?}", e))?;

    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    fs::write(&path, hex::encode(payload)).context("writing identity key")?;
    set_owner_only(&path)?;
    Ok(path)
}

/// Load the identity secret key for a given identity pubkey (hex).
pub fn load_identity_key(base: &Path, identity_pubkey_hex: &str) -> Result<SecretKey> {
    load_identity_key_with_password(base, identity_pubkey_hex, None)
}

fn load_identity_key_with_password(
    base: &Path,
    identity_pubkey_hex: &str,
    explicit_password: Option<&str>,
) -> Result<SecretKey> {
    let path = identity_key_path(base, identity_pubkey_hex);
    if !path.exists() {
        anyhow::bail!(
            "identity key not found at {}.\n\
             This profile cannot be modified on this machine — it was registered \
             elsewhere, or before identity keys were saved.",
            path.display()
        );
    }
    let hex_str = fs::read_to_string(&path).context("reading identity key")?;
    let bytes = hex::decode(hex_str.trim()).context("decoding identity key hex")?;

    let secret_key = if bytes.len() == 32 {
        // Legacy plaintext hex format
        SecretKey::from_slice(&bytes).context("parsing legacy identity key")?
    } else if bytes.len() > 16 + 12 + 16 {
        // Encrypted format: salt (16) + nonce (12) + ciphertext
        let salt = &bytes[0..16];
        let nonce_bytes = &bytes[16..28];
        let ciphertext = &bytes[28..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let try_decrypt = |pwd: &str| -> Option<SecretKey> {
            let key = derive_key(pwd, salt);
            let cipher = Aes256Gcm::new(&key);
            cipher
                .decrypt(nonce, ciphertext)
                .ok()
                .and_then(|pt| SecretKey::from_slice(&pt).ok())
        };

        if let Some(pwd) = explicit_password {
            try_decrypt(pwd).context("incorrect explicit password or corrupted key file")?
        } else if let Ok(pwd) = std::env::var("SATSPATH_PASSWORD") {
            try_decrypt(&pwd).context("incorrect SATSPATH_PASSWORD or corrupted key file")?
        } else if let Some(sk) = try_decrypt("") {
            // Key was saved without password (empty password)
            sk
        } else {
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "SATSPATH_PASSWORD environment variable required to decrypt identity key in non-interactive environment"
                );
            } else {
                print!(
                    "Enter password to decrypt identity key {}: ",
                    identity_pubkey_hex
                );
                let _ = std::io::stdout().flush();
                let pwd = rpassword::read_password().context("reading password")?;
                try_decrypt(&pwd).context("incorrect password or corrupted key file")?
            }
        }
    } else {
        anyhow::bail!("invalid key file length");
    };

    // The file is named by pubkey; make sure the contents actually match it.
    if pubkey_hex_of(&secret_key) != identity_pubkey_hex {
        anyhow::bail!("identity key file does not match the requested identity pubkey");
    }
    Ok(secret_key)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::crypto::generate_identity_keypair;

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());

        let path = save_identity_key_with_password(dir.path(), &kp.secret_key, "testpass").unwrap();
        assert!(path.exists());

        let loaded =
            load_identity_key_with_password(dir.path(), &pubkey_hex, Some("testpass")).unwrap();
        assert_eq!(loaded.secret_bytes(), kp.secret_key.secret_bytes());
    }

    #[test]
    fn load_missing_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        assert!(
            load_identity_key_with_password(dir.path(), &pubkey_hex, Some("testpass")).is_err()
        );
    }

    #[test]
    fn save_then_load_unencrypted_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());

        let path = save_identity_key_with_password(dir.path(), &kp.secret_key, "").unwrap();
        assert!(path.exists());

        let loaded = load_identity_key_with_password(dir.path(), &pubkey_hex, Some("")).unwrap();
        assert_eq!(loaded.secret_bytes(), kp.secret_key.secret_bytes());
    }

    #[test]
    fn load_with_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());

        save_identity_key_with_password(dir.path(), &kp.secret_key, "correct_password").unwrap();
        assert!(
            load_identity_key_with_password(dir.path(), &pubkey_hex, Some("wrong_password"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let kp = generate_identity_keypair();
        let path = save_identity_key_with_password(dir.path(), &kp.secret_key, "testpass").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
