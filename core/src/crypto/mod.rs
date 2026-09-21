use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};

const VERIFY_PLAINTEXT: &[u8] = b"NEOSHELL_VAULT_OK";

/// On-disk vault format version written by this build.
///
/// Version 1 is also what a header *without* a `version` field means — vaults
/// created before 0.7.0 had no version and no recorded KDF cost, and used the
/// constants in [`KdfParams::legacy`].
pub const VAULT_VERSION: u32 = 1;

/// Argon2id cost parameters, recorded in the vault header so the cost can be
/// raised later without locking users out of vaults written at the old cost.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// The cost every build before 0.7.0 hardcoded: m=64MB, t=3, p=4. This is
    /// what a header with no `kdf` field must derive with, or existing vaults
    /// stop opening.
    pub fn legacy() -> Self {
        KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4 }
    }
}

impl Default for KdfParams {
    /// The cost this build writes into new vaults. Raising it is safe: old
    /// vaults keep their own params in their header.
    fn default() -> Self {
        KdfParams::legacy()
    }
}

fn default_vault_version() -> u32 {
    // A header that predates the `version` field is, by definition, version 1.
    1
}

fn default_kdf_params() -> KdfParams {
    KdfParams::legacy()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultHeader {
    pub salt: String,
    pub kek_nonce: String,
    pub encrypted_dek: String,
    pub verify_nonce: String,
    pub verify_token: String,
    /// Absent in pre-0.7.0 vaults -> 1.
    #[serde(default = "default_vault_version")]
    pub version: u32,
    /// Absent in pre-0.7.0 vaults -> the cost those builds hardcoded.
    #[serde(default = "default_kdf_params")]
    pub kdf: KdfParams,
}

pub struct CryptoEngine {
    dek: Option<[u8; 32]>,
}

impl Drop for CryptoEngine {
    fn drop(&mut self) {
        self.clear_dek();
    }
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self { dek: None }
    }

    /// Wipe the in-memory DEK. Zeroizes in place before dropping the Option so
    /// the key bytes do not survive in the struct's storage.
    fn clear_dek(&mut self) {
        if let Some(dek) = self.dek.as_mut() {
            dek.zeroize();
        }
        self.dek = None;
    }

    /// Initialize a new vault with the given master password.
    /// Returns a VaultHeader containing all the cryptographic material
    /// needed to unlock the vault in the future.
    pub fn init_vault(&mut self, password: &str) -> Result<VaultHeader, String> {
        // 1. Generate a random salt for Argon2
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // 2. Derive KEK from password, at this build's cost
        let kdf = KdfParams::default();
        let kek = derive_key(password, &salt, &kdf)?;

        // 3. Generate random DEK
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(dek.as_mut_slice());

        // 4. Encrypt DEK with KEK
        let kek_cipher = Aes256Gcm::new_from_slice(kek.as_slice())
            .map_err(|e| format!("Failed to create KEK cipher: {}", e))?;
        let mut kek_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut kek_nonce_bytes);
        let kek_nonce = Nonce::from_slice(&kek_nonce_bytes);
        let encrypted_dek = kek_cipher
            .encrypt(kek_nonce, dek.as_slice())
            .map_err(|e| format!("Failed to encrypt DEK: {}", e))?;

        // 5. Encrypt verification token with KEK
        let mut verify_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut verify_nonce_bytes);
        let verify_nonce = Nonce::from_slice(&verify_nonce_bytes);
        let verify_token = kek_cipher
            .encrypt(verify_nonce, VERIFY_PLAINTEXT)
            .map_err(|e| format!("Failed to encrypt verify token: {}", e))?;

        // 6. Store DEK in memory
        self.clear_dek();
        self.dek = Some(*dek);

        Ok(VaultHeader {
            salt: BASE64.encode(salt),
            kek_nonce: BASE64.encode(kek_nonce_bytes),
            encrypted_dek: BASE64.encode(encrypted_dek),
            verify_nonce: BASE64.encode(verify_nonce_bytes),
            verify_token: BASE64.encode(verify_token),
            version: VAULT_VERSION,
            kdf,
        })
    }

    /// Unlock the vault by deriving KEK from password, decrypting DEK,
    /// and verifying the known plaintext token.
    ///
    /// The KDF cost comes from the header, never from a constant — that is what
    /// lets the cost be raised for new vaults without breaking old ones.
    pub fn unlock(&mut self, password: &str, header: &VaultHeader) -> Result<bool, String> {
        if header.version > VAULT_VERSION {
            return Err(format!(
                "Vault format v{} was written by a newer NeoShell (this build understands up to v{}). Upgrade NeoShell to open it.",
                header.version, VAULT_VERSION
            ));
        }

        let salt = BASE64.decode(&header.salt)
            .map_err(|e| format!("Failed to decode salt: {}", e))?;
        let kek_nonce_bytes = BASE64.decode(&header.kek_nonce)
            .map_err(|e| format!("Failed to decode kek_nonce: {}", e))?;
        let encrypted_dek = BASE64.decode(&header.encrypted_dek)
            .map_err(|e| format!("Failed to decode encrypted_dek: {}", e))?;
        let verify_nonce_bytes = BASE64.decode(&header.verify_nonce)
            .map_err(|e| format!("Failed to decode verify_nonce: {}", e))?;
        let verify_token = BASE64.decode(&header.verify_token)
            .map_err(|e| format!("Failed to decode verify_token: {}", e))?;

        // Derive KEK at the cost this vault was written with
        let kek = derive_key(password, &salt, &header.kdf)?;

        let kek_cipher = Aes256Gcm::new_from_slice(kek.as_slice())
            .map_err(|e| format!("Failed to create KEK cipher: {}", e))?;

        // Verify password by decrypting the verification token
        let verify_nonce = Nonce::from_slice(&verify_nonce_bytes);
        let decrypted_verify = kek_cipher
            .decrypt(verify_nonce, verify_token.as_ref())
            .map_err(|_| "Invalid master password".to_string())?;

        if decrypted_verify != VERIFY_PLAINTEXT {
            return Ok(false);
        }

        // Decrypt DEK
        let kek_nonce = Nonce::from_slice(&kek_nonce_bytes);
        let dek_bytes = Zeroizing::new(
            kek_cipher
                .decrypt(kek_nonce, encrypted_dek.as_ref())
                .map_err(|_| "Failed to decrypt DEK - invalid password".to_string())?,
        );

        if dek_bytes.len() != 32 {
            return Err("Invalid DEK length".to_string());
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        self.clear_dek();
        self.dek = Some(dek);

        Ok(true)
    }

    /// Encrypt data with the DEK. Returns (nonce_base64, ciphertext_base64).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String), String> {
        let dek = self.dek.as_ref().ok_or("Vault is locked")?;
        let cipher = Aes256Gcm::new_from_slice(dek.as_slice())
            .map_err(|e| format!("Failed to create DEK cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok((BASE64.encode(nonce_bytes), BASE64.encode(ciphertext)))
    }

    /// Decrypt data with the DEK. The plaintext is wiped when the caller drops it.
    pub fn decrypt(&self, nonce_b64: &str, ciphertext_b64: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let dek = self.dek.as_ref().ok_or("Vault is locked")?;
        let cipher = Aes256Gcm::new_from_slice(dek.as_slice())
            .map_err(|e| format!("Failed to create DEK cipher: {}", e))?;

        let nonce_bytes = BASE64.decode(nonce_b64)
            .map_err(|e| format!("Failed to decode nonce: {}", e))?;
        let ciphertext = BASE64.decode(ciphertext_b64)
            .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(Zeroizing::new(plaintext))
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }
}

/// Derive a 32-byte key from a password and salt using Argon2id at the given cost.
/// The key is wiped when the returned wrapper is dropped.
fn derive_key(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| format!(
            "Invalid Argon2 params (m={}, t={}, p={}): {}",
            kdf.m_cost, kdf.t_cost, kdf.p_cost, e
        ))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery staple";

    #[test]
    fn init_then_unlock_round_trip() {
        let mut a = CryptoEngine::new();
        let header = a.init_vault(PW).unwrap();
        assert!(a.is_unlocked());

        let mut b = CryptoEngine::new();
        assert!(!b.is_unlocked());
        assert!(b.unlock(PW, &header).unwrap());
        assert!(b.is_unlocked());

        // Both engines hold the same DEK: ciphertext from one decrypts in the other.
        let (nonce, data) = a.encrypt(b"hello vault").unwrap();
        assert_eq!(b.decrypt(&nonce, &data).unwrap().as_slice(), b"hello vault");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let mut a = CryptoEngine::new();
        let header = a.init_vault(PW).unwrap();

        let mut b = CryptoEngine::new();
        let err = b.unlock("not the password", &header).unwrap_err();
        assert!(err.contains("Invalid master password"), "unexpected error: {}", err);
        assert!(!b.is_unlocked(), "a failed unlock must not leave a DEK behind");
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let mut e = CryptoEngine::new();
        e.init_vault(PW).unwrap();

        for plaintext in [&b""[..], &b"a"[..], "secret — 密码 🔐".as_bytes()] {
            let (nonce, data) = e.encrypt(plaintext).unwrap();
            assert_eq!(e.decrypt(&nonce, &data).unwrap().as_slice(), plaintext);
        }
    }

    #[test]
    fn encrypt_uses_a_fresh_nonce_each_time() {
        let mut e = CryptoEngine::new();
        e.init_vault(PW).unwrap();
        let (n1, c1) = e.encrypt(b"same plaintext").unwrap();
        let (n2, c2) = e.encrypt(b"same plaintext").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut e = CryptoEngine::new();
        e.init_vault(PW).unwrap();
        let (nonce, data) = e.encrypt(b"transfer 1 BTC to alice").unwrap();

        // Flip one bit in the ciphertext body.
        let mut raw = BASE64.decode(&data).unwrap();
        raw[0] ^= 0x01;
        let tampered = BASE64.encode(&raw);
        assert!(e.decrypt(&nonce, &tampered).is_err(), "GCM tag must reject a flipped bit");

        // Flip one bit in the nonce.
        let mut raw_nonce = BASE64.decode(&nonce).unwrap();
        raw_nonce[0] ^= 0x01;
        assert!(e.decrypt(&BASE64.encode(&raw_nonce), &data).is_err());

        // Truncating the ciphertext (a partial write) must not decrypt either.
        let mut short = BASE64.decode(&data).unwrap();
        short.truncate(short.len() - 1);
        assert!(e.decrypt(&nonce, &BASE64.encode(&short)).is_err());
    }

    #[test]
    fn locked_engine_refuses_to_encrypt_or_decrypt() {
        let e = CryptoEngine::new();
        assert!(e.encrypt(b"x").is_err());
        assert!(e.decrypt("AAAAAAAAAAAAAAAA", "AAAA").is_err());
    }

    /// The backward-compatibility guarantee: a header written by a pre-0.7.0
    /// build has no `version` and no `kdf` key at all, and must still open.
    #[test]
    fn legacy_header_without_version_or_kdf_still_unlocks() {
        let mut a = CryptoEngine::new();
        let header = a.init_vault(PW).unwrap();

        // Strip the two new keys, exactly as an old vault.json on disk lacks them.
        let mut obj: serde_json::Value = serde_json::to_value(&header).unwrap();
        let map = obj.as_object_mut().unwrap();
        map.remove("version");
        map.remove("kdf");
        assert_eq!(map.len(), 5, "legacy header must be exactly the original 5 fields");
        let legacy = serde_json::to_string(&obj).unwrap();

        let parsed: VaultHeader = serde_json::from_str(&legacy).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.kdf, KdfParams::legacy());

        let mut b = CryptoEngine::new();
        assert!(b.unlock(PW, &parsed).unwrap(), "pre-0.7.0 vault must still open");
    }

    #[test]
    fn new_header_records_version_and_kdf() {
        let mut e = CryptoEngine::new();
        let header = e.init_vault(PW).unwrap();
        assert_eq!(header.version, VAULT_VERSION);
        assert_eq!(header.kdf, KdfParams::legacy());

        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"m_cost\""));
    }

    /// Proves unlock derives with the *header's* cost rather than a constant:
    /// change the recorded cost and the derived KEK no longer opens the vault.
    #[test]
    fn unlock_honours_header_kdf_params() {
        let mut a = CryptoEngine::new();
        let mut header = a.init_vault(PW).unwrap();
        header.kdf.t_cost += 1;

        let mut b = CryptoEngine::new();
        assert!(b.unlock(PW, &header).is_err());
        assert!(!b.is_unlocked());
    }

    #[test]
    fn future_vault_version_is_refused_with_a_clear_error() {
        let mut a = CryptoEngine::new();
        let mut header = a.init_vault(PW).unwrap();
        header.version = VAULT_VERSION + 1;

        let mut b = CryptoEngine::new();
        let err = b.unlock(PW, &header).unwrap_err();
        assert!(err.contains("newer NeoShell"), "unexpected error: {}", err);
    }

    #[test]
    fn nonsensical_kdf_params_fail_loudly() {
        let mut a = CryptoEngine::new();
        let mut header = a.init_vault(PW).unwrap();
        header.kdf.m_cost = 0;

        let mut b = CryptoEngine::new();
        let err = b.unlock(PW, &header).unwrap_err();
        assert!(err.contains("Invalid Argon2 params"), "unexpected error: {}", err);
    }
}
