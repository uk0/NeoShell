use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Serialize, Deserialize};

const VERIFY_PLAINTEXT: &[u8] = b"NEOSHELL_VAULT_OK";

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultHeader {
    pub salt: String,
    pub kek_nonce: String,
    pub encrypted_dek: String,
    pub verify_nonce: String,
    pub verify_token: String,
}

pub struct CryptoEngine {
    dek: Option<[u8; 32]>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self { dek: None }
    }

    /// Initialize a new vault with the given master password.
    /// Returns a VaultHeader containing all the cryptographic material
    /// needed to unlock the vault in the future.
    pub fn init_vault(&mut self, password: &str) -> Result<VaultHeader, String> {
        // 1. Generate a random salt for Argon2
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // 2. Derive KEK from password
        let kek = derive_key(password, &salt)?;

        // 3. Generate random DEK
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);

        // 4. Encrypt DEK with KEK
        let kek_cipher = Aes256Gcm::new_from_slice(&kek)
            .map_err(|e| format!("Failed to create KEK cipher: {}", e))?;
        let mut kek_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut kek_nonce_bytes);
        let kek_nonce = Nonce::from_slice(&kek_nonce_bytes);
        let encrypted_dek = kek_cipher
            .encrypt(kek_nonce, dek.as_ref())
            .map_err(|e| format!("Failed to encrypt DEK: {}", e))?;

        // 5. Encrypt verification token with KEK
        let mut verify_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut verify_nonce_bytes);
        let verify_nonce = Nonce::from_slice(&verify_nonce_bytes);
        let verify_token = kek_cipher
            .encrypt(verify_nonce, VERIFY_PLAINTEXT)
            .map_err(|e| format!("Failed to encrypt verify token: {}", e))?;

        // 6. Store DEK in memory
        self.dek = Some(dek);

        Ok(VaultHeader {
            salt: BASE64.encode(salt),
            kek_nonce: BASE64.encode(kek_nonce_bytes),
            encrypted_dek: BASE64.encode(encrypted_dek),
            verify_nonce: BASE64.encode(verify_nonce_bytes),
            verify_token: BASE64.encode(verify_token),
        })
    }

    /// Unlock the vault by deriving KEK from password, decrypting DEK,
    /// and verifying the known plaintext token.
    pub fn unlock(&mut self, password: &str, header: &VaultHeader) -> Result<bool, String> {
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

        // Derive KEK
        let kek = derive_key(password, &salt)?;

        let kek_cipher = Aes256Gcm::new_from_slice(&kek)
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
        let dek_bytes = kek_cipher
            .decrypt(kek_nonce, encrypted_dek.as_ref())
            .map_err(|_| "Failed to decrypt DEK - invalid password".to_string())?;

        if dek_bytes.len() != 32 {
            return Err("Invalid DEK length".to_string());
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        self.dek = Some(dek);

        Ok(true)
    }

    /// Encrypt data with the DEK. Returns (nonce_base64, ciphertext_base64).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String), String> {
        let dek = self.dek.ok_or("Vault is locked")?;
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| format!("Failed to create DEK cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok((BASE64.encode(nonce_bytes), BASE64.encode(ciphertext)))
    }

    /// Decrypt data with the DEK.
    pub fn decrypt(&self, nonce_b64: &str, ciphertext_b64: &str) -> Result<Vec<u8>, String> {
        let dek = self.dek.ok_or("Vault is locked")?;
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| format!("Failed to create DEK cipher: {}", e))?;

        let nonce_bytes = BASE64.decode(nonce_b64)
            .map_err(|e| format!("Failed to decode nonce: {}", e))?;
        let ciphertext = BASE64.decode(ciphertext_b64)
            .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }
}

/// Derive a 32-byte key from a password and salt using Argon2id.
/// Parameters: m=64MB, t=3 iterations, p=4 parallelism.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| format!("Invalid Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}
