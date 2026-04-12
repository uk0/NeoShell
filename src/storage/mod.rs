use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::PathBuf;
use parking_lot::RwLock;

use crate::crypto::{CryptoEngine, VaultHeader};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionConfig {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub color: String,
}

/// Safe version without secrets - sent to frontend for listing
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: String,
    pub group: String,
    pub color: String,
}

impl From<&ConnectionConfig> for ConnectionInfo {
    fn from(c: &ConnectionConfig) -> Self {
        ConnectionInfo {
            id: c.id.clone(),
            name: c.name.clone(),
            host: c.host.clone(),
            port: c.port,
            username: c.username.clone(),
            auth_type: c.auth_type.clone(),
            group: c.group.clone(),
            color: c.color.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub connections: HashMap<String, EncryptedBlob>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedBlob {
    pub nonce: String,
    pub data: String,
}

pub struct ConnectionStore {
    crypto: RwLock<CryptoEngine>,
    vault_path: PathBuf,
}

impl ConnectionStore {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("neoshell");

        // Ensure the directory exists
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            eprintln!("Warning: failed to create data dir {:?}: {}", data_dir, e);
        }

        let vault_path = data_dir.join("vault.json");

        ConnectionStore {
            crypto: RwLock::new(CryptoEngine::new()),
            vault_path,
        }
    }

    /// Check if the vault file exists on disk
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Initialize vault with a new master password
    pub fn set_master_password(&self, password: &str) -> Result<(), String> {
        if self.vault_exists() {
            return Err("Master password is already set. Vault exists.".to_string());
        }

        let mut crypto = self.crypto.write();
        let header = crypto.init_vault(password)?;

        let vault = VaultFile {
            header,
            connections: HashMap::new(),
        };

        self.save_vault(&vault)
    }

    /// Verify a master password against the stored vault
    pub fn verify_master_password(&self, password: &str) -> Result<bool, String> {
        if !self.vault_exists() {
            return Err("No vault found. Set a master password first.".to_string());
        }

        let vault = self.load_vault()?;
        let mut crypto = self.crypto.write();
        crypto.unlock(password, &vault.header)
    }

    /// Unlock the vault with the master password (keeps DEK in memory)
    pub fn unlock(&self, password: &str) -> Result<bool, String> {
        if !self.vault_exists() {
            return Err("No vault found. Set a master password first.".to_string());
        }

        let vault = self.load_vault()?;
        let mut crypto = self.crypto.write();
        crypto.unlock(password, &vault.header)
    }

    pub fn is_unlocked(&self) -> bool {
        self.crypto.read().is_unlocked()
    }

    /// Save a new connection. Generates a UUID if id is empty. Returns the id.
    pub fn save_connection(&self, mut config: ConnectionConfig) -> Result<String, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        if config.id.is_empty() {
            config.id = uuid::Uuid::new_v4().to_string();
        }

        let id = config.id.clone();

        // Serialize the full config to JSON
        let json = serde_json::to_vec(&config)
            .map_err(|e| format!("Failed to serialize connection: {}", e))?;

        // Encrypt with DEK
        let crypto = self.crypto.read();
        let (nonce, data) = crypto.encrypt(&json)?;

        let blob = EncryptedBlob { nonce, data };

        let mut vault = self.load_vault()?;
        vault.connections.insert(id.clone(), blob);
        drop(crypto);
        self.save_vault(&vault)?;

        Ok(id)
    }

    /// Get all connections as safe ConnectionInfo (no secrets)
    pub fn get_connections(&self) -> Result<Vec<ConnectionInfo>, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let vault = self.load_vault()?;
        let crypto = self.crypto.read();
        let mut connections = Vec::new();

        for (_id, blob) in &vault.connections {
            let plaintext = crypto.decrypt(&blob.nonce, &blob.data)?;
            let config: ConnectionConfig = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Failed to deserialize connection: {}", e))?;
            connections.push(ConnectionInfo::from(&config));
        }

        Ok(connections)
    }

    /// Get a single connection with full secrets (for SSH connect)
    pub fn get_connection(&self, id: &str) -> Result<ConnectionConfig, String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let vault = self.load_vault()?;
        let blob = vault.connections.get(id)
            .ok_or_else(|| format!("Connection '{}' not found", id))?;

        let crypto = self.crypto.read();
        let plaintext = crypto.decrypt(&blob.nonce, &blob.data)?;
        let config: ConnectionConfig = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to deserialize connection: {}", e))?;

        Ok(config)
    }

    /// Delete a connection by id
    pub fn delete_connection(&self, id: &str) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let mut vault = self.load_vault()?;
        if vault.connections.remove(id).is_none() {
            return Err(format!("Connection '{}' not found", id));
        }
        self.save_vault(&vault)
    }

    /// Update an existing connection
    pub fn update_connection(&self, config: ConnectionConfig) -> Result<(), String> {
        if !self.is_unlocked() {
            return Err("Vault is locked. Unlock first.".to_string());
        }

        let mut vault = self.load_vault()?;
        if !vault.connections.contains_key(&config.id) {
            return Err(format!("Connection '{}' not found", config.id));
        }

        let json = serde_json::to_vec(&config)
            .map_err(|e| format!("Failed to serialize connection: {}", e))?;

        let crypto = self.crypto.read();
        let (nonce, data) = crypto.encrypt(&json)?;
        drop(crypto);

        vault.connections.insert(config.id.clone(), EncryptedBlob { nonce, data });
        self.save_vault(&vault)
    }

    fn load_vault(&self) -> Result<VaultFile, String> {
        let content = std::fs::read_to_string(&self.vault_path)
            .map_err(|e| format!("Failed to read vault file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse vault file: {}", e))
    }

    fn save_vault(&self, vault: &VaultFile) -> Result<(), String> {
        // Ensure parent directory exists
        if let Some(parent) = self.vault_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create vault directory: {}", e))?;
        }

        let json = serde_json::to_string_pretty(vault)
            .map_err(|e| format!("Failed to serialize vault: {}", e))?;
        std::fs::write(&self.vault_path, json)
            .map_err(|e| format!("Failed to write vault file: {}", e))
    }
}
