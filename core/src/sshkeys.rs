//! Local SSH key management (v0.7.0).
//!
//! Lists keypairs found in `~/.ssh`, generates new ed25519 keys in
//! OpenSSH format, and exposes the public key line for clipboard copy
//! or one-click deployment to a server's `authorized_keys`.

use ssh_key::{Algorithm, LineEnding, PrivateKey};

#[derive(Debug, Clone)]
pub struct LocalKey {
    /// File stem, e.g. `id_ed25519`.
    pub name: String,
    /// Private key path (`~/.ssh/<name>`).
    pub path: String,
    /// Key type from the .pub line, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Full public key line (type + base64 + comment).
    pub pubkey: String,
    /// Trailing comment of the .pub line (often user@host).
    pub comment: String,
}

fn ssh_dir() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ssh")
}

/// Scan `~/.ssh/*.pub` and return every keypair found, sorted by name.
pub fn list_keys() -> Vec<LocalKey> {
    let dir = ssh_dir();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let line = content.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key_type = parts.next().unwrap_or("").to_string();
        // Only surface things that look like SSH public keys.
        if !key_type.starts_with("ssh-") && !key_type.starts_with("ecdsa-") {
            continue;
        }
        let _b64 = parts.next();
        let comment = parts.collect::<Vec<_>>().join(" ");
        let priv_path = path.with_extension("");
        let name = priv_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        out.push(LocalKey {
            name,
            path: priv_path.to_string_lossy().to_string(),
            key_type,
            pubkey: line,
            comment,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Generate a new ed25519 keypair under `~/.ssh/<name>` (+ `.pub`).
/// Refuses to overwrite existing files. Sets 0600/0644 on unix.
pub fn generate_ed25519(name: &str, comment: &str) -> Result<LocalKey, String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.starts_with('.')
        || name.contains("..")
    {
        return Err("invalid key name".into());
    }
    let dir = ssh_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create ~/.ssh: {}", e))?;
    let priv_path = dir.join(name);
    let pub_path = dir.join(format!("{}.pub", name));
    if priv_path.exists() || pub_path.exists() {
        return Err(format!("{} already exists", priv_path.display()));
    }

    let mut key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)
        .map_err(|e| format!("keygen: {}", e))?;
    if !comment.is_empty() {
        key.set_comment(comment);
    }

    let priv_pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("encode private: {}", e))?;
    let pub_line = key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("encode public: {}", e))?;

    std::fs::write(&priv_path, priv_pem.as_bytes())
        .map_err(|e| format!("write private key: {}", e))?;
    std::fs::write(&pub_path, format!("{}\n", pub_line))
        .map_err(|e| format!("write public key: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644));
    }

    Ok(LocalKey {
        name: name.to_string(),
        path: priv_path.to_string_lossy().to_string(),
        key_type: "ssh-ed25519".to_string(),
        pubkey: pub_line,
        comment: comment.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn reject_bad_names() {
        assert!(super::generate_ed25519("", "").is_err());
        assert!(super::generate_ed25519("../evil", "").is_err());
        assert!(super::generate_ed25519("a/b", "").is_err());
        assert!(super::generate_ed25519(".hidden", "").is_err());
    }
}
