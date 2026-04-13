use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct SshHostConfig {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identity_file: String,
}

/// Parse ~/.ssh/config and return a list of host configurations.
pub fn parse_ssh_config() -> Vec<SshHostConfig> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    let config_path = home.join(".ssh").join("config");

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut hosts = Vec::new();
    let mut current: Option<SshHostConfig> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on first whitespace or =
        let (key, value) = if let Some(eq_pos) = line.find('=') {
            (line[..eq_pos].trim(), line[eq_pos + 1..].trim())
        } else if let Some(space_pos) = line.find(char::is_whitespace) {
            (line[..space_pos].trim(), line[space_pos + 1..].trim())
        } else {
            continue;
        };

        match key.to_lowercase().as_str() {
            "host" => {
                // Save previous host if any
                if let Some(host) = current.take() {
                    if !host.alias.contains('*') && !host.alias.contains('?') {
                        hosts.push(host);
                    }
                }
                // Start new host
                current = Some(SshHostConfig {
                    alias: value.to_string(),
                    port: 22,
                    ..Default::default()
                });
            }
            "hostname" => {
                if let Some(ref mut host) = current {
                    host.hostname = value.to_string();
                }
            }
            "user" => {
                if let Some(ref mut host) = current {
                    host.user = value.to_string();
                }
            }
            "port" => {
                if let Some(ref mut host) = current {
                    host.port = value.parse().unwrap_or(22);
                }
            }
            "identityfile" => {
                if let Some(ref mut host) = current {
                    // Expand ~ to home directory
                    let expanded = if value.starts_with("~/") {
                        home.join(&value[2..]).to_string_lossy().to_string()
                    } else {
                        value.to_string()
                    };
                    host.identity_file = expanded;
                }
            }
            _ => {} // Ignore other directives
        }
    }

    // Don't forget the last host
    if let Some(host) = current {
        if !host.alias.contains('*') && !host.alias.contains('?') {
            hosts.push(host);
        }
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_content() {
        // parse_ssh_config reads from disk; just verify the struct defaults
        let cfg = SshHostConfig::default();
        assert_eq!(cfg.port, 0);
        assert!(cfg.alias.is_empty());
    }
}
