use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfigFile {
    pub listen: Option<bool>,
    pub port: Option<u16>,
    pub metrics_port: Option<u16>,
    pub targets: Option<Vec<String>>,
    pub interval: Option<f64>,
    pub count: Option<u64>,
    pub min_packet_size: Option<usize>,
    pub dscp: Option<String>,
    pub srv: Option<bool>,
    pub adaptive: Option<bool>,
    pub active_key_id: Option<String>,
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub auth_secret: Option<String>,
    pub encrypt_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct KeyringFile {
    pub active_key_id: Option<String>,
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

impl AppConfigFile {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let parsed: Self = toml::from_str(&content)?;
        Ok(parsed)
    }
}

impl KeyringFile {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let parsed: Self = toml::from_str(&content)?;
        Ok(parsed)
    }
}
