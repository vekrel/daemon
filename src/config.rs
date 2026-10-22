use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct EngineConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    pub health_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub engine: EngineConfig,
    pub daemon: DaemonConfig,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Parse(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    toml::from_str(&text).map_err(ConfigError::Parse)
}
