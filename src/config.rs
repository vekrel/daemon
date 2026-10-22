use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct EngineConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Loopback port for the engine; defaults to server.port + 10.
    pub port: Option<u16>,
    #[serde(default)]
    pub record: bool,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub engine: EngineConfig,
}

impl Config {
    pub fn engine_port(&self) -> u16 {
        self.engine.port.unwrap_or(self.server.port + 10)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> Config {
        toml::from_str(t).unwrap()
    }

    #[test]
    fn engine_port_defaults_to_server_port_plus_ten() {
        let c = parse("[server]\nport = 3779\n[engine]\ncommand = \"x\"\n");
        assert_eq!(c.engine_port(), 3789);
        let c = parse("[server]\nport = 3779\n[engine]\ncommand = \"x\"\nport = 5000\n");
        assert_eq!(c.engine_port(), 5000);
    }
}
