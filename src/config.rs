use serde::Deserialize;
use std::{collections::HashMap, path::Path};

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
    #[serde(default)]
    pub rust: RustConfig,
}

/// `[rust.handlers]`: per-handler mode keyed by `"METHOD /path"` (HTTP) or RPC tag.
#[derive(Debug, Deserialize, Default)]
pub struct RustConfig {
    #[serde(default)]
    pub handlers: HashMap<String, Mode>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Node answers; Rust is not consulted.
    Off,
    /// Node answers; Rust computes its answer too and logs whether they match.
    #[default]
    Shadow,
    /// Rust answers; Node never sees the request.
    Serve,
}

impl RustConfig {
    /// Every handler defaults to `shadow`.
    pub fn mode(&self, key: &str) -> Mode {
        self.handlers.get(key).copied().unwrap_or_default()
    }
}

impl Config {
    pub fn engine_port(&self) -> Result<u16, ConfigError> {
        match self.engine.port {
            Some(p) => Ok(p),
            None => self.server.port.checked_add(10).ok_or(ConfigError::Invalid(
                "server.port too high to derive engine.port; set engine.port explicitly",
            )),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Parse(e) => write!(f, "invalid config: {e}"),
            Self::Invalid(m) => write!(f, "invalid config: {m}"),
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
        assert_eq!(c.engine_port().unwrap(), 3789);
        let c = parse("[server]\nport = 3779\n[engine]\ncommand = \"x\"\nport = 5000\n");
        assert_eq!(c.engine_port().unwrap(), 5000);
    }

    #[test]
    fn handler_modes_default_to_shadow() {
        let c = parse("[server]\nport = 1\n[engine]\ncommand = \"x\"\n");
        assert_eq!(c.rust.mode("GET /api/auth/session"), Mode::Shadow);
        assert_eq!(c.rust.mode("projects.readFile"), Mode::Shadow);
        let c = parse(
            "[server]\nport = 1\n[engine]\ncommand = \"x\"\n[rust.handlers]\n\"GET /api/auth/session\" = \"serve\"\n\"x\" = \"off\"\n",
        );
        assert_eq!(c.rust.mode("GET /api/auth/session"), Mode::Serve);
        assert_eq!(c.rust.mode("x"), Mode::Off);
        assert!(
            toml::from_str::<Config>(
                "[server]\nport = 1\n[engine]\ncommand = \"x\"\n[rust.handlers]\na = \"on\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn engine_port_overflow_is_a_config_error() {
        let c = parse("[server]\nport = 65530\n[engine]\ncommand = \"x\"\n");
        assert_eq!(
            c.engine_port().unwrap_err().to_string(),
            "invalid config: server.port too high to derive engine.port; set engine.port explicitly"
        );
        let c = parse("[server]\nport = 65530\n[engine]\ncommand = \"x\"\nport = 5000\n");
        assert_eq!(c.engine_port().unwrap(), 5000);
    }
}
