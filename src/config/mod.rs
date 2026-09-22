use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::types::MaskMode;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_max_inflight")]
    pub max_inflight: usize,
    #[serde(default = "default_mapping_ttl_sec")]
    pub mapping_ttl_sec: u64,
    #[serde(default = "default_mapping_max_entries")]
    pub mapping_max_entries: usize,
}
fn default_max_body_bytes() -> usize { 4 * 1024 * 1024 }
fn default_max_inflight() -> usize { 2048 }
fn default_mapping_ttl_sec() -> u64 { 900 }
fn default_mapping_max_entries() -> usize { 200_000 }

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TypesFilter {
    All(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_mask_mode")]
    pub mask_mode: MaskMode,
    #[serde(default = "default_unmask_enabled")]
    pub unmask_enabled: bool,
    #[serde(default = "default_types")]
    pub types: TypesFilter,
    #[serde(default)]
    pub overrides: HashMap<String, MaskMode>,
    #[serde(default)]
    pub combination_rule: bool,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
    #[serde(default)]
    pub allow_addresses: Vec<String>,
}
fn default_enabled() -> bool { true }
fn default_mask_mode() -> MaskMode { MaskMode::Token }
fn default_unmask_enabled() -> bool { true }
fn default_types() -> TypesFilter { TypesFilter::All("all".to_string()) }
fn default_min_confidence() -> f32 { 0.3 }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub api_key_env: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub force_stream: bool,
}
fn default_timeout_ms() -> u64 { 60_000 }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub server: ServerConfig,
    #[serde(default)]
    pub default_system: Option<String>,
    #[serde(default)]
    pub systems: Vec<SystemConfig>,
    pub upstream: UpstreamConfig,
    /// Path to the PII types YAML file.
    pub pii_types: String,
    /// Path to the allowlist YAML file.
    pub allowlist: String,
}

impl Config {
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }
        let mut seen = std::collections::HashSet::new();
        for sys in &self.systems {
            if !seen.insert(sys.id.clone()) {
                return Err(ConfigError::DuplicateSystem(sys.id.clone()));
            }
        }
        Ok(())
    }

    pub fn system(&self, id: &str) -> Option<&SystemConfig> {
        self.systems.iter().find(|s| s.id == id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unsupported config version {0}")]
    UnsupportedVersion(u32),
    #[error("duplicate system id {0}")]
    DuplicateSystem(String),
}

/// Atomic snapshot of the config; hot reload swaps the inner value.
pub struct ConfigStore {
    inner: ArcSwap<Config>,
}

impl ConfigStore {
    pub fn new(cfg: Config) -> Self {
        Self { inner: ArcSwap::from_pointee(cfg) }
    }

    pub fn load(&self) -> Arc<Config> {
        self.inner.load_full()
    }

    pub fn replace(&self, cfg: Config) -> Result<(), ConfigError> {
        cfg.validate()?;
        self.inner.store(Arc::new(cfg));
        Ok(())
    }
}