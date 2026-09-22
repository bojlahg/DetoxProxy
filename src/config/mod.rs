use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::types::MaskMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Stateless,
    Stateful,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenNumbering {
    Sequential,
    Hash,
}

/// How to resolve a conflict when both PII and non-PII markers are near a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrapPolicy {
    /// Treat the candidate as PII (leak is worse than over-masking).
    #[default]
    PreferMask,
    /// Treat the candidate as non-PII.
    PreferSkip,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TypeSelection {
    All(String),
    List(Vec<String>),
}

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
    #[serde(default = "default_request_deadline_ms")]
    pub request_deadline_ms: u64,
    /// Birth dates older than this many years are treated as historical (confidence penalty).
    #[serde(default = "default_historical_date_years")]
    pub historical_date_years: u32,
    /// Texts longer than this many bytes run detection+masking on a blocking thread pool.
    #[serde(default = "default_inline_max_bytes")]
    pub inline_max_bytes: usize,
    /// Max concurrent heavy (blocking) detection tasks; extra requests wait for a permit.
    #[serde(default = "default_heavy_max_concurrency")]
    pub heavy_max_concurrency: usize,
}
fn default_max_body_bytes() -> usize { 4 * 1024 * 1024 }
fn default_max_inflight() -> usize { 2048 }
fn default_mapping_ttl_sec() -> u64 { 900 }
fn default_mapping_max_entries() -> usize { 200_000 }
fn default_request_deadline_ms() -> u64 { 5000 }
fn default_historical_date_years() -> u32 { 120 }
fn default_inline_max_bytes() -> usize { 16384 }
fn default_heavy_max_concurrency() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
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
    pub types: TypeSelection,
    #[serde(default)]
    pub overrides: HashMap<String, MaskMode>,
    #[serde(default)]
    pub combination_rule: bool,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
    #[serde(default)]
    pub allow_substrings: Vec<String>,
    #[serde(default)]
    pub trap_policy: TrapPolicy,
    #[serde(default = "default_session_mode")]
    pub session_mode: SessionMode,
    #[serde(default = "default_token_numbering")]
    pub token_numbering: TokenNumbering,
    #[serde(default)]
    pub hash_salt: Option<String>,
}
fn default_enabled() -> bool { true }
fn default_mask_mode() -> MaskMode { MaskMode::Token }
fn default_unmask_enabled() -> bool { true }
fn default_types() -> TypeSelection { TypeSelection::All("all".to_string()) }
fn default_min_confidence() -> f32 { 0.3 }
fn default_session_mode() -> SessionMode { SessionMode::Stateless }
fn default_token_numbering() -> TokenNumbering { TokenNumbering::Sequential }

/// Optional LLM proxy configuration. When `upstream_url` is absent the proxy runs in demo mode.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    /// Upstream OpenAI-compatible endpoint. Absent => demo mode.
    #[serde(default)]
    pub upstream_url: Option<String>,
    /// Name of the environment variable holding the upstream API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Upstream request timeout in milliseconds.
    #[serde(default = "default_llm_timeout_ms")]
    pub timeout_ms: u64,
    /// Prepend a system message telling the model how to request a grammatical case for a token.
    #[serde(default = "default_case_hints")]
    pub case_hints: bool,
}
fn default_llm_timeout_ms() -> u64 { 60_000 }
fn default_case_hints() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u64,
    pub server: ServerConfig,
    pub default_system: String,
    #[serde(default)]
    pub systems: Vec<SystemConfig>,
    pub pii_types_file: String,
    pub allowlist_file: String,
    #[serde(default)]
    pub dictionaries_dir: Option<String>,
    #[serde(default)]
    pub llm: Option<LlmConfig>,
}

impl Config {
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }
        if self.server.listen.trim().is_empty() {
            return Err(ConfigError::EmptyListen);
        }
        let mut seen = std::collections::HashSet::new();
        for sys in &self.systems {
            if !seen.insert(sys.id.clone()) {
                return Err(ConfigError::DuplicateSystem(sys.id.clone()));
            }
            if !(0.0..=1.0).contains(&sys.min_confidence) {
                return Err(ConfigError::BadConfidence(sys.id.clone()));
            }
            if sys.token_numbering == TokenNumbering::Hash && sys.hash_salt.is_none() {
                return Err(ConfigError::MissingHashSalt(sys.id.clone()));
            }
        }
        let default = self.system(&self.default_system);
        match default {
            Some(sys) if sys.enabled => {}
            _ => return Err(ConfigError::BadDefaultSystem(self.default_system.clone())),
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
    UnsupportedVersion(u64),
    #[error("server.listen must not be empty")]
    EmptyListen,
    #[error("duplicate system id {0}")]
    DuplicateSystem(String),
    #[error("system {0}: min_confidence must be in 0..=1")]
    BadConfidence(String),
    #[error("system {0}: token_numbering hash requires hash_salt")]
    MissingHashSalt(String),
    #[error("default_system {0} must exist and be enabled")]
    BadDefaultSystem(String),
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

    /// Validates and swaps the config; on error the previous snapshot is kept.
    pub fn replace(&self, cfg: Config) -> Result<(), ConfigError> {
        cfg.validate()?;
        self.inner.store(Arc::new(cfg));
        Ok(())
    }
}