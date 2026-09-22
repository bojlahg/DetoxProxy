use crate::types::{MaskMode, TypeId};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator { None, Luhn, Inn, Snils, Date, Phone, Email }

/// Declarative description of one PII type. Loaded from YAML; adding a type needs no code.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeSpec {
    pub id: TypeId,
    pub name: String,
    /// Regex patterns (case-insensitive, unicode). Any match is a candidate.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Words that, when found within `context_window` chars before the candidate, raise confidence.
    #[serde(default)]
    pub context_words: Vec<String>,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    /// If true, a match is accepted only when a context word is present.
    #[serde(default)]
    pub context_required: bool,
    #[serde(default = "default_validator")]
    pub validator: Validator,
    /// Named dictionary this type consults (e.g. "surnames"); resolved by the detector.
    #[serde(default)]
    pub dictionary: Option<String>,
    #[serde(default = "default_mask_mode")]
    pub mask: MaskMode,
    /// Token label used in `{LABEL_N}`, e.g. "FIO".
    pub token_label: String,
    /// For stars mode: how many leading/trailing chars stay visible.
    #[serde(default)]
    pub stars_keep_prefix: usize,
    #[serde(default)]
    pub stars_keep_suffix: usize,
    /// Masked only when another confidently detected type is present in the same text (cvv, pin).
    #[serde(default)]
    pub requires_companion: bool,
}
fn default_context_window() -> usize { 40 }
fn default_validator() -> Validator { Validator::None }
fn default_mask_mode() -> MaskMode { MaskMode::Token }

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("invalid regex in type {type_id}: {source}")]
    Regex { type_id: TypeId, source: regex::Error },
    #[error("duplicate type id {0}")]
    Duplicate(TypeId),
}

/// Compiled registry: specs plus compiled regexes. Immutable after build; shared via Arc.
pub struct Registry {
    specs: Vec<TypeSpec>,
    compiled: Vec<Vec<regex::Regex>>,
}

impl Registry {
    pub fn from_yaml(text: &str) -> Result<Self, RegistryError> { todo!() }
    pub fn from_specs(specs: Vec<TypeSpec>) -> Result<Self, RegistryError> { todo!() }
    pub fn types(&self) -> &[TypeSpec] { todo!() }
    pub fn get(&self, id: &str) -> Option<&TypeSpec> { todo!() }
    pub fn patterns(&self, id: &str) -> &[regex::Regex] { todo!() }
}