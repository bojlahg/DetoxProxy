use crate::types::{MaskMode, TypeId};
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator { None, Luhn, Inn, Snils, Date, Phone, Email }

/// Global context markers applied to every type unless a type overrides them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSpec {
    /// Words that lower confidence when found near a candidate (e.g. "поэт", "отделение", "пример").
    #[serde(default)]
    pub non_pii_markers: Vec<String>,
    /// Words that raise confidence when found near a candidate (e.g. "клиент", "паспорт").
    #[serde(default)]
    pub pii_markers: Vec<String>,
    /// Words that mark a span as a place (city/region markers) for birth_place detection.
    #[serde(default)]
    pub place_markers: Vec<String>,
    /// Words that mark a preceding token as a city (e.g. "г", "город").
    #[serde(default)]
    pub city_markers: Vec<String>,
    /// Abbreviation words whose trailing period is not a sentence delimiter.
    #[serde(default)]
    pub abbreviation_words: Vec<String>,
    /// Street markers used to recognize street components in addresses.
    #[serde(default)]
    pub street_markers: Vec<String>,
    /// Prefixes that a passport issuer phrase must start with.
    #[serde(default)]
    pub issuer_prefixes: Vec<String>,
    /// Separators allowed between adjacent address components.
    #[serde(default)]
    pub address_separators: Vec<String>,
    /// Words that mark a nearby value as a bank card number.
    #[serde(default)]
    pub card_markers: Vec<String>,
    /// Words that mark a nearby value as a birth date.
    #[serde(default)]
    pub birth_markers: Vec<String>,
    /// Genitive suffixes stripped from a country word before dictionary lookup.
    #[serde(default)]
    pub country_suffixes: Vec<String>,
}

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
    /// Whether the type is detected under `types: all` (enabled_types == None). Types that
    /// are off by default (e.g. secrets) are detected only when explicitly listed.
    #[serde(default = "default_enabled_by_default")]
    pub enabled_by_default: bool,
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
    /// Patronymic suffixes (e.g. "-ович", "-овна"); a word ending with one is a patronymic.
    #[serde(default)]
    pub patronymic_suffixes: Vec<String>,
    /// Surname suffixes (e.g. "-ов", "-ский"); a word ending with one is a surname.
    #[serde(default)]
    pub surname_suffixes: Vec<String>,
    /// Case endings stripped from a first name before dictionary lookup (oblique cases).
    #[serde(default)]
    pub first_name_case_endings: Vec<String>,
    /// Suffixes stripped from a surname in oblique cases before dictionary lookup.
    #[serde(default)]
    pub surname_case_suffixes: Vec<String>,
    /// PII markers that raise confidence when found near a candidate (e.g. "клиент", "паспорт").
    #[serde(default)]
    pub pii_context: Vec<String>,
    /// Non-PII markers that lower confidence when found near a candidate (e.g. "поэт", "писатель").
    #[serde(default)]
    pub non_pii_context: Vec<String>,
    /// Per-type override for the global `context.non_pii_markers`; empty = use global.
    #[serde(default)]
    pub non_pii_markers: Vec<String>,
    /// Per-type override for the global `context.pii_markers`; empty = use global.
    #[serde(default)]
    pub pii_markers: Vec<String>,
    /// Trailing suffixes that extend a date span (e.g. " г.", " года").
    #[serde(default)]
    pub date_suffixes: Vec<String>,
    /// Markers that strongly imply a place follows (birth_place), even without a toponym.
    #[serde(default)]
    pub strong_markers: Vec<String>,
}
fn default_context_window() -> usize { 40 }
fn default_validator() -> Validator { Validator::None }
fn default_mask_mode() -> MaskMode { MaskMode::Token }
fn default_enabled_by_default() -> bool { true }

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("invalid regex in type {type_id}: {source}")]
    Regex { type_id: TypeId, source: regex::Error },
    #[error("duplicate type id {0}")]
    Duplicate(TypeId),
}

/// Configuration for the `pseudonym` masking mode.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PseudonymSpec {
    /// Email domains used to build a plausible pseudonym email (original domain is never kept).
    #[serde(default)]
    pub email_domains: Vec<String>,
}

/// Compiled registry: specs plus compiled regexes. Immutable after build; shared via Arc.
pub struct Registry {
    specs: Vec<TypeSpec>,
    compiled: Vec<Vec<regex::Regex>>,
    context: ContextSpec,
    pseudonym: PseudonymSpec,
}

impl Registry {
    pub fn from_yaml(text: &str) -> Result<Self, RegistryError> {
        #[derive(Deserialize)]
        struct Root {
            types: Vec<TypeSpec>,
            #[serde(default)]
            context: ContextSpec,
            #[serde(default)]
            pseudonym: PseudonymSpec,
        }
        let root: Root = serde_yaml_ng::from_str(text)?;
        Self::from_specs(root.types, root.context, root.pseudonym)
    }

    pub fn from_specs(
        specs: Vec<TypeSpec>,
        context: ContextSpec,
        pseudonym: PseudonymSpec,
    ) -> Result<Self, RegistryError> {
        let mut seen = HashSet::new();
        for spec in &specs {
            if !seen.insert(spec.id.clone()) {
                return Err(RegistryError::Duplicate(spec.id.clone()));
            }
        }
        let mut compiled = Vec::with_capacity(specs.len());
        for spec in &specs {
            let mut pats = Vec::with_capacity(spec.patterns.len());
            for p in &spec.patterns {
                let re = RegexBuilder::new(p)
                    .case_insensitive(true)
                    .unicode(true)
                    .build()
                    .map_err(|source| RegistryError::Regex { type_id: spec.id.clone(), source })?;
                pats.push(re);
            }
            compiled.push(pats);
        }
        Ok(Self { specs, compiled, context, pseudonym })
    }

    pub fn types(&self) -> &[TypeSpec] {
        &self.specs
    }

    pub fn context(&self) -> &ContextSpec {
        &self.context
    }

    /// Email domains used by the `pseudonym` masking mode.
    pub fn pseudonym_email_domains(&self) -> &[String] {
        &self.pseudonym.email_domains
    }

    pub fn get(&self, id: &str) -> Option<&TypeSpec> {
        self.specs.iter().find(|s| s.id == id)
    }

    pub fn patterns(&self, id: &str) -> &[regex::Regex] {
        self.specs
            .iter()
            .position(|s| s.id == id)
            .map(|i| &self.compiled[i][..])
            .unwrap_or(&[])
    }
}